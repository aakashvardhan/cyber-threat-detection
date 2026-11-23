"""Persistent incident state (SJSU-131).

Incidents come from the replay in a fixed order, so the same live model always produces the same incident IDs.
What must survive a restart is what people and the LLM added on top: the analyst's status, technique override,
mitigations and activity log, and the cached explanation with its evidence. Those are kept per (model, incident).

Also kept: the incident chat (app.chat), so a conversation continues after a restart.

  MemoryStore    default; lost on restart (tests, quick local runs)
  DynamoStore    one DynamoDB table: partition key `model`, sort key `incident_id`; DynamoDB Local in docker compose,
                 the real service on AWS (same code, only DYNAMODB_ENDPOINT differs)

Writes never break a request: a failed write is logged and the console keeps working from memory.
"""
from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone

log = logging.getLogger(__name__)

ANALYST_FIELDS = ("status", "technique_override", "mitigations_applied", "activity")
EXPLANATION_FIELDS = ("explanation", "evidence", "retrieval_trace", "cve_status")
JSON_FIELDS = ("activity", "explanation", "evidence", "retrieval_trace", "mitigations_applied", "chat")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def analyst_state(incident) -> dict:
    return {"status": incident.status, "technique_override": incident.technique_override,
            "mitigations_applied": list(incident.mitigations_applied), "activity": list(incident.activity)}


def explanation_state(incident) -> dict:
    return {"explanation": incident.explanation, "evidence": incident.evidence,
            "retrieval_trace": incident.retrieval_trace, "cve_status": incident.cve_status}


def apply_state(incident, saved: dict | None) -> None:
    """Put saved fields back on a freshly created incident."""
    if not saved:
        return
    for name in (*ANALYST_FIELDS, "chat"):
        if name in saved and saved[name] is not None:
            setattr(incident, name, saved[name])
    if (saved.get("explanation") or {}).get("status") == "ready":
        for name in EXPLANATION_FIELDS:
            if name in saved:
                setattr(incident, name, saved[name])


class MemoryStore:
    name = "memory"

    def __init__(self):
        self.items: dict[tuple[str, str], dict] = {}
        self.lock = threading.Lock()

    def load_all(self, model: str) -> dict[str, dict]:
        with self.lock:
            return {iid: dict(v) for (m, iid), v in self.items.items() if m == model}

    def save(self, model: str, incident_id: str, fields: dict) -> None:
        with self.lock:
            self.items.setdefault((model, incident_id), {}).update(fields)

    def clear(self, model: str | None = None) -> int:
        with self.lock:
            keys = [k for k in self.items if model is None or k[0] == model]
            for k in keys:
                del self.items[k]
            return len(keys)


class DynamoStore:
    name = "dynamodb"

    def __init__(self, table, client=None):
        self.table = table
        self.client = client

    @classmethod
    def connect(cls, table_name: str, region: str, endpoint: str | None = None, create: bool = True) -> "DynamoStore":
        import boto3
        from botocore.config import Config

        config = Config(retries={"max_attempts": 3, "mode": "standard"}, connect_timeout=3, read_timeout=5)
        resource = boto3.resource("dynamodb", region_name=region, endpoint_url=endpoint or None, config=config)
        client = resource.meta.client
        try:
            client.describe_table(TableName=table_name)
        except client.exceptions.ResourceNotFoundException:
            if not create:
                raise RuntimeError(f"DynamoDB table {table_name} does not exist; run scripts/create_tables.py")
            create_table(client, table_name)
        return cls(resource.Table(table_name), client)

    @staticmethod
    def _decode(item: dict) -> dict:
        out = {}
        for k, v in item.items():
            if k in JSON_FIELDS and isinstance(v, str):
                out[k] = json.loads(v)
            elif k not in ("model", "incident_id", "updated_at"):
                out[k] = v
        return out

    def load_all(self, model: str) -> dict[str, dict]:
        from boto3.dynamodb.conditions import Key

        out, kwargs = {}, {"KeyConditionExpression": Key("model").eq(model)}
        while True:
            page = self.table.query(**kwargs)
            for item in page.get("Items", []):
                out[item["incident_id"]] = self._decode(item)
            if "LastEvaluatedKey" not in page:
                return out
            kwargs["ExclusiveStartKey"] = page["LastEvaluatedKey"]

    def save(self, model: str, incident_id: str, fields: dict) -> None:
        names, values, sets = {}, {":u": _now()}, ["#updated_at = :u"]
        names["#updated_at"] = "updated_at"
        for i, (k, v) in enumerate(fields.items()):
            names[f"#f{i}"] = k
            # JSON text keeps floats exact and avoids DynamoDB's Decimal type; items stay far below 400 KB
            values[f":v{i}"] = json.dumps(v, ensure_ascii=False) if k in JSON_FIELDS else v
            sets.append(f"#f{i} = :v{i}")
        self.table.update_item(Key={"model": model, "incident_id": incident_id},
                               UpdateExpression="SET " + ", ".join(sets),
                               ExpressionAttributeNames=names, ExpressionAttributeValues=values)

    def clear(self, model: str | None = None) -> int:
        removed = 0
        kwargs = {"ProjectionExpression": "#m, incident_id", "ExpressionAttributeNames": {"#m": "model"}}
        while True:
            page = self.table.scan(**kwargs)
            with self.table.batch_writer() as batch:
                for item in page.get("Items", []):
                    if model is None or item["model"] == model:
                        batch.delete_item(Key={"model": item["model"], "incident_id": item["incident_id"]})
                        removed += 1
            if "LastEvaluatedKey" not in page:
                return removed
            kwargs["ExclusiveStartKey"] = page["LastEvaluatedKey"]


def create_table(client, table_name: str) -> None:
    """On-demand table: partition key `model`, sort key `incident_id`."""
    log.info("Creating DynamoDB table %s", table_name)
    client.create_table(
        TableName=table_name,
        AttributeDefinitions=[{"AttributeName": "model", "AttributeType": "S"},
                              {"AttributeName": "incident_id", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "model", "KeyType": "HASH"},
                   {"AttributeName": "incident_id", "KeyType": "RANGE"}],
        BillingMode="PAY_PER_REQUEST",
    )
    client.get_waiter("table_exists").wait(TableName=table_name, WaiterConfig={"Delay": 1, "MaxAttempts": 30})


class SafeStore:
    """Wraps a store so that a failing database never breaks the console."""

    def __init__(self, inner):
        self.inner = inner
        self.name = inner.name

    def load_all(self, model: str) -> dict[str, dict]:
        try:
            return self.inner.load_all(model)
        except Exception as exc:  # noqa: BLE001
            log.warning("Could not load saved incidents from %s: %s: %s", self.name, type(exc).__name__, exc)
            return {}

    def save(self, model: str, incident_id: str, fields: dict) -> None:
        try:
            self.inner.save(model, incident_id, fields)
        except Exception as exc:  # noqa: BLE001
            log.warning("Could not save %s to %s: %s: %s", incident_id, self.name, type(exc).__name__, exc)

    def clear(self, model: str | None = None) -> int:
        return self.inner.clear(model)


def load_store(settings) -> SafeStore:
    if settings.incident_store == "dynamodb":
        try:
            store = DynamoStore.connect(settings.dynamodb_table, settings.aws_region, settings.dynamodb_endpoint,
                                        create=settings.dynamodb_create_table)
            log.info("Incident store: DynamoDB table %s%s", settings.dynamodb_table,
                     f" at {settings.dynamodb_endpoint}" if settings.dynamodb_endpoint else "")
            return SafeStore(store)
        except Exception as exc:  # noqa: BLE001 - keep the console running
            log.warning("DynamoDB unavailable (%s: %s); incident state is kept in memory only", type(exc).__name__, exc)
    return SafeStore(MemoryStore())
