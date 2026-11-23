"""Persistent incident state (SJSU-131).

Incidents come from the replay in a fixed order, so the same live model always produces the same incident IDs.
What must survive a restart is what people and the LLM added on top: the analyst's status, technique override,
mitigations and activity log, and the cached explanation with its evidence. Those are kept per (model, incident).

Also kept: the incident chat (app.chat), so a conversation continues after a restart.

  MemoryStore    default; lost on restart (tests, quick local runs)
  DynamoStore    one DynamoDB table: partition key `model`, sort key `incident_id`; DynamoDB Local in docker compose,
                 the real service on AWS (same code, only DYNAMODB_ENDPOINT differs)
  SafeStore      wraps either; keeps a copy of everything in memory so a failing database never breaks the console

Safety rules (review of #60/#61):
  - Every saved item carries the incident's fingerprint (source, first window, detector technique). State is put back
    only on an incident with the same fingerprint, so a changed replay or model never moves edits to another incident.
  - The first connection is retried for DYNAMODB_WAIT_S seconds (DynamoDB Local may still be starting); a table
    created at the same moment by another process is waited for, not treated as an error.
  - A write that fails is kept in memory and retried with the next write or read; a read that fails returns the
    in-memory copy instead of nothing, so a Reset during an outage keeps the state it had.
  - Reads are strongly consistent, so a restart right after an edit sees the edit.
  - The activity log is capped (MAX_ACTIVITY entries) so an item stays far below DynamoDB's 400 KB limit.
  - One backend process per table: the state lives in that process's memory, and DynamoDB keeps it across restarts.
    Running several backend replicas against one table is not supported (see DEPLOYMENT.md).
"""
from __future__ import annotations

import copy
import json
import logging
import threading
import time
from datetime import datetime, timezone

from app.timeutil import iso

log = logging.getLogger(__name__)

ANALYST_FIELDS = ("status", "technique_override", "mitigations_applied", "activity")
EXPLANATION_FIELDS = ("explanation", "evidence", "retrieval_trace", "cve_status")
JSON_FIELDS = ("activity", "explanation", "evidence", "retrieval_trace", "mitigations_applied", "chat")
MAX_ACTIVITY = 200
MAX_ITEM_BYTES = 350_000         # DynamoDB's limit is 400 KB per item


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def fingerprint(incident) -> str:
    """What makes an incident the same incident across restarts: its source, its first window and the detector's
    technique. The ID alone is not enough: it is a counter, so a changed replay or model reuses it."""
    first = incident.edges[0] if incident.edges else None
    window = iso(first.window_start) if first is not None else ""
    return f"{incident.source_ip}|{window}|{incident.technique_id}"


def analyst_state(incident) -> dict:
    return {"fingerprint": fingerprint(incident), "status": incident.status,
            "technique_override": incident.technique_override,
            "mitigations_applied": list(incident.mitigations_applied),
            "activity": list(incident.activity)[-MAX_ACTIVITY:]}


def explanation_state(incident) -> dict:
    return {"fingerprint": fingerprint(incident), "explanation": copy.deepcopy(incident.explanation),
            "evidence": copy.deepcopy(incident.evidence), "retrieval_trace": copy.deepcopy(incident.retrieval_trace),
            "cve_status": incident.cve_status}


def chat_state(incident) -> dict:
    return {"fingerprint": fingerprint(incident), "chat": copy.deepcopy(incident.chat)}


def apply_state(incident, saved: dict | None) -> bool:
    """Put saved fields back on a freshly created incident; False if the saved state belongs to another incident."""
    if not saved:
        return False
    if saved.get("fingerprint") != fingerprint(incident):
        log.info("Saved state for %s is for another incident (%s, now %s); not applied",
                 incident.incident_id, saved.get("fingerprint"), fingerprint(incident))
        return False
    for name in (*ANALYST_FIELDS, "chat"):
        if name in saved and saved[name] is not None:
            setattr(incident, name, copy.deepcopy(saved[name]))
    if (saved.get("explanation") or {}).get("status") == "ready":
        for name in EXPLANATION_FIELDS:
            if name in saved:
                setattr(incident, name, copy.deepcopy(saved[name]))
    return True


class MemoryStore:
    name = "memory"

    def __init__(self):
        self.items: dict[tuple[str, str], dict] = {}
        self.lock = threading.Lock()

    def load_all(self, model: str) -> dict[str, dict]:
        with self.lock:
            return {iid: copy.deepcopy(v) for (m, iid), v in self.items.items() if m == model}

    def save(self, model: str, incident_id: str, fields: dict) -> None:
        with self.lock:
            self.items.setdefault((model, incident_id), {}).update(copy.deepcopy(fields))

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
    def connect(cls, table_name: str, region: str, endpoint: str | None = None, create: bool = True,
                wait_s: float = 0.0) -> "DynamoStore":
        """Connect, creating the table if allowed. Connection errors are retried for `wait_s` seconds."""
        import boto3
        from botocore.config import Config

        config = Config(retries={"max_attempts": 3, "mode": "standard"}, connect_timeout=3, read_timeout=5)
        kwargs = {"region_name": region, "endpoint_url": endpoint or None, "config": config}
        if endpoint:
            # DynamoDB Local accepts any key; real AWS credentials (env vars or the instance role) are only used
            # without an endpoint, so they never have to be faked in the compose file (#60 review)
            session = boto3.session.Session()
            if session.get_credentials() is None:
                kwargs.update(aws_access_key_id="local", aws_secret_access_key="local")
        resource = boto3.resource("dynamodb", **kwargs)
        client = resource.meta.client
        deadline = time.monotonic() + max(wait_s, 0.0)
        delay = 0.5
        while True:
            try:
                _ensure_table(client, table_name, create)
                return cls(resource.Table(table_name), client)
            except TableMissing:
                raise
            except Exception as exc:  # noqa: BLE001 - e.g. DynamoDB Local still starting
                if time.monotonic() + delay > deadline:
                    raise
                log.info("DynamoDB not ready (%s: %s); retrying in %.1fs", type(exc).__name__, exc, delay)
                time.sleep(delay)
                delay = min(delay * 2, 5.0)

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

        # strongly consistent: a restart or Reset right after a write must see that write (#61 review)
        out, kwargs = {}, {"KeyConditionExpression": Key("model").eq(model), "ConsistentRead": True}
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
        size = 0
        for i, (k, v) in enumerate(fields.items()):
            names[f"#f{i}"] = k
            # JSON text keeps floats exact and avoids DynamoDB's Decimal type
            values[f":v{i}"] = json.dumps(v, ensure_ascii=False) if k in JSON_FIELDS else v
            size += len(str(values[f":v{i}"]).encode())
            sets.append(f"#f{i} = :v{i}")
        if size > MAX_ITEM_BYTES:
            raise ValueError(f"{incident_id}: {size} bytes exceeds the {MAX_ITEM_BYTES}-byte item budget")
        # only the fields given are set, so an explanation save never touches the analyst fields and vice versa
        self.table.update_item(Key={"model": model, "incident_id": incident_id},
                               UpdateExpression="SET " + ", ".join(sets),
                               ExpressionAttributeNames=names, ExpressionAttributeValues=values)

    def clear(self, model: str | None = None) -> int:
        """Delete saved state. Stop the backend first: a running backend may write while the table is scanned."""
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


class TableMissing(RuntimeError):
    pass


def _ensure_table(client, table_name: str, create: bool) -> None:
    try:
        client.describe_table(TableName=table_name)
        return
    except client.exceptions.ResourceNotFoundException:
        if not create:
            raise TableMissing(f"DynamoDB table {table_name} does not exist; run backend/scripts/create_tables.py")
    create_table(client, table_name)


def create_table(client, table_name: str) -> None:
    """On-demand table: partition key `model`, sort key `incident_id`. Safe if another process creates it too."""
    log.info("Creating DynamoDB table %s", table_name)
    try:
        client.create_table(
            TableName=table_name,
            AttributeDefinitions=[{"AttributeName": "model", "AttributeType": "S"},
                                  {"AttributeName": "incident_id", "AttributeType": "S"}],
            KeySchema=[{"AttributeName": "model", "KeyType": "HASH"},
                       {"AttributeName": "incident_id", "KeyType": "RANGE"}],
            BillingMode="PAY_PER_REQUEST",
        )
    except client.exceptions.ResourceInUseException:
        log.info("DynamoDB table %s is being created by another process; waiting for it", table_name)
    client.get_waiter("table_exists").wait(TableName=table_name, WaiterConfig={"Delay": 1, "MaxAttempts": 30})


class SafeStore:
    """Wraps a store so that a failing database never breaks the console or loses what the console shows.

    Everything saved is also kept in `mirror` (memory). A failed write stays in `pending` and is retried before the
    next write or read; a failed read returns the mirror, so a Reset during an outage keeps the current state."""

    def __init__(self, inner):
        self.inner = inner
        self.name = inner.name
        self.mirror = MemoryStore()
        self.pending: dict[tuple[str, str], dict] = {}
        self.lock = threading.Lock()

    def _flush(self) -> None:
        """Retry failed writes. Never raises: what still fails stays pending for the next attempt."""
        with self.lock:
            waiting = list(self.pending.items())
        for (model, incident_id), fields in waiting:
            try:
                self.inner.save(model, incident_id, fields)
            except Exception:  # noqa: BLE001 - still down; keep it
                return
            with self.lock:
                if self.pending.get((model, incident_id)) is fields:
                    del self.pending[(model, incident_id)]
            log.info("Saved %s to %s after an earlier failure", incident_id, self.name)

    def load_all(self, model: str) -> dict[str, dict]:
        self._flush()
        try:
            loaded = self.inner.load_all(model)
        except Exception as exc:  # noqa: BLE001
            log.warning("Could not load saved incidents from %s (%s: %s); using the in-memory copy",
                        self.name, type(exc).__name__, exc)
            return self.mirror.load_all(model)
        for incident_id, fields in loaded.items():
            # what the database has, then anything newer that this process saved
            merged = {**fields, **self.mirror.load_all(model).get(incident_id, {})}
            self.mirror.save(model, incident_id, merged)
        return self.mirror.load_all(model)

    def save(self, model: str, incident_id: str, fields: dict) -> None:
        self.mirror.save(model, incident_id, fields)
        self._flush()
        try:
            self.inner.save(model, incident_id, fields)
        except ValueError as exc:            # too large: retrying cannot help, the mirror still has it
            log.error("Not saved to %s: %s", self.name, exc)
        except Exception as exc:  # noqa: BLE001
            with self.lock:
                self.pending[(model, incident_id)] = {**self.pending.get((model, incident_id), {}),
                                                      **copy.deepcopy(fields)}
            log.warning("Could not save %s to %s (%s: %s); kept in memory and retried with the next write",
                        incident_id, self.name, type(exc).__name__, exc)

    def clear(self, model: str | None = None) -> int:
        self.mirror.clear(model)
        with self.lock:
            for key in [k for k in self.pending if model is None or k[0] == model]:
                del self.pending[key]
        return self.inner.clear(model)


def load_store(settings) -> SafeStore:
    if settings.incident_store not in ("memory", "dynamodb"):
        raise ValueError(f"INCIDENT_STORE must be memory or dynamodb, not {settings.incident_store!r}")
    if settings.incident_store == "dynamodb":
        try:
            store = DynamoStore.connect(settings.dynamodb_table, settings.aws_region, settings.dynamodb_endpoint,
                                        create=settings.dynamodb_create_table,
                                        wait_s=getattr(settings, "dynamodb_wait_s", 30.0))
            log.info("Incident store: DynamoDB table %s%s", settings.dynamodb_table,
                     f" at {settings.dynamodb_endpoint}" if settings.dynamodb_endpoint else "")
            return SafeStore(store)
        except Exception as exc:  # noqa: BLE001 - keep the console running
            log.error("DynamoDB unavailable after waiting (%s: %s); incident state is kept in memory only and is "
                      "lost on restart", type(exc).__name__, exc)
    return SafeStore(MemoryStore())
