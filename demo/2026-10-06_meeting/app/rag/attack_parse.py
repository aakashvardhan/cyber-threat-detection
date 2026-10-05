"""MITRE ATT&CK parse helpers from rag.ipynb."""
from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

import pandas as pd


def _attack_id(obj: dict) -> tuple[str | None, str | None]:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id"), ref.get("url")
    return None, None


def _active(obj: dict) -> bool:
    return not obj.get("revoked", False) and not obj.get("x_mitre_deprecated", False)


def _clean_attack_text(text: str | None) -> str:
    text = re.sub(r"\(Citation:[^)]*\)", "", text or "")
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)
    return re.sub(r"\s+", " ", text).strip()


def parse_attack(path: Path) -> tuple[pd.DataFrame, pd.DataFrame]:
    with path.open(encoding="utf-8") as handle:
        objects = json.load(handle)["objects"]

    tactics: dict[str, tuple[str, str]] = {}
    for obj in objects:
        if obj.get("type") == "x-mitre-tactic" and _active(obj):
            ta_id, _ = _attack_id(obj)
            tactics[obj["x_mitre_shortname"]] = (ta_id or "", obj["name"])

    techniques: list[dict[str, Any]] = []
    stix_to_tid: dict[str, str] = {}
    for obj in objects:
        if obj.get("type") != "attack-pattern" or not _active(obj):
            continue
        tid, url = _attack_id(obj)
        if not tid:
            continue
        stix_to_tid[obj["id"]] = tid
        phases = [
            p["phase_name"]
            for p in obj.get("kill_chain_phases", [])
            if p.get("kill_chain_name") == "mitre-attack"
        ]
        techniques.append(
            {
                "technique_id": tid,
                "name": obj.get("name", ""),
                "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique", False)),
                "parent_id": tid.split(".")[0],
                "tactic_ids": ", ".join(tactics.get(p, ("", ""))[0] for p in phases),
                "tactics": ", ".join(tactics.get(p, ("", p))[1] for p in phases),
                "platforms": ", ".join(obj.get("x_mitre_platforms", [])),
                "description": obj.get("description", ""),
                "detection": obj.get("x_mitre_detection", ""),
                "url": url,
            }
        )

    mitigations_by_stix: dict[str, tuple[str | None, str]] = {}
    for obj in objects:
        if obj.get("type") == "course-of-action" and _active(obj):
            mid, _ = _attack_id(obj)
            mitigations_by_stix[obj["id"]] = (mid, obj.get("name", ""))

    mit_rows: list[dict[str, Any]] = []
    for obj in objects:
        if (
            obj.get("type") == "relationship"
            and obj.get("relationship_type") == "mitigates"
            and _active(obj)
            and obj.get("source_ref") in mitigations_by_stix
            and obj.get("target_ref") in stix_to_tid
        ):
            mid, mname = mitigations_by_stix[obj["source_ref"]]
            mit_rows.append(
                {
                    "technique_id": stix_to_tid[obj["target_ref"]],
                    "mitigation_id": mid,
                    "mitigation_name": mname,
                    "how": obj.get("description", ""),
                }
            )

    lookup = pd.DataFrame(techniques).sort_values("technique_id").reset_index(drop=True)
    mitigations = pd.DataFrame(
        mit_rows, columns=["technique_id", "mitigation_id", "mitigation_name", "how"]
    )
    if len(mitigations):
        summary = (
            mitigations.groupby("technique_id")
            .apply(
                lambda g: "; ".join(
                    f"{a} {b}" for a, b in zip(g.mitigation_id, g.mitigation_name)
                ),
                include_groups=False,
            )
            .rename("mitigations")
        )
        lookup = lookup.merge(summary, on="technique_id", how="left").fillna({"mitigations": ""})
    else:
        lookup["mitigations"] = ""
    return lookup, mitigations


def parse_procedures(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        objects = json.load(handle)["objects"]
    by_id = {obj["id"]: obj for obj in objects}
    chunks: list[dict[str, Any]] = []
    stats: Counter[str] = Counter()
    for obj in objects:
        if (
            obj.get("type") != "relationship"
            or obj.get("relationship_type") != "uses"
            or not _active(obj)
        ):
            continue
        tgt = by_id.get(obj.get("target_ref"))
        src = by_id.get(obj.get("source_ref"))
        if (
            not tgt
            or tgt.get("type") != "attack-pattern"
            or not _active(tgt)
            or not src
            or not _active(src)
        ):
            continue
        tid, _ = _attack_id(tgt)
        if not tid:
            continue
        text = _clean_attack_text(obj.get("description"))
        if len(text.split()) < 4:
            stats["dropped_too_short"] += 1
            continue
        src_id, src_url = _attack_id(src)
        chunks.append(
            {
                "id": "proc-" + obj["id"].split("--")[-1],
                "text": text,
                "metadata": {
                    "source": "attack-procedure",
                    "technique_id": tid,
                    "technique_ids": sorted({tid, tid.split(".")[0]}),
                    "source_name": src.get("name", ""),
                    "source_type": src.get("type", ""),
                    "source_attack_id": src_id or "",
                    "url": src_url or "",
                },
            }
        )
    return chunks


def write_jsonl(records: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]
