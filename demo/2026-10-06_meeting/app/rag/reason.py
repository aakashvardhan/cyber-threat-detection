"""Analyst reasoning over RAG sources via Groq LLM (GPT-OSS).

API key / model are resolved from:
1) explicit args
2) app/.env (GROQ_API_KEY, GROQ_MODEL)
3) Streamlit secrets (.streamlit/secrets.toml)

Falls back to local synthesis if no key is available.
"""
from __future__ import annotations

import json
import re
from typing import Any

from app.rag.retrieve import RetrievalResult, _first_sentence
from app.rag.secrets import get_groq_api_key, get_groq_model


def _clean(text: str | None, limit: int | None = None) -> str:
    value = re.sub(r"\s+", " ", (text or "").strip())
    if limit and len(value) > limit:
        return value[: limit - 1].rstrip() + "..."
    return value


def _actor_names(sources: list[dict[str, Any]]) -> list[str]:
    names: list[str] = []
    for src in sources:
        if src.get("type") == "mitre":
            continue
        name = _clean(str(src.get("title") or ""))
        if not name or name.lower() in {"cti/procedure", "unknown"}:
            continue
        if name not in names:
            names.append(name)
    return names[:4]


def _evidence_highlights(sources: list[dict[str, Any]], limit: int = 2) -> list[str]:
    highlights: list[str] = []
    for src in sources:
        if src.get("type") == "mitre":
            continue
        title = _clean(str(src.get("title") or src.get("id") or "related campaign"))
        snippet = _clean(str(src.get("text") or ""), 160)
        if not snippet:
            continue
        first = re.split(r"(?<=[.!?])\s+", snippet, maxsplit=1)[0]
        highlights.append(f"{title} ({first})")
        if len(highlights) >= limit:
            break
    return highlights


def _mitigation_codes(mitigations: str) -> list[str]:
    codes = re.findall(r"\bM\d{4}\b", mitigations or "")
    seen: set[str] = set()
    ordered: list[str] = []
    for code in codes:
        if code not in seen:
            seen.add(code)
            ordered.append(code)
    return ordered[:5]


def _why_attack(event: dict[str, Any], mitre: dict[str, Any], tactics: str) -> str:
    tid = mitre.get("technique_id") or event.get("technique_id") or "unknown"
    name = mitre.get("name") or "an unknown technique"
    behavior = _clean(event.get("behavior"), 320)
    conf = event.get("technique_confidence")
    conf_txt = f" (model confidence {float(conf):.0%})" if isinstance(conf, (int, float)) else ""

    why = (
        f"This event is flagged as a likely attack because the observed traffic closely matches "
        f"MITRE ATT&CK {tid} ({name}) in the {tactics} stage{conf_txt}. "
    )
    if behavior:
        why += f"Specifically, {behavior[0].lower() + behavior[1:]}. "
    why += (
        "That pattern is unusual for routine business communication and is more consistent with "
        "hostile probing, scanning, or capability-building activity than with normal service traffic."
    )
    return why


def _context_and_evidence(mitre: dict[str, Any], sources: list[dict[str, Any]]) -> str:
    mitre_line = _clean(_first_sentence(mitre.get("description")), 220)
    actors = _actor_names(sources)
    highlights = _evidence_highlights(sources, limit=2)

    parts: list[str] = []
    if mitre_line:
        parts.append(f"In ATT&CK terms, {mitre_line[0].lower() + mitre_line[1:]}")

    if actors and highlights:
        actor_phrase = (
            ", ".join(actors[:-1]) + f", and {actors[-1]}" if len(actors) > 1 else actors[0]
        )
        parts.append(
            f"Retrieved threat intelligence links similar activity to groups/tools such as {actor_phrase}. "
            f"For example, {highlights[0]}"
            + (f"; likewise, {highlights[1]}" if len(highlights) > 1 else "")
            + "."
        )
    elif highlights:
        parts.append(
            "Retrieved procedure examples describe similar tradecraft — "
            + "; ".join(highlights)
            + "."
        )
    else:
        parts.append(
            "Retrieved sources currently provide MITRE technique context only; "
            "no closely matching procedure/CTI snippets were found for this technique."
        )
    return " ".join(parts)


def _next_steps(event: dict[str, Any], mitre: dict[str, Any], tactics: str) -> str:
    src = event.get("src_ip") or "the source host"
    dst = event.get("dst_ip") or "the destination host"
    service = event.get("service") or "the observed service"
    port = event.get("port") or "the observed port/protocol"
    codes = _mitigation_codes(str(mitre.get("mitigations") or ""))

    steps = [
        f"Confirm whether {src} is an expected scanner/admin host; if not, isolate or rate-limit it while investigating.",
        f"Review Zeek/firewall logs for {src} -> {dst} around this 5-minute window, focusing on {service}/{port} and failed handshakes.",
        f"Check whether the same source touched additional internal assets with the same {tactics.lower()} pattern.",
        "Open or update an incident ticket with the GNN attack score, MITRE technique, and RAG source count for handoff.",
    ]
    if codes:
        steps.append(
            "Apply relevant ATT&CK mitigations where feasible: " + ", ".join(codes) + "."
        )
    else:
        steps.append(
            "Prioritize containment and deeper packet/host forensics if the destination is a critical asset."
        )

    numbered = " ".join(f"{i}) {step}" for i, step in enumerate(steps, start=1))
    return "Recommended SOC next steps: " + numbered


def synthesize_reasoning(event: dict[str, Any], result: RetrievalResult) -> str:
    """Local fallback synthesizer if Groq is unavailable."""
    mitre = result.mitre or {}
    tactics = ", ".join(result.tactics) or event.get("gnn_tactic") or "unknown"
    sources = result.sources_for_llm(max_each=4)
    why = _why_attack(event, mitre, tactics)
    evidence = _context_and_evidence(mitre, sources)
    next_steps = _next_steps(event, mitre, tactics)
    return f"{why}\n\n{evidence}\n\n{next_steps}"


def _build_llm_payload(event: dict[str, Any], result: RetrievalResult) -> dict[str, Any]:
    return {
        "event": {
            "event_id": event.get("event_id"),
            "technique_id": event.get("technique_id"),
            "technique_confidence": event.get("technique_confidence"),
            "service": event.get("service"),
            "port": event.get("port"),
            "protocol": event.get("protocol"),
            "behavior": event.get("behavior"),
            "src_ip": event.get("src_ip"),
            "dst_ip": event.get("dst_ip"),
            "gnn_tactic": event.get("gnn_tactic"),
        },
        "mitre": result.mitre,
        "tactics": result.tactics,
        "sources": result.sources_for_llm(max_each=4),
    }


def _groq_reason(
    event: dict[str, Any],
    result: RetrievalResult,
    api_key: str,
    model: str,
) -> str:
    from groq import Groq

    client = Groq(api_key=api_key)
    payload = _build_llm_payload(event, result)

    system = (
        "You are an experienced SOC analyst. Using ONLY the provided GNN detection event "
        "and retrieved RAG sources, write clear human-readable threat reasoning.\n"
        "Requirements:\n"
        "1) Explain why this event could be an attack (tie observed traffic to the MITRE technique).\n"
        "2) Briefly use the retrieved sources/evidence (do not invent actors, CVEs, or facts).\n"
        "3) Give concrete next steps a SOC analyst should take.\n"
        "4) Write 2-3 short paragraphs in plain English. No bullet dumps of raw snippets. "
        "No markdown headings. Do not invent information not present in the input."
    )
    user = (
        "Produce the analyst reasoning for this attack event.\n\n"
        f"INPUT JSON:\n{json.dumps(payload, ensure_ascii=False)}"
    )

    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        temperature=0.2,
        max_tokens=500,
    )
    text = (response.choices[0].message.content or "").strip()
    if not text:
        raise RuntimeError("Empty response from Groq")
    return text


def generate_reasoning(
    event: dict[str, Any],
    result: RetrievalResult,
    api_key: str | None = None,
    model: str | None = None,
) -> dict[str, Any]:
    sources = result.sources_for_llm(max_each=3)
    resolved_key = get_groq_api_key(api_key)
    resolved_model = get_groq_model(model)

    mode = "groq_llm"
    used_model: str | None = resolved_model
    try:
        if not resolved_key:
            raise RuntimeError(
                "GROQ_API_KEY not found in app/.env or Streamlit secrets"
            )
        text = _groq_reason(event, result, resolved_key, resolved_model)
    except Exception as exc:  # noqa: BLE001 - keep demo resilient
        mode = f"local_fallback ({exc})"
        used_model = None
        text = synthesize_reasoning(event, result)

    return {
        "reasoning": text,
        "mode": mode,
        "model": used_model if mode == "groq_llm" else None,
        "technique_id": event.get("technique_id"),
        "sources": sources,
        "source_count": len(sources),
        "source_summary": "; ".join(
            f"{s.get('type')}:{s.get('id') or s.get('title')}" for s in sources[:5]
        ),
    }
