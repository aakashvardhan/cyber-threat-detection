"""Threat Detection Console API (docs/api/openapi.yaml, v0.4.1).

Run (from backend/): uvicorn app.main:create_app --factory --reload --port 8000
"""
from __future__ import annotations

import logging
import threading
from dataclasses import dataclass

import pandas as pd
from fastapi import Body, Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app import schemas
from app.config import Settings
from app.detectors import Detector, load_detector
from app.explain import ExplanationManager
from app.incidents import Incident, ReplayController, ReplayError
from app.knowledge import KnowledgeBase
from app.replay_data import ReplayData
from app.research import ModelOutputs, load_metrics
from app.timeutil import iso, now_iso

log = logging.getLogger(__name__)


@dataclass
class AppState:
    settings: Settings
    replay_data: ReplayData
    detector: Detector
    controller: ReplayController
    kb: KnowledgeBase
    explanations: ExplanationManager
    model_outputs: ModelOutputs
    metrics: dict
    primary_model: str
    edit_lock: threading.Lock


def build_state(settings: Settings) -> AppState:
    replay_data = ReplayData.load(settings.replay_file)
    detector = load_detector(settings, replay_data)
    kb = KnowledgeBase.load(settings.knowledge_dir)
    metrics = load_metrics(settings.metrics_file)
    primary = settings.primary_model_name or (
        detector.name if detector.name == "heuristic-fallback" else metrics.get("primary_model") or detector.name)
    log.info("Replay: %s (%d windows) | detector: %s | knowledge base: %s | LLM: %s",
             replay_data.source, len(replay_data), detector.name, settings.knowledge_dir, settings.llm_provider)
    return AppState(
        settings=settings, replay_data=replay_data, detector=detector,
        controller=ReplayController(replay_data, detector, settings.incident_gap_minutes),
        kb=kb, explanations=ExplanationManager(settings, kb),
        model_outputs=ModelOutputs.load(settings.model_outputs, replay_data),
        metrics=metrics, primary_model=primary, edit_lock=threading.Lock())


# ------------------------------------------------------------------ views
def _round(value: float) -> float:
    return round(float(value), 4)


def incident_summary(state: AppState, incident: Incident) -> dict:
    kb, threshold = state.kb, state.detector.threshold
    technique = incident.effective_technique
    tactic, _ = incident.tactic(kb)
    max_probability = max(e.attack_probability for e in incident.edges)
    preview = sorted(incident.edges, key=lambda e: (-e.attack_probability, e.event_id))[:3]
    return {
        "incident_id": incident.incident_id,
        "source_ip": incident.source_ip,
        "technique_id": technique,
        "technique_name": kb.technique_name(technique),
        "tactic": tactic,
        "max_attack_probability": _round(max_probability),
        "severity": incident.severity(),
        "low_confidence": abs(max_probability - threshold) <= 0.10,
        "target_count": len({e.destination_ip for e in incident.edges}),
        "edge_count": incident.edge_count,
        "first_seen": iso(incident.first_window),
        "last_seen": iso(incident.last_window),
        "status": incident.status,
        "technique_override": incident.technique_override,
        "mitigations_applied": list(incident.mitigations_applied),
        "edges_preview": [{"event_id": e.event_id, "window_start": iso(e.window_start),
                           "destination_ip": e.destination_ip, "service": e.service, "port": e.port,
                           "attack_probability": _round(e.attack_probability)} for e in preview],
    }


def related_incidents(state: AppState, incident: Incident) -> list[str]:
    window = pd.Timedelta(minutes=state.settings.related_window_minutes)
    ips = {incident.source_ip} | {e.destination_ip for e in incident.edges}
    related = []
    for other in state.controller.state.incidents.values():
        if other.incident_id == incident.incident_id:
            continue
        other_ips = {other.source_ip} | {e.destination_ip for e in other.edges}
        overlap = other.first_window <= incident.last_window + window and incident.first_window <= other.last_window + window
        if overlap and ips & other_ips:
            related.append(other.incident_id)
    return related


def incident_detail(state: AppState, incident: Incident, refresh: bool) -> dict:
    explanation = state.explanations.view(incident, refresh=refresh)
    kb, data = state.kb, state.replay_data
    summary = incident_summary(state, incident)
    technique_probs = incident.mean_probs("technique_probs")
    candidates = sorted(technique_probs.items(), key=lambda kv: -kv[1])[:3]
    tactic, tactic_confidence = incident.tactic(kb)

    edges = []
    for edge in sorted(incident.edges, key=lambda e: (e.window_start, e.event_id)):
        row = data.frame.iloc[edge.row]
        edges.append({"event_id": edge.event_id, "window_start": iso(edge.window_start),
                      "destination_ip": edge.destination_ip, "attack_probability": _round(edge.attack_probability),
                      "traffic_features": data.traffic_features(row)})

    models = state.model_outputs.for_incident([e.event_id for e in incident.edges])
    if not any(m["model"] == state.primary_model for m in models):
        models.insert(0, {"model": state.primary_model, "label": "attack",
                          "attack_probability": summary["max_attack_probability"],
                          "technique_id": incident.technique_id,
                          "confidence": _round(technique_probs.get(incident.technique_id, 0.0)) if technique_probs else None})

    return {
        **summary,
        "verdict": "attack" if summary["max_attack_probability"] >= state.detector.threshold else "normal",
        "mitre_candidates": [{"rank": i + 1, "technique_id": tid, "name": kb.technique_name(tid),
                              "confidence": _round(p)} for i, (tid, p) in enumerate(candidates)],
        "tactic_prediction": {"label": tactic, "confidence": _round(tactic_confidence)},
        "edges": edges,
        "evidence": incident.evidence,
        "cve_status": incident.cve_status,
        "explanation": explanation,
        "retrieval_trace": incident.retrieval_trace,
        "mitigations": [{"mitigation_id": m["mitigation_id"], "name": m["name"]}
                        for m in kb.mitigations_for(incident.effective_technique)],
        "related_incident_ids": related_incidents(state, incident),
        "models": models,
        "activity": incident.activity,
    }


# ------------------------------------------------------------------ app
def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    app = FastAPI(title="Threat Detection Console API", version="0.4.1",
                  description="Backend for the analyst console (CS/DATA 298B, Team 3).")
    app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_credentials=False,
                       allow_methods=["GET", "POST", "PATCH", "OPTIONS"], allow_headers=["*"])
    app.state.app_state = build_state(settings)

    def get_state(request: Request) -> AppState:
        return request.app.state.app_state

    def require_key(x_api_key: str | None = Header(default=None)) -> None:
        if x_api_key != settings.api_key:
            raise HTTPException(status_code=401, detail="Missing or wrong X-API-Key")

    @app.exception_handler(ReplayError)
    async def replay_error(_: Request, exc: ReplayError):
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

    def find(state: AppState, incident_id: str) -> Incident:
        incident = state.controller.state.incidents.get(incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail=f"No incident with ID {incident_id}")
        return incident

    @app.get("/health", include_in_schema=False)
    def health(state: AppState = Depends(get_state)):
        return {"status": "ok", "detector": state.detector.name, "windows": len(state.replay_data),
                "replay_source": state.replay_data.source, "llm_provider": state.settings.llm_provider}

    @app.post("/detect", response_model=schemas.DetectResponse, tags=["Replay"],
              dependencies=[Depends(require_key)],
              responses={400: {"model": schemas.Error}, 401: {"model": schemas.Error}, 409: {"model": schemas.Error}})
    def detect(body: schemas.DetectRequest | None = Body(default=None), state: AppState = Depends(get_state)):
        body = body or schemas.DetectRequest()
        return state.controller.detect(body.window_start, body.reset)

    @app.get("/incidents", response_model=schemas.IncidentList, tags=["Incidents"],
             dependencies=[Depends(require_key)], responses={401: {"model": schemas.Error}})
    def list_incidents(state: AppState = Depends(get_state)):
        replay = state.controller.state
        last = replay.last_window
        return {
            "replay": {"window_start": iso(last),
                       "window_index": state.replay_data.window_position[last] + 1 if last is not None else 0,
                       "window_count": len(state.replay_data)},
            "primary_model": state.primary_model,
            "threshold": state.detector.threshold,
            "windows": [{"window_start": iso(w), "events": replay.results[w].events,
                         "attack_edges": replay.results[w].attack_edges} for w in replay.order],
            "incidents": [incident_summary(state, i) for i in replay.incidents.values()],
        }

    @app.get("/incidents/{incident_id}", response_model=schemas.IncidentDetail, tags=["Incidents"],
             dependencies=[Depends(require_key)],
             responses={401: {"model": schemas.Error}, 404: {"model": schemas.Error}})
    def get_incident(incident_id: str, refresh_explanation: bool = Query(default=False),
                     state: AppState = Depends(get_state)):
        return incident_detail(state, find(state, incident_id), refresh_explanation)

    @app.patch("/incidents/{incident_id}", response_model=schemas.IncidentSummary, tags=["Incidents"],
               dependencies=[Depends(require_key)],
               responses={401: {"model": schemas.Error}, 404: {"model": schemas.Error}})
    def update_incident(incident_id: str, update: schemas.IncidentUpdate, state: AppState = Depends(get_state)):
        with state.edit_lock:
            incident = find(state, incident_id)
            changed = update.model_fields_set
            if "status" in changed and update.status is not None:
                incident.status = update.status
            if "technique_override" in changed:
                incident.technique_override = update.technique_override
            if "mitigations_applied" in changed and update.mitigations_applied is not None:
                incident.mitigations_applied = list(dict.fromkeys(update.mitigations_applied))
            entry = {"at": now_iso(), "actor": "analyst", "status": incident.status}
            if update.note:
                entry["note"] = update.note
            if "technique_override" in changed:
                entry["technique_override"] = update.technique_override
            if "mitigations_applied" in changed:
                entry["mitigations_applied"] = incident.mitigations_applied
            incident.activity.append(entry)
            return incident_summary(state, incident)

    @app.get("/metrics", tags=["Research"], dependencies=[Depends(require_key)],
             responses={401: {"model": schemas.Error}})
    def metrics(state: AppState = Depends(get_state)):
        payload = dict(state.metrics)
        if "knowledge_base" not in payload:
            techniques = sorted(set(getattr(state.detector, "technique_classes", []) or []))
            payload["knowledge_base"] = state.kb.stats(techniques)
        return payload

    return app
