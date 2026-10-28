"""Request and response models from docs/api/openapi.yaml (v0.4.2)."""
from __future__ import annotations

from datetime import datetime
from typing import ClassVar, Literal

from pydantic import BaseModel, ConfigDict, Field, model_serializer

IncidentStatus = Literal["new", "confirmed", "investigating", "contained", "closed", "dismissed"]
Severity = Literal["high", "medium", "low"]


class _Model(BaseModel):
    """Optional fields left as None are omitted; fields in NULLABLE are sent as null (as in the spec)."""
    model_config = ConfigDict(extra="ignore")
    NULLABLE: ClassVar[frozenset[str]] = frozenset()

    @model_serializer(mode="wrap")
    def _omit_unset_optionals(self, handler):
        data = handler(self)
        return {k: v for k, v in data.items() if v is not None or k in self.NULLABLE}


class Error(_Model):
    detail: str


class DetectRequest(_Model):
    window_start: datetime | None = None
    reset: bool = False


class DetectResponse(_Model):
    NULLABLE = frozenset({"next_window_start"})
    window_start: str
    next_window_start: str | None
    already_processed: bool
    window_index: int
    window_count: int
    events: int
    attack_edges: int
    new_incident_ids: list[str]
    updated_incident_ids: list[str]


class ReplayState(_Model):
    NULLABLE = frozenset({"window_start"})
    window_start: str | None
    window_index: int
    window_count: int
    first_window_start: str | None = None
    last_window_start: str | None = None
    day_starts: list[str] | None = None


class WindowStats(_Model):
    window_start: str
    events: int
    attack_edges: int


class EdgePreview(_Model):
    NULLABLE = frozenset({"service", "port"})
    event_id: str
    window_start: str
    destination_ip: str
    service: str | None = None
    port: int | None = None
    attack_probability: float


class IncidentSummary(_Model):
    NULLABLE = frozenset({"severity", "technique_override"})
    incident_id: str
    source_ip: str
    technique_id: str
    technique_name: str
    tactic: str
    max_attack_probability: float
    severity: Severity | None
    low_confidence: bool
    target_count: int
    edge_count: int
    first_seen: str
    last_seen: str
    status: IncidentStatus = "new"
    technique_override: str | None = None
    mitigations_applied: list[str] = Field(default_factory=list)
    edges_preview: list[EdgePreview] = Field(default_factory=list)


class IncidentList(_Model):
    replay: ReplayState
    primary_model: str
    threshold: float
    windows: list[WindowStats]
    incidents: list[IncidentSummary]


class MitreCandidate(_Model):
    rank: int
    technique_id: str
    name: str | None = None
    confidence: float


class TacticPrediction(_Model):
    label: str
    confidence: float


class Edge(_Model):
    event_id: str
    window_start: str
    destination_ip: str
    attack_probability: float
    traffic_features: dict


class Evidence(_Model):
    NULLABLE = frozenset({"url"})
    evidence_id: str
    source: Literal["mitre", "cti", "procedure", "cve"]
    level: Literal["technique", "tactic", "procedure", "cve"]
    ref: str | None = None
    title: str
    text: str
    score: float
    url: str | None = None


class Sentence(_Model):
    text: str
    citations: list[str]


class Explanation(_Model):
    NULLABLE = frozenset({"model"})
    status: Literal["generating", "ready", "error"]
    stale: bool = False
    based_on_edge_count: int | None = None
    started_at: str | None = None
    message: str | None = None
    model: str | None = None
    mode: Literal["llm", "fallback"] | None = None
    latency_ms: int | None = None
    groundedness: float | None = None
    sentences: list[Sentence] = Field(default_factory=list)
    next_steps: list[str] = Field(default_factory=list)


class RetrievalSource(_Model):
    source: Literal["mitre", "procedure", "cti", "cve"]
    searched: int | None = None
    returned: int
    skipped: bool | None = None


class BehaviorCandidate(_Model):
    technique_id: str
    name: str
    rank: int


class BehaviorCheck(_Model):
    """ATT&CK techniques the traffic pattern matches, searched without the detector's technique."""
    NULLABLE = frozenset({"agrees_with_detector"})
    facts: str
    reading: list[str]
    method: str
    candidates: list[BehaviorCandidate]
    agrees_with_detector: bool | None = None


class RetrievalTrace(_Model):
    query: str
    sources: list[RetrievalSource]
    top_k: int | None = None
    min_score: float | None = None
    fallback_to_tactic: bool | None = None
    latency_ms: int | None = None
    behavior_check: BehaviorCheck | None = None


class Mitigation(_Model):
    mitigation_id: str
    name: str


class ModelOutput(_Model):
    NULLABLE = frozenset({"attack_probability", "technique_id", "confidence", "groundedness"})
    model: str
    label: Literal["attack", "normal"]
    attack_probability: float | None = None
    technique_id: str | None = None
    confidence: float | None = None
    explanation_text: str | None = None
    groundedness: float | None = None


class ActivityEntry(_Model):
    NULLABLE = frozenset({"technique_override"})
    at: str
    actor: str | None = None
    status: IncidentStatus
    note: str | None = None
    technique_override: str | None = None
    mitigations_applied: list[str] | None = None


class IncidentDetail(IncidentSummary):
    NULLABLE = IncidentSummary.NULLABLE
    verdict: Literal["attack", "normal"]
    mitre_candidates: list[MitreCandidate]
    tactic_prediction: TacticPrediction
    edges: list[Edge]
    evidence: list[Evidence]
    cve_status: Literal["applicable", "not_applicable"]
    explanation: Explanation
    retrieval_trace: RetrievalTrace | None = None
    mitigations: list[Mitigation]
    related_incident_ids: list[str]
    models: list[ModelOutput]
    activity: list[ActivityEntry] = Field(default_factory=list)


class IncidentUpdate(_Model):
    status: IncidentStatus | None = None
    technique_override: str | None = None
    note: str | None = None
    mitigations_applied: list[str] | None = None
