# backend/data

Put the model artifacts here (they are git-ignored). Every file is optional; the backend uses what it finds.

| File | From | Used for |
|---|---|---|
| `test_edges.parquet` | Sai, `processed_edges/test_edges.parquet` (raw, pre-log, with IPs) | Replay traffic for `POST /detect` |
| `graphsage_best_model.pt` (or `graphsage_exp1_best_model.pt`) | Sai, model training notebook | Primary model (3-head GraphSAGE) |
| `preprocessing_objects.joblib` | Sai, data-prep notebook | Scalers, one-hot encoder, label binarizers |
| `primary_predictions.parquet` | Decision model (model_5) or any model | Primary model as precomputed per-edge predictions, with severity |
| `model_outputs.jsonl` | Evaluation notebooks | Models 1-5 outputs on the Research tab |
| `metrics.json` | Evaluation notebooks | `GET /metrics` (falls back to `app/data/metrics.default.json`) |
| `knowledge/` | RAG pipeline | `mitre_lookup.csv`, `mitre_mitigations.csv`, `procedure_chunks.jsonl`, optional `cti_chunks.jsonl`, `cve_chunks.jsonl` (falls back to the Oct 6 demo files) |

## Formats

`primary_predictions.parquet`, one row per edge:

| column | type | required |
|---|---|---|
| `window_start`, `src_ip_zeek`, `dest_ip_zeek` | timestamp, string, string | yes |
| `attack_probability` | float | yes |
| `technique_candidates` | JSON list of `{"technique_id", "confidence"}` | no (or `technique_id` + `technique_confidence`) |
| `tactic`, `tactic_confidence` | string, float | no |
| `severity` | `high` / `medium` / `low` | no |
| `threshold` | float (same on every row) | no |

`model_outputs.jsonl`, one line per (edge, model):

```json
{"event_id": "uwf-test-135942", "model": "model_4", "label": "attack", "attack_probability": 0.91,
 "technique_id": "T1190", "confidence": 0.64, "explanation_text": "...", "groundedness": 0.85}
```

`event_id` can be replaced by `window_start` + `src_ip_zeek` + `dest_ip_zeek`.
