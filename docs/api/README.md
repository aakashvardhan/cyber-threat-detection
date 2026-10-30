# API contract

`openapi.yaml` is the single source of truth for the API between the React analyst console (`frontend/`) and the FastAPI backend (`backend/`).

Current version: **v0.4.1**: 4 endpoints + 1 optional. Every request sends the shared demo key in the `X-API-Key` header.

| # | Endpoint | Purpose | Computed |
|---|---|---|---|
| 1 | `POST /detect` | Run the primary GNN on the next 5-minute window; group attack edges into incidents | Live (replay) |
| 2 | `GET /incidents` | All incidents so far + per-window stats | Live |
| 3 | `GET /incidents/{incident_id}` | Full incident; RAG + LLM run on the first call, then cached | Live |
| 4 | `GET /metrics` | Offline evaluation, RAG ablation, knowledge-base stats | Offline |
| 5 | `PATCH /incidents/{incident_id}` | Status, note, applied mitigations (optional) | Live |

## Viewing the spec

- Paste `openapi.yaml` into <https://editor.swagger.io> for an interactive view, or
- Once the backend's Pydantic models match the spec, FastAPI serves the same docs at `/docs`.

## How it is used

- **Frontend:** builds mock JSON from the examples in the spec, so it can be developed before the backend is ready. Switching to the real backend only changes the base URL.
- **Backend:** request and response models follow the schemas in `components/schemas`. Field names match `create_gnn_json()` in `demo/2026-10-06_meeting/app/inference/json_export.py`.

## Changing the API

1. Edit `openapi.yaml` in a branch and open a PR that links the Linear issue.
2. Bump `info.version` (e.g. 0.4.0 → 0.5.0) and say what changed in the PR description.
3. Frontend and backend owners both review before merging, because any change affects both sides.
