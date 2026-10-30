# Backend: Threat Detection Console API

FastAPI implementation of the API contract in `docs/api/openapi.yaml` (v0.4.2, SJSU-113) for the analyst console.

## Run

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # set API_KEY; add GROQ_API_KEY or LLM_BASE_URL for LLM explanations
set -a && source .env && set +a
uvicorn app.main:create_app --factory --reload --port 8000
```

Interactive docs: <http://localhost:8000/docs>. Every request needs the `X-API-Key` header.

Python 3.10 or newer.

## Endpoints

| Endpoint | What it does |
|---|---|
| `POST /detect` | Runs the primary model on one 5-minute test window and groups attack edges into incidents (same source IP and top technique within 30 minutes). Idempotent per window; `reset` is atomic. |
| `GET /incidents` | Replay position, per-window stats and all incident summaries |
| `GET /incidents/{id}` | Full incident. Retrieval runs on the first call; the LLM explanation runs in the background (`status: generating`, poll until `ready`). Cached, with `stale` set when the incident grows; `?refresh_explanation=true` regenerates. |
| `PATCH /incidents/{id}` | Status, technique override, note, applied mitigations; appends to `activity` |
| `GET /metrics` | Offline evaluation (`metrics.json`) plus live knowledge-base stats |

## How the pieces plug in

The backend runs today with what is in the repo and switches to the real artifacts as they are delivered (see `data/README.md`):

| Piece | Until it arrives | When it arrives |
|---|---|---|
| Replay traffic | Oct 6 demo test split | Sai's `test_edges.parquet` |
| Primary model | Label-free heuristic, shown as `heuristic-fallback` | Sai's GraphSAGE (`graphsage_best_model.pt` + `preprocessing_objects.joblib`), or any model's per-edge predictions (`primary_predictions.parquet`, e.g. the decision model with severity) |
| Explanations | Evidence-only sentences with citations (`mode: fallback`) | Groq (`LLM_PROVIDER=groq`) or the fine-tuned LLM behind an OpenAI-compatible server (`LLM_PROVIDER=local`) |
| Knowledge base | ATT&CK lookup + procedure examples (built from `enterprise-attack.json` if `procedure_chunks.jsonl` is an LFS pointer) | `data/knowledge/` with `cti_chunks.jsonl` and `cve_chunks.jsonl` from the RAG notebook (shared drive, `RAG Corpus/processed`) |
| Retrieval | Token overlap | Vector search from the RAG notebook (Chroma + all-MiniLM-L6-v2), on automatically when `chromadb` and `sentence-transformers` are installed |
| Research tab (Models 1-5) | Primary model only | `model_outputs.jsonl` |
| Metrics | `app/data/metrics.default.json` (verified numbers only) | `data/metrics.json` |

`GET /health` (no key) reports which detector, replay file and LLM provider are active.

## Retrieval (RAG)

Follows `notebooks/RAG/rag.ipynb`. For each incident, on the first `GET /incidents/{id}`:

1. **Evidence for the detector's technique**: MITRE entry, then CTI-HAL chunks of that technique, then ATT&CK procedure examples of that technique, then CTI chunks of other techniques in the same tactic (`level` = technique / procedure / tactic). CVEs only for exploit-type techniques (T1190, T1210, ...), filtered by the service keyword (HTTP, SSH, ...).
2. **Behaviour check** (`retrieval_trace.behavior_check`): the incident's traffic is described in numbers (`facts`), turned into a short analyst reading (`reading`, e.g. "repeated login attempts against ssh authentication"), and searched over **all** ATT&CK techniques without the detector's technique as a filter (BM25 over technique descriptions and network detection analytics, fused with vector search when available). `agrees_with_detector` is false when the detector's technique is not in the top 3; the explanation then names the alternative. This is how a technique the detector never learned can still surface: in leave-one-recording-out tests, Brute Force (absent from training when ZeekData24 is held out) came first for 95% of those incidents with the reading, and was never found with the facts alone.

| Setting | Default | |
|---|---|---|
| `RAG_MODE` | `auto` | `vector` (fail if unavailable), `token` (old token overlap) |
| `EMBED_MODEL` | `sentence-transformers/all-MiniLM-L6-v2` | Hugging Face name or a local folder |
| `CHROMA_DIR` | `data/chroma_db` | The index is built on first start (about 10 minutes on a laptop CPU with CVE + procedures) and reused; a collection is rebuilt when its source file changes |
| `ATTACK_STIX` | `data/knowledge/enterprise-attack.json`, else the Oct 6 demo copy | Technique documents for the behaviour check; procedure examples |
| `BEHAVIOR_CHECK` | `true` | |

## Notes

- Retrieval maps the old UWF tactic "Defense Evasion" to the newer ATT&CK names (Stealth, Defense Impairment), so tactic fallback still finds evidence.
- With `REDACT_IPS=true`, IPs are replaced by `host-A`, `host-B`, ... before anything is sent to the LLM and mapped back in the response.
- State lives in memory: restarting the server clears incidents (the frontend replays again).
- `POST /detect` and `PATCH` run under a lock; at most one explanation job runs per incident.

## Tests

```bash
cd backend && pytest
```

`tests/test_contract.py` checks every path, method and required field against `docs/api/openapi.yaml` when the spec is present (set `OPENAPI_SPEC` to point elsewhere).
