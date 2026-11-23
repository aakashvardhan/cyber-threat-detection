# Deploying the Threat Console

How the app runs in containers, locally and on AWS. Local setup: Jane (SJSU-130, SJSU-132); AWS setup: Shriansh.

## Services

| Service | Image | Port (host) | Stores |
|---|---|---|---|
| `frontend` | `frontend/Dockerfile` (React build on nginx; proxies `/api` to the backend) | `CONSOLE_PORT` (8080), **the only public port** | — |
| `backend` | `backend/Dockerfile` (FastAPI, GraphSAGE/HGT on CPU, GraphRAG) | 127.0.0.1:8000 | — (reads `backend/data`) |
| `neo4j` | `neo4j:5-community` | 127.0.0.1:7474 (browser), 127.0.0.1:7687 (Bolt) | ATT&CK knowledge graph (GraphRAG) |
| `chroma` | `infra/chroma/Dockerfile` | 127.0.0.1:8001 | Vector index of CTI / procedure / CVE text |
| `dynamodb` | `amazon/dynamodb-local` | 127.0.0.1:8002 | Analyst edits, explanations and chats per incident (SJSU-131) |

**How the browser reaches the API.** The console calls `/api/...` on its own origin; nginx in the `frontend` container
adds the shared `API_KEY` and forwards the request to the backend on the compose network. The key is never in the
JavaScript the browser downloads. Set `BASIC_AUTH_USER` / `BASIC_AUTH_PASSWORD` to put a login in front of the whole
console (recommended whenever it is reachable from the internet). The backend, Neo4j, Chroma and DynamoDB Local are
bound to 127.0.0.1 on the host (for debugging there) and are otherwise only reachable inside the compose network;
Chroma and DynamoDB Local have no authentication of their own, so never publish their ports.

The backend loads the ATT&CK graph into Neo4j on start when Neo4j is empty, holds an older graph or a load was
interrupted (only nodes labelled `:AttackEntity` are replaced; other data in the database is left alone), and builds
the Chroma index on its first start (about 10 minutes on a laptop CPU; reused afterwards, rebuilt when a chunk's text
changes or a build was interrupted). The backend starts as soon as Neo4j and Chroma have started, waits up to about
two minutes (Neo4j) and one minute (`CHROMA_WAIT_S`, Chroma) for them, and otherwise keeps working with the in-memory
graph and the local index files. Its health check allows 15 minutes for the first start.

## Run locally

Requirements: Docker Desktop (Windows: with WSL 2), about 8 GB of free RAM for Docker, 10 GB of disk.

1. Check out `main`.
2. Put the data files in `backend/data` (they are not in Git):

   | File | What |
   |---|---|
   | `graphsage_exp1_best_model.pt`, `preprocessing_objects.joblib` | GraphSAGE checkpoint and preprocessing (Sai) |
   | `transformer_best_model.pt` | Hierarchical Graph Transformer checkpoint (Sai) |
   | `test_edges.parquet` | Test split replayed by the console (69,161 edges) |
   | `model_outputs.jsonl`, `metrics.json` | Research tab and Evaluation page |
   | `knowledge/mitre_lookup.csv`, `knowledge/mitre_mitigations.csv` | ATT&CK lookup |
   | `knowledge/procedure_chunks.jsonl`, `knowledge/cti_chunks.jsonl`, `knowledge/cve_chunks.jsonl` | RAG sources |

   The ATT&CK STIX file is read from `demo/2026-10-06_meeting/app/data/rag/enterprise-attack.json` (in Git).
3. `cp .env.example .env` and set `API_KEY`, `NEO4J_PASSWORD` (8+ characters) and `GROQ_API_KEY`
   (or `LLM_PROVIDER=none` for evidence-only explanations).
4. `docker compose up -d --build`
5. Check:
   - `docker compose ps`: all services `running`, backend `healthy` (the first start takes a few minutes)
   - http://localhost:8000/health shows the detector and `"llm_provider"`
   - `docker compose logs backend | grep -i "graphrag\|neo4j\|chroma"` shows `GraphRAG (neo4j)` and the Chroma server
   - http://localhost:8080: the console (log in if `BASIC_AUTH_USER` is set); open an incident and check the
     Knowledge graph panel and "Ask about this incident"
   - http://localhost:7474: Neo4j Browser, e.g. `MATCH (t:Technique {id:'T1595'})<-[:USES]-(g:Group) RETURN t, g`

Stop with `docker compose down` (data in the named volumes stays); `docker compose down -v` also deletes the
Neo4j, Chroma and DynamoDB volumes.

## Incident state (DynamoDB)

Incidents come from the replay in a fixed order, so each live model always produces the same incident IDs. The
backend stores what is added on top of them in one table, `threat-console-incidents`:

| Key / attribute | Type | |
|---|---|---|
| `model` | partition key (S) | live model: `graphsage` or `hgt` |
| `incident_id` | sort key (S) | e.g. `INC-0042` |
| `status`, `technique_override` | S | analyst edits |
| `mitigations_applied`, `activity` | S (JSON) | applied mitigations, activity log with notes |
| `explanation`, `evidence`, `retrieval_trace`, `cve_status` | S (JSON / S) | cached explanation, so the LLM is not called again |
| `updated_at` | S | last write (UTC) |

| `chat` | S (JSON) | the incident chat (last 20 messages) |
| `fingerprint` | S | source IP, first window and detector technique of the incident the state belongs to |

On-demand billing; items are a few KB to a few tens of KB (the activity log keeps the last 200 entries). When the
replay creates an incident, the saved state is put back if its `fingerprint` matches, so edits, explanations and chats
survive a restart, a Reset in the console and a redeploy, and never move to another incident when the replay data or
the model change.

If DynamoDB is still starting, the backend retries for `DYNAMODB_WAIT_S` seconds (30). If it cannot be reached at all,
the backend logs an error and keeps the state in memory only. A write that fails later is kept in memory and retried
with the next write; a read that fails uses the in-memory copy, so a Reset during an outage loses nothing.

**One backend process.** The incident state lives in the backend's memory and DynamoDB keeps it across restarts. The
backend also loads Neo4j and builds the Chroma index on its first start. Run exactly one backend container against a
given table, Neo4j and Chroma (as the compose file does); several replicas, or a rolling deploy that starts the new
backend before the old one stops, are not supported. Redeploy with `docker compose up -d --build`, which replaces the
container.

Table commands, from the repository root (a one-off backend container, so nothing needs installing on the host):

```bash
docker compose run --rm backend python scripts/create_tables.py                # create the table if it is missing
docker compose stop backend                                                    # stop the backend before clearing
docker compose run --rm backend python scripts/create_tables.py --clear --yes  # remove all saved state
docker compose start backend
```

Without Docker: `python backend/scripts/create_tables.py` (with the backend's virtual environment).

## Environment variables

Compose reads `.env` in the repository root (see `.env.example`):

| Variable | Default | |
|---|---|---|
| `API_KEY` | required | Shared key between the console's nginx proxy and the backend; never sent to browsers |
| `BASIC_AUTH_USER`, `BASIC_AUTH_PASSWORD` | empty | Login for the console; empty = no login (only for localhost) |
| `CONSOLE_PORT` | `8080` | Host port of the console (80 on AWS) |
| `NEO4J_PASSWORD` | required | Neo4j password (8+ characters) |
| `LLM_PROVIDER` | `groq` | `none` = explanations from the evidence only |
| `GROQ_API_KEY` | empty | Keep it out of Git; on AWS use Secrets Manager or SSM Parameter Store |
| `AWS_REGION` | `us-west-2` | Region for DynamoDB |
| `DYNAMODB_ENDPOINT` | `http://dynamodb:8000` | DynamoDB Local; set it **empty** (`DYNAMODB_ENDPOINT=`) on AWS to use the real service |
| `DYNAMODB_CREATE_TABLE` | `true` | `false` if the instance role may not create tables |
| `CORS_ORIGINS` | `http://localhost:5173` | Only for a dev server on another origin; the console itself calls `/api` on its own origin |
| `RERANK` | `false` | Cross-encoder reranking of the evidence. Off because the LLM-judge comparison showed no gain beyond judge variance and it adds memory; `true` turns it on (no rebuild needed) |

The backend's other settings (`backend/.env.example`) can be added under `backend: environment:` in the compose file.

## On AWS (handover to the deployment issue)

What the app needs; the choices are Shriansh's:

- **Compute**: one EC2 instance with Docker is enough for the demo: 2 vCPU / 8 GB RAM (e.g. `t3.large`); detection
  takes about 75–90 ms per window on 2 vCPU. Install Docker and the compose plugin, clone `main`, then the steps above.
- **Data**: keep `backend/data` in an S3 bucket and sync it on the instance before starting
  (`aws s3 sync s3://<bucket>/backend-data backend/data`); the instance role needs `s3:GetObject` / `s3:ListBucket`.
- **DynamoDB**: create the table above (`python backend/scripts/create_tables.py` with AWS credentials, or the
  console: table `threat-console-incidents`, partition key `model` (String), sort key `incident_id` (String),
  on-demand). In `.env` set `DYNAMODB_ENDPOINT=` (empty): the backend then uses the real service with the instance
  role (the compose file holds no credentials). Set `DYNAMODB_CREATE_TABLE=false` if the role cannot create tables.
  The role needs `dynamodb:DescribeTable`, `GetItem`, `Query`, `UpdateItem` (and `Scan`, `BatchWriteItem` for
  `--clear`) on that table. The `dynamodb` (Local) container still starts but is not used.
- **Secrets**: `GROQ_API_KEY`, `API_KEY`, `NEO4J_PASSWORD` and `BASIC_AUTH_PASSWORD` from Secrets Manager or SSM,
  written to `.env` at boot.
- **HTTPS**: put an Application Load Balancer with an ACM certificate (or CloudFront) in front of the console port and
  let the instance's security group accept the console port only from the load balancer. Users then reach the
  console, its login and `/api` over HTTPS only. (Without a domain, a self-signed certificate on the load balancer is
  still better than plain HTTP for the demo.)
- **Network**: the security group opens only the console port (`CONSOLE_PORT=80`, or 443 behind a load balancer)
  and SSH for admins. Nothing else needs a rule: the other services listen on 127.0.0.1 only. Set
  `BASIC_AUTH_USER` / `BASIC_AUTH_PASSWORD` so the console asks for a login.
- **Frontend**: the `frontend` container on the same instance. (A static build on Amplify / S3 + CloudFront would
  have to call the API directly with the key in the bundle, which exposes it; don't, unless the API sits behind real
  user authentication.)
- **Logs**: `docker compose logs`; for CloudWatch, the `awslogs` logging driver on each service.
