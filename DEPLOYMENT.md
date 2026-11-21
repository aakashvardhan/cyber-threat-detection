# Deploying the Threat Console

How the app runs in containers, locally and on AWS. Local setup: Jane (SJSU-130, SJSU-132); AWS setup: Shriansh.

## Services

| Service | Image | Port (host) | Stores |
|---|---|---|---|
| `frontend` | `frontend/Dockerfile` (React build on nginx) | 8080 | — |
| `backend` | `backend/Dockerfile` (FastAPI, GraphSAGE/HGT on CPU, GraphRAG) | 8000 | — (reads `backend/data`) |
| `neo4j` | `neo4j:5-community` | 7474 (browser), 7687 (Bolt) | ATT&CK knowledge graph (GraphRAG) |
| `chroma` | `infra/chroma/Dockerfile` | 8001 | Vector index of CTI / procedure / CVE text |
| `dynamodb` | `amazon/dynamodb-local` | 8002 | Analyst edits and cached explanations per incident (SJSU-131) |

The backend loads the ATT&CK graph into Neo4j on start when Neo4j is empty or holds an older graph, and builds the
Chroma index on its first start (about 10 minutes on a laptop CPU; reused afterwards). If Neo4j or Chroma cannot be
reached, it logs a warning and keeps working with the in-memory graph and local index files.

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
   - http://localhost:8080: the console; open an incident and check the Knowledge graph panel
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

On-demand billing; items are a few KB to a few tens of KB. When the replay creates an incident, the saved state is put
back, so edits and explanations survive a restart, a Reset in the console and a redeploy. If DynamoDB cannot be
reached, the backend logs a warning and keeps the state in memory. `python scripts/create_tables.py` creates the table;
`--clear` removes saved state (e.g. before a clean demo).

## Environment variables

Compose reads `.env` in the repository root (see `.env.example`):

| Variable | Default | |
|---|---|---|
| `API_KEY` | required | Shared key; the frontend is built with it |
| `NEO4J_PASSWORD` | required | Neo4j password (8+ characters) |
| `LLM_PROVIDER` | `groq` | `none` = explanations from the evidence only |
| `GROQ_API_KEY` | empty | Keep it out of Git; on AWS use Secrets Manager or SSM Parameter Store |
| `PUBLIC_API_URL` | `http://localhost:8000` | Where the browser reaches the API; baked into the frontend at build time |
| `AWS_REGION` | `us-west-2` | Region for DynamoDB |

The backend's other settings (`backend/.env.example`) can be added under `backend: environment:` in the compose file.

## On AWS (handover to the deployment issue)

What the app needs; the choices are Shriansh's:

- **Compute**: one EC2 instance with Docker is enough for the demo: 2 vCPU / 8 GB RAM (e.g. `t3.large`); detection
  takes about 75–90 ms per window on 2 vCPU. Install Docker and the compose plugin, clone `main`, then the steps above.
- **Data**: keep `backend/data` in an S3 bucket and sync it on the instance before starting
  (`aws s3 sync s3://<bucket>/backend-data backend/data`); the instance role needs `s3:GetObject` / `s3:ListBucket`.
- **DynamoDB**: create the table above (`python scripts/create_tables.py` with AWS credentials, or the console:
  table `threat-console-incidents`, partition key `model` (String), sort key `incident_id` (String), on-demand).
  In the backend environment keep `INCIDENT_STORE=dynamodb`, remove `DYNAMODB_ENDPOINT` and the dummy keys so it uses
  the instance role, and set `DYNAMODB_CREATE_TABLE=false` if the role cannot create tables. The role needs
  `dynamodb:DescribeTable`, `GetItem`, `Query`, `UpdateItem` (and `Scan`, `BatchWriteItem` for `--clear`) on that table.
- **Secrets**: `GROQ_API_KEY`, `API_KEY` and `NEO4J_PASSWORD` from Secrets Manager or SSM, written to `.env` at boot.
- **Network**: open 80/443 (frontend) and the API port to users; keep 7474/7687 (Neo4j), 8001 (Chroma) and 8002
  (DynamoDB Local) closed to the internet. Set `PUBLIC_API_URL` to the public API address and add the console's
  address to `CORS_ORIGINS`.
- **Frontend**: either the `frontend` container on the same instance, or `npm run build` with `VITE_API_BASE_URL`
  and `VITE_API_KEY` set and the `dist` folder on Amplify / S3 + CloudFront.
- **Logs**: `docker compose logs`; for CloudWatch, the `awslogs` logging driver on each service.
