# Threat Detection Demo (GNN + RAG)

Self-contained Streamlit demo under `app/`:
1. Live GraphSAGE detection on 5-minute windows
2. RAG retrieval (MITRE + ATT&CK procedures) for predicted attacks
3. LLM reasoning via **Groq GPT-OSS** using retrieved sources

## Setup

1. Install deps:

```powershell
cd app
pip install -r requirements.txt
python -m app.rag.bootstrap
```

2. Put your Groq key in **either**:

`app/.env`
```env
GROQ_API_KEY=your_real_key_here
GROQ_MODEL=openai/gpt-oss-20b
```

or `app/.streamlit/secrets.toml`
```toml
GROQ_API_KEY = "your_real_key_here"
GROQ_MODEL = "openai/gpt-oss-20b"
```

Priority: environment / `.env` first, then Streamlit secrets.

Free GPT-OSS options on Groq:
- `openai/gpt-oss-20b` (default, faster)
- `openai/gpt-oss-120b` (stronger reasoning)

3. Run:

```powershell
streamlit run streamlit_app.py
```

If `GROQ_API_KEY` is missing, the app falls back to local grounded synthesis so the demo still runs.

## Data layout (`app/data/`)

```
data/
  models/
  prepared_graphs/
  rag_input/
  rag/
    enterprise-attack.json
    processed/
      mitre_lookup.csv
      procedure_chunks.jsonl
  test_edges_5min_enriched.parquet
```
