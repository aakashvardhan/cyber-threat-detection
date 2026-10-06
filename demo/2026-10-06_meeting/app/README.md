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

## Gemma 4 prompting page

`pages/1_Gemma4_Prompting.py` appears in the sidebar of the running app. It shows, for any of the 400 evaluated test edges:

- the event being classified (JSON event layout: `event_id`, `row_id`, `event.traffic_features`) and, for few-shot, how many labelled examples the prompt carries,
- the saved Gemma 4 reply, parsed verdict, MITRE technique, and ground truth,
- a **Compare runs** tab with recall, false-positive rate, projected precision and F1, and technique accuracy for zero-shot and three few-shot example draws, next to GraphSAGE.

Saved results live in `data/llm_eval/` (the final answers only; the model's reasoning is not stored or shown). Replay needs no key and no prompt configuration.

**Private prompt configuration.** The prompt wording and the few-shot examples are not in this repository. Live calls need them, loaded at run time from the first of:

1. the Streamlit secret (or environment variable) `GEMMA_PROMPT_CONFIG`, holding the JSON text,
2. the file named by `GEMMA_PROMPT_CONFIG_FILE`,
3. `app/.private/prompt_config.json` (gitignored).

Schema (`version` 1): `system`, `joiner`, `example_template` (placeholders `{n}`, `{event}`, `{answer}`), `target_template` (placeholder `{event}`), and `draws` mapping each few-shot draw to its list of `{event, answer}` examples. Without the configuration the page still works for replay and comparison, and live calls are disabled with a notice. To deploy, paste the configuration into the app's Secrets as `GEMMA_PROMPT_CONFIG`.

**Live call.** Paste a Gemini API key in the sidebar and click *Run live*. You can send the selected edge or paste your own event; `gnn_detection` and `ground_truth` are removed before sending. The key stays in that browser session only: it is sent to the Gemini API over HTTPS and is never saved, logged, or displayed, and error messages are scrubbed of it. A deployer can instead set `GEMINI_API_KEY` in Streamlit secrets or the environment. The saved replies came from an earlier prompt format, so repeat the runs before comparing live results with the saved numbers.

Tests: from `demo/2026-10-06_meeting`, run `python -m pytest app/tests -q`.
