# Cyber Threat Detection

An explainable threat-detection system for Zeek network logs. It decides whether traffic between two hosts is an attack, names the MITRE ATT&CK tactics and techniques involved, and explains each incident with cited evidence so an analyst can check the call.

We built and compared five models on the same data: two graph neural networks and three fine-tuned language models. A retrieval-augmented (RAG) layer sits on top of whichever model is used and writes the explanation. This README follows Workbook 2 (November 2026).

## Contents

1. [The problem](#1-the-problem)
2. [Repository layout](#2-repository-layout)
3. [Data](#3-data)
4. [Models](#4-models)
5. [RAG explanation layer](#5-rag-explanation-layer)
6. [How we evaluate](#6-how-we-evaluate)
7. [Results](#7-results)
8. [Threat console](#8-threat-console)
9. [Limitations](#9-limitations)
10. [Reproducing the results](#10-reproducing-the-results)

## 1. The problem

Analysts get millions of connection logs, and only a small share are attacks. Flagging an attack isn't enough: the analyst also needs to know what kind it is and why the system thinks so. We split the work into four problems:

| # | Problem | Handled by |
|---|---|---|
| a | Is this connection an attack? | All five models |
| b | Which ATT&CK tactics are involved? (13 classes, multi-label) | All five models |
| c | Which ATT&CK techniques are involved? (27 classes, multi-label) | All five models |
| d | Why, with evidence the analyst can verify? | RAG layer |

A single connection can involve more than one tactic or technique, so (b) and (c) are multi-label.

## 2. Repository layout

| Path | Contents |
|---|---|
| `notebooks/eda_data_prep/` | Data gathering, EDA, and the windowed graph preprocessing from Workbook 1 |
| `laya/graphSAGE-data-prep.ipynb` | Builds the shared 5-minute edges and the random 80/10/10 split used by all five models |
| `mistral_multi_lora/` | Model 2: Mistral-7B multi-LoRA fine-tuning notebook, results, and adapter configs |
| `notebooks/fine_tuned_llm/` | Model 3: Qwen2.5-7B QLoRA fine-tuning notebook |
| `laya/` | Model 5: Laya baseline and fine-tuning notebook, GPU Docker setup, and run outputs |
| `notebooks/blocked_cv/` | Split-strategy study and leave-one-recording-out evaluation for the GNN |
| `notebooks/RAG/rag.ipynb` | Knowledge-base preparation for the RAG layer |
| `notebooks/gnn_rag/` | Earlier GraphSAGE pipeline on the chronological split (Workbook 1) |
| `intelligence/` | Zero-shot and few-shot LLM baseline harness (`baseline_llm.py`) and tests |
| `evaluation/model_b/` | Zero-shot and few-shot LLM baseline outputs and write-ups |
| `docs/api/openapi.yaml` | API contract between the console frontend and backend (v0.5.0) |
| `pipeline/` | Airflow DAG that loads Parquet from S3 into ClickHouse |
| `demo/2026-10-06_meeting/app/` | Earlier Streamlit demo |
| `backend/`, `frontend/`, `infra/` | Placeholders. The console code described in section 8 hasn't been merged here yet |

The notebooks for Model 1 (GraphSAGE on the new split) and Model 4 (Hierarchical Graph Transformer) aren't in the repository yet either.

## 3. Data

We use the public [UWF Zeek datasets](https://datasets.uwf.edu/data/): six recordings, 50 Parquet files, about 27.1 million connection logs from December 2021 to July 2025.

### Preparation

1. **Ingest and clean.** Load every file into DuckDB, cast all files to one schema, drop the 33,053 rows labelled `Duplicate`, and fill nulls. This leaves 27,078,541 logs.
2. **Label.** A log is an attack when `label_tactic` is set. Tactic and technique labels come from the same columns.
3. **Aggregate.** Group logs into edges, one per source IP, destination IP, and 5-minute window. A window becomes a directed graph with hosts as nodes and edges as connections.
4. **Split.** Make a random 80/10/10 split of whole windows (seed 42), stratified by whether a window contains an attack. Every edge in a window lands in the same split.

The test split has 2,518 windows and 69,161 edges, 5,670 of them attacks (about 8%).

**Why not a chronological split?** Workbook 1 split by time, but that left almost no attacks in the validation set. The random window split fixes that. The catch is that windows from the same attack campaign can show up in both training and test, so section 6 adds extra checks to measure how much that inflates the scores.

### What the data looks like

- **Techniques are heavily skewed.** T1595 Active Scanning and T1046 Network Service Discovery dominate. Many of the 27 techniques have only a handful of examples, which is why macro-F1 stays low for most models.
- **Recordings differ a lot.** At the edge level the attack share ranges from about 0.3% to 62% depending on the recording, and features such as packet history and response packets vary between them.
- **Near-duplicates are common.** Scripted campaigns repeat the same traffic, so a test connection often has a near-identical twin in training.

## 4. Models

All five models get the same three tasks and the same split. The graph models read each 5-minute window as a graph. The language models read each connection as a short text summary.

### Model 1: GraphSAGE

Two SAGEConv layers (hidden size 32, ReLU, dropout 0.35) build an embedding for every host from its neighbours. For each edge, the source embedding, destination embedding, and edge features are joined and passed to three small MLP heads: attack, tactics, and techniques.

- 22 node features describe what each host did as sender and receiver: edges, connections, unique peers, duration, bytes, packets, and TCP/UDP/ICMP activity.
- 56 edge features summarise traffic on each pair: connection count, duration and byte statistics, distinct and most common destination ports, and protocol counts.
- Counts are log1p-transformed and standardised, with the scaler fitted on training data only. IP addresses are never features.
- The loss is binary cross-entropy for attack plus 0.25 × each of the tactic and technique losses. Rare labels get higher positive weights (square root of the class ratio, capped at 5).
- Training: Adam, learning rate 1e-4, weight decay 1e-3, 64 window graphs per batch, up to 30 epochs, early stopping after 5 epochs without improvement.

GraphSAGE is the live detector in the console.

### Model 2: Mistral-7B multi-LoRA

One Mistral-7B-Instruct-v0.3 base model shares its weights across three LoRA adapters, one per task. The adapter is switched at inference time, so there's no need to keep three full copies of the model.

- QLoRA: 4-bit NF4 base model, LoRA rank 16 and alpha 16 on the attention and feed-forward projections. That's about 41.9M trainable parameters per adapter, roughly 0.58% of the model.
- Loss is computed only on the JSON answer, not on the input summary.
- One epoch, learning rate 2e-4, max 1,024 tokens, on a single RTX 5080 (16 GB).
- Data: 4,998 training connections (up to 500 per attack type plus as many normal ones), 475 for validation.

### Model 3: Qwen2.5-7B QLoRA

A single adapter answers all three tasks in one JSON response: attack decision, tactics, and techniques. The input is a plain-English summary of the connection with no IPs, timestamps, or dataset names. Answers outside the 13 allowed tactics and 27 allowed techniques count as invalid.

- 4-bit Qwen2.5-7B-Instruct with QLoRA through Unsloth: rank 16, one epoch, learning rate 2e-4, max 1,024 tokens, loss on the answer only.
- Trained on a Colab A100 with the same 4,998 / 475 samples as Mistral.

### Model 4: Hierarchical Graph Transformer (HGT)

The next step after GraphSAGE. GraphSAGE weighs all neighbours equally. HGT uses attention to learn which neighbours and which edge features matter, which suits network graphs where some connections are far more suspicious than others.

- Two edge-aware TransformerConv layers with 4 attention heads, hidden size 32, and dropout 0.35. Edge features feed into message passing directly.
- The heads are cascaded: attack, then tactic, then technique, each conditioned on the one before.
- Training: batch size 64, up to 50 epochs with patience 10, BCE-with-logits with capped positive weights. The best checkpoint is picked by validation binary F1.

### Model 5: Laya

Laya (`convaiinnovations/laya`) isn't a text generator. It's a decision model: a ModernBERT-large encoder with a two-layer transformer head, about 421M parameters, that answers fixed yes/no questions with probabilities. Each tactic and technique becomes its own question.

- Starts from an earlier binary fine-tuned Laya checkpoint and adds the 13 tactic and 27 technique questions.
- 10,000 training rows (50% attack), 4 epochs, encoder learning rate 2.5e-5 and head learning rate 1e-4, max 512 tokens. The best checkpoint is picked by validation average precision.
- After training, temperature scaling and a separate threshold per label are tuned on a calibration slice of the validation split.

### Platforms

| Model | Environment | Main libraries |
|---|---|---|
| GraphSAGE | Google Colab GPU | PyTorch, PyTorch Geometric, scikit-learn |
| Mistral multi-LoRA | Single 16 GB CUDA GPU | Transformers, PEFT, TRL, bitsandbytes |
| Qwen QLoRA | Colab A100 | Unsloth, Transformers, PEFT, bitsandbytes |
| HGT | Google Colab GPU | PyTorch, PyTorch Geometric, scikit-learn |
| Laya | CUDA GPU (`laya/` Docker image) | Laya SDK, PyTorch, Transformers, scikit-learn |

## 5. RAG explanation layer

A label alone, such as "T1110 Brute Force", isn't something an analyst can act on. The RAG layer explains every incident with evidence and cites where each claim comes from. It doesn't change the detection scores, and it works with any of the five models.

**Knowledge base:** MITRE ATT&CK (techniques, tactics, mitigations, procedure examples), CTI-HAL threat-report passages labelled with ATT&CK techniques, and CVE records (cvelistV5 with the CTID KEV-to-ATT&CK mapping).

**For each incident:**

1. Look up the predicted technique's name, tactic, description, and mitigations.
2. Build one query from the technique name and the observed behaviour (service, protocol, port), embed it with `all-MiniLM-L6-v2`, and search ChromaDB.
3. Pull related CTI passages and ATT&CK procedure examples. If fewer than 5 hits come back, widen the search to other techniques in the same tactic. For exploit techniques (T1190, T1210, T1203, T1211, T1212, T1068), add CVE records that match the service.
4. Drop hits with cosine similarity below 0.05 and keep the top 5.
5. **Behaviour check:** describe the traffic in plain terms (port scan, host sweep, repeated logins, large outbound transfer) and match it against every ATT&CK technique with BM25. This gives a second opinion that agrees or disagrees with the model.
6. Have `openai/gpt-oss-20b` on Groq (JSON mode, temperature 0.2) write 3 to 5 cited sentences plus next steps.

If the analyst changes the technique, the explanation is regenerated for the new one.

We chose retrieval over fine-tuning an LLM to explain, because every statement stays traceable to a source and the knowledge base can be updated without retraining.

## 6. How we evaluate

Attacks are about 8% of the test edges and many labels are rare, so accuracy would look good for a model that says "normal" every time. We report:

- **Attack detection:** precision, recall, F1, PR-AUC, ROC-AUC, false-alarm rate.
- **Tactics and techniques:** micro-F1, which is driven by common labels, and macro-F1, which gives rare labels equal weight.
- **Language models:** the share of answers that parse as JSON and the share that contain a label outside the allowed lists.

### The models don't share one test set

Keep this in mind when reading section 7.

| Model | Test data | Decision rule |
|---|---|---|
| GraphSAGE, HGT | All 2,518 test windows: 69,161 edges, 5,670 attacks | Probability ≥ 0.5 |
| Mistral, Qwen | The same 7,882 connections, sampled per attack combination and weighted back to the full test split | The JSON answer; PR-AUC uses P("true") vs. P("false") |
| Laya | A separate 2,000-row sample at the real attack rate | Temperature scaling plus per-label thresholds from validation |

Tactic and technique scores for the language models and Laya are computed over labelled attack rows only.

### Extra checks

Because the main split is random, we also ran:

1. **Leave-one-dataset-out** for GraphSAGE: train on five UWF recordings, test on the sixth, six times over.
2. **Unseen-only test for Qwen:** drop test texts that also appear in training (3,630 rows remain).
3. **Zero-shot baselines** for Mistral, Qwen, and Laya before fine-tuning.
4. **Synthetic traffic:** 894 synthetic connections unlike the UWF data, for Mistral and Qwen.

The RAG layer is scored separately with Hit@5, Precision@5, MRR, and nDCG@10 on golden queries from human-labelled CTI-HAL data and on hand-written network-event queries. We also checked groundedness, citations, latency, and made-up technique IDs.

## 7. Results

### Overall

| Model | Test rows | Attack F1 | Attack PR-AUC | Tactic micro-F1 | Tactic macro-F1 | Technique micro-F1 | Technique macro-F1 |
|---|---|---|---|---|---|---|---|
| GraphSAGE | 69,161 | **0.9932** | 0.9970 | 0.8013 | 0.1484 | 0.7770 | 0.0677 |
| Mistral multi-LoRA | 7,882 weighted | 0.9558 | 0.9902 | 0.7970 | 0.4817 | 0.8187 | 0.3593 |
| Qwen QLoRA | 7,882 weighted | 0.9058 | 0.9868 | **0.9539** | **0.5445** | **0.9464** | **0.4326** |
| HGT | 69,161 | 0.9711 | 0.9943 | 0.7780 | 0.2386 | 0.7756 | 0.1141 |
| Laya | 2,000 | 0.9850 | **0.9999** | 0.6316 | 0.3028 | 0.5195 | 0.1469 |

- **Detection:** GraphSAGE is best and scores every test edge. Laya has the top PR-AUC, but on 2,000 rows, so it isn't a like-for-like comparison.
- **Tactics and techniques:** the graph models do well on micro-F1 and poorly on macro-F1. They mostly learned the common labels. Qwen, then Mistral, handle rare labels best.
- HGT beats GraphSAGE on macro-F1 (tactics 0.239 vs. 0.148, techniques 0.114 vs. 0.068). The two also used different loss weights, though, so we can't credit attention alone.

### Attack detection detail

| Model | Precision | Recall | ROC-AUC | False-alarm rate |
|---|---|---|---|---|
| GraphSAGE | 0.9952 | 0.9912 | 0.9991 | ~0.04% |
| Mistral | 0.9176 | 0.9974 | 0.9994 | 0.8% |
| Qwen | 0.8290 | 0.9980 | – | 1.8% |
| HGT | 0.9925 | 0.9506 | 0.9994 | ~0.06% |

GraphSAGE catches 99.1% of attacks with 27 false alarms out of 63,491 normal edges. The language models catch almost everything but raise more false alarms, which adds up quickly for an analyst. That's why GraphSAGE runs live.

### Fine-tuning matters

| Model | Zero-shot PR-AUC | Fine-tuned PR-AUC |
|---|---|---|
| Mistral | 0.069 | 0.990 |
| Qwen | 0.058 | 0.987 |
| Laya (binary pilot, 2,000 rows) | 0.319 | 0.997 |

Out of the box, none of these models can do the task. One epoch of fine-tuning takes Mistral and Qwen above 0.98.

### Losses

| Model | Training loss | Validation loss | Test loss |
|---|---|---|---|
| GraphSAGE | – | 0.0177 | 0.0144 |
| HGT | – | 0.0508 | 0.0465 |
| Qwen | 0.22 → 0.015 | 0.0170 | – |
| Mistral (attack / tactic / technique adapters) | 0.039 / 0.064 / 0.075 | – | – |

### Results are optimistic

- **Leakage:** 53.9% of Qwen's test texts also appear in training. On the 3,630 unseen texts its PR-AUC holds at 0.982, but precision drops from 0.83 to 0.60.
- **Synthetic traffic:** Mistral and Qwen fall to a PR-AUC of about 0.16 and flag large amounts of normal traffic.
- **Unseen recordings:** GraphSAGE drops when a whole recording is held out (see `notebooks/blocked_cv/README.md`).

Treat the main-split numbers as an upper bound on how these models would do in a real deployment.

### RAG layer

| Check | Result |
|---|---|
| Retrieval, technique queries (Hit@5 / P@5 / MRR / nDCG@10) | 0.653 / 0.318 / 0.522 / 0.294 |
| Retrieval, network-event queries (Hit@5 / P@5 / MRR / nDCG@10) | 0.500 / 0.400 / 0.403 / 0.381 |
| Behaviour check, leave-one-family-out Hit@5 | 0.23 to 0.81, depending on the attack family |
| Evidence per incident (1,959 incidents) | 6 items: 1 MITRE entry, about 4.4 procedures, 0.6 CTI passages |

CTI evidence was found for only 29% of incidents because CTI coverage is uneven across techniques. The behaviour check is most useful for scans and sweeps, where it agrees with the model on 76% of incidents, and weakest for brute force over HTTP.

## 8. Threat console

The console replays recorded Zeek traffic window by window, runs the live detector, groups flagged edges into incidents, and explains each one. Training, knowledge preparation, and evaluation all happen offline. The app loads their outputs at start-up.

**Who uses it**

- **SOC analyst:** watches traffic, triages incidents, reads explanations, and responds (confirm, dismiss, investigate, contain, close).
- **Researcher:** compares the five models on an incident and reviews evaluation results.
- **Operator:** sets data and model paths, the API key, the LLM provider, and IP redaction.

**What it does**

- Live detection with GraphSAGE or HGT, switchable at runtime. Play, pause, step, or jump through the replay at 1 to 4 windows per second.
- An incident queue with filters, a status workflow, notes, applied mitigations, and CSV export.
- An incident page with the cited explanation, evidence and retrieval trace, behaviour check, GNNExplainer view of the top edge, the window graph, and a Research tab showing all five models' predictions.
- An Evaluation page with comparison tables and RAG ablations, and a Knowledge base page listing every ATT&CK technique with its evidence.

**How it's built**

- React 19 and Vite frontend.
- FastAPI backend. It reads `test_edges.parquet`, the model checkpoints, the knowledge files, `chroma_db/`, `model_outputs.jsonl` (154,086 per-edge predictions), and `metrics.json`.
- Groq provides the LLM.
- Incidents and cached explanations live in memory.
- The API contract is in `docs/api/openapi.yaml`. It covers `POST /detect`, `GET /incidents`, `GET /incidents/{id}`, `GET /incidents/{id}/graph`, `GET /incidents/{id}/model-explanation`, `PATCH /incidents/{id}`, `GET /models`, `POST /models/active`, `GET /metrics`, and `GET /knowledge-base`.

**Security:** every request needs a shared API key in `X-API-Key`. IPs can be redacted before anything goes to the LLM. Without an LLM, the app still works in evidence-only mode.

**Testing:** 15 Playwright end-to-end tests cover the analyst and researcher use cases, plus error handling for a backend that's down or a wrong API key. All pass.

**Status:** everything above is implemented except the Laya results in the model comparison (pending) and the AWS deployment (planned: Amplify, API Gateway, EC2 with Docker, Chroma on EBS, S3, DynamoDB, CloudWatch).

## 9. Limitations

- **Optimistic split.** The random window split lets the same campaign appear in training and test. Unseen recordings and synthetic traffic score much lower.
- **Different test sets.** Graph models, the two LLMs, and Laya were scored on different data, so cross-family comparisons are approximate.
- **Rare labels.** Technique labels are sparse and skewed, so macro-F1 stays low, especially for the graph models.
- **Laya** has only a 2,000-row run so far.
- **Calibration.** Most models' probabilities aren't calibrated. Laya is the exception.
- **RAG follows the prediction.** If the predicted technique is wrong, the evidence is well cited but for the wrong technique. The behaviour check helps flag this but can't fix it.

## 10. Reproducing the results

1. **Shared split:** run `laya/graphSAGE-data-prep.ipynb` to produce `processed_edges/` (train, validation, test) and `preprocessing_objects.joblib`.
2. **Mistral:** run `mistral_multi_lora/mistral-adapt-finetune.ipynb` on a 16 GB+ CUDA GPU.
3. **Qwen:** run `notebooks/fine_tuned_llm/UWF_LLM_Finetune.ipynb` in Colab. See that folder's README for the `SPLIT_DIR` setting.
4. **Laya:** from `laya/`, run `docker compose up` (needs an NVIDIA GPU) and open `Laya_baseline_and_finetuning_new.ipynb` at `http://localhost:8888`. Set `JUPYTER_TOKEN` in `laya/.env` first.
5. **GNN robustness checks:** run `notebooks/blocked_cv/UWF_GNN_Blocked_CV.ipynb`.
6. **RAG knowledge base:** run `notebooks/RAG/rag.ipynb`.
7. **Zero-shot and few-shot LLM baselines:** copy `.env.example` to `.env`, set `LLM_API_KEY`, and run `intelligence/baseline_llm.py`. Tests are in `intelligence/test_baseline_llm.py`.
8. **Ingestion pipeline:** in `pipeline/`, set the S3 and ClickHouse values in `.env` and run `docker compose up`.
