# Cyber Threat Detection

This project detects malicious network activity in Zeek connection logs and maps each detection to MITRE ATT&CK. A graph neural network (GraphSAGE) flags suspicious host-to-host connections. A retrieval-augmented LLM layer then explains each alert with ATT&CK context.

This README reports four deliverables: data pre-processing, training and test data preparation, data analytics, and ongoing machine learning results.

## Contents

1. [Problem and approach](#1-problem-and-approach)
2. [Repository layout](#2-repository-layout)
3. [Data pre-processing](#3-data-pre-processing)
4. [Training and test data preparation](#4-training-and-test-data-preparation)
5. [Data analytics](#5-data-analytics)
6. [Ongoing machine learning results](#6-ongoing-machine-learning-results)
7. [Limitations and next steps](#7-limitations-and-next-steps)
8. [Reproducing the results](#8-reproducing-the-results)

## 1. Problem and approach

**Problem.** Security analysts face millions of connection logs and a very small fraction of attacks. The system must find those attacks with few false alarms, then tell the analyst what kind of attack it is.

**Approach.**

| Stage | Task | Method |
|---|---|---|
| 1 | Binary detection: attack or normal, per (source IP, destination IP, time window) edge | Edge-level GraphSAGE |
| 2 | Technique and tactic classification (MITRE ATT&CK) | GraphSAGE multi-label heads |
| 3 | Explanation and grounding | RAG over ATT&CK STIX data plus an LLM |
| Baseline | Compare against LLMs with no training | Zero-shot and few-shot Gemma 4, Qwen, GPT-OSS |

**Data.** The project uses the public [UWF Zeek datasets](https://datasets.uwf.edu/data/): six captures, 50 Parquet files, about 1.2 GB, 27.1 million connection logs, spanning December 2021 to July 2025.

## 2. Repository layout

| Path | Contents |
|---|---|
| `notebooks/eda_data_prep/` | Data gathering, EDA, and windowed graph preprocessing |
| `notebooks/gnn_rag/` | GNN training (1), few-shot training (2), MITRE technique (3) and tactic (4) classification, combined inference (5) |
| `notebooks/RAG/` | Retrieval pipeline prototype |
| `intelligence/` | Baseline LLM evaluation harness (`baseline_llm.py`) and tests |
| `evaluation/model_b/` | LLM baseline outputs, metrics, and the GNN-versus-LLM comparison |
| `pipeline/` | Airflow DAG that ingests Parquet from S3 into ClickHouse |
| `demo/2026-10-06_meeting/app/` | Streamlit demo with trained models, test graphs, and RAG data |
| `backend/`, `frontend/`, `infra/` | Application scaffolding |

## 3. Data pre-processing

The pre-processing notebook is `notebooks/eda_data_prep/3_UWF_Windowed_Graph_Preprocessing.ipynb`.

### Steps

1. **Ingest.** The notebook loads all 50 Parquet files into DuckDB. Column sets differ by year (22 to 27 columns, mixed `int32`/`int64`), so it casts each file to one target schema and fills missing columns with NULL.
2. **Clean.** The notebook drops rows labelled `Duplicate` (33,053 rows) and drops `label_cve`. It also fills nulls (`history` → `-`, `service` → `unknown`, numeric fields → 0) and normalises `vlan`.
3. **Label.** A log is an attack when `label_tactic` is not `none` or NULL. Attack logs without a known technique become `<Tactic>_unspecified`.
4. **Encode.** The notebook maps each IP to an integer node ID, sorted by IP string, and applies `ln(1+x)` scaling to durations, bytes, and packets. It one-hot encodes protocol (TCP, UDP, ICMP) and the top five services.
5. **Aggregate into windows.** An edge becomes a (source IP, destination IP, time window) tuple. Windows are built per dataset, so concurrent captures are never merged.
6. **Engineer features.** Each edge gains `conn_state` fractions, TCP-flag counts from `history`, destination-port group fractions, distinct-port counts, and duration and rate. Each node gains per-window degree, volume, failed-connection ratio, PageRank, and clustering. There is no IP-identity one-hot, so the model cannot memorise addresses.

### Results

| Check | Result |
|---|---|
| Raw logs ingested | 27,111,594 |
| Logs after cleaning | 27,078,541 |
| Unique IPs (nodes) | 1,176 (1,082 internal, 64 IPv6, 56 special) |
| Parity with the earlier whole-graph aggregation | Pass: 2,183 edges (1,235 attack, 948 normal), identical to Phase A |

**Why windows.** The earlier whole-graph design collapsed 27 million logs into 2,183 edges, too few to learn from. Windowing produced these sample counts:

| Window | Edges (samples) | Attack edges | Attack share | Median edges per window |
|---|---|---|---|---|
| 5 min | 726,307 | 54,650 | 7.5% | 16 |
| 15 min | 438,683 | 51,709 | 11.8% | 36 |
| 60 min | 224,097 | 43,485 | 19.4% | 74 |

No window size produced an edge that mixes attack and normal logs (0.00%), so edge labels are unambiguous. The preprocessing notebook uses 15-minute windows. The GNN training pipeline uses the 5-minute variant (`*_edges_5min_enriched.parquet`).

## 4. Training and test data preparation

### Split strategy

The split is chronological, never random, so a model cannot see the future during training. Each split comes from a different period:

| Split | Period | Edges | Normal | Attack | Attack share |
|---|---|---|---|---|---|
| Train | Dec 2021 – Oct 2022 | 150,914 | 150,135 | 779 | 0.52% |
| Validation | Feb – Dec 2024 | 295,052 | 242,139 | 52,913 | 17.9% |
| Test | May – Jul 2025 | 232,088 | 231,130 | 958 | 0.41% |

Other preparation choices:

- **Leakage control.** The windowed pipeline purges a gap of windows before each split boundary, so an attack that straddles the boundary cannot leak across splits. The scaler uses train-split statistics only.
- **Context graphs.** For each 5-minute prediction interval, the pipeline builds a graph from the preceding 60 minutes of traffic. The model predicts labels for the target edges only. This yields 9,300 training, 10,560 validation, and 5,326 test graphs (about 55 nodes per graph on average).
- **Edge features (10).** Log connection count, durations, bytes, and packets, plus TCP, UDP, and ICMP ratios. The pipeline fits the scaler on training data only.
- **Class imbalance.** The binary model uses a positive-class weight of 13.88.
- **Label sparsity.** Nested masks keep 100%, 15%, 10%, 5%, or 1% of attack labels, stratified by technique. Normal edges stay labelled, and unlabelled attacks are masked out of the loss rather than treated as normal. Validation and test splits are always fully labelled.
- **Few-shot sets.** The 1%, 5%, and 10% sets contain 8, 39, and 78 attack edges, each trained with three seeds (42, 43, 44).

## 5. Data analytics

### Attack composition

Dominant techniques across the 51,709 attack edges (15-minute windows) are T1595 Active Scanning (36,761), T1110 Brute Force (5,186), T1078 Valid Accounts (4,239), T1190 Exploit Public-Facing Application (3,696), and T1046 Network Service Discovery (542). The dataset covers 33 distinct techniques.

### Distribution shift across captures

Attack share varies sharply by capture, which drives most of the evaluation difficulty:

| Capture | Edges | Attack edges | Attack share |
|---|---|---|---|
| UWF-ZeekData24 | 80,481 | 49,639 | 61.7% |
| UWF-ZeekDataFall24-2 | 100,788 | 851 | 0.8% |
| UWF-ZeekDataFall22 | 19,058 | 322 | 1.7% |
| UWF-ZeekData22 | 95,863 | 309 | 0.3% |
| UWF-ZeekDataSum25-1 | 96,586 | 315 | 0.3% |
| UWF-ZeekDataSum25-2 | 45,907 | 273 | 0.6% |

At the log level every capture is about 50% attack, so the imbalance appears only after aggregation into edges.

### Findings that shaped the models

- **Duplicated attack patterns.** In the chronological split, 96.2% of test attack edges have a near-identical training twin (distance below 0.05). A within-period split therefore scores almost perfectly (PR-AUC 0.9997) and overstates real-world performance.
- **Volume shortcut check.** Removing volume-proxy features (`edge_weight`, rates, protocol totals) barely changed the smoke-test score, which suggests the model learns behaviour, not just traffic volume.
- **Cross-capture generalisation is uneven.** Leave-one-capture-out tests ranged from strong (Sum25-2 PR-AUC 0.9985) to poor (Fall24-2 PR-AUC 0.0774). Features such as `m_h_len`, `m_h_data`, and `avg_log_resp_pkts` differ widely between captures.
- **Temporal drift.** Adding more historical attacks did not improve 2024 validation performance. Some 2022 attack patterns differ from the dominant 2024 patterns.

## 6. Ongoing machine learning results

All results below use the fully labelled 2025 test split (232,088 edges, 958 attacks, 0.41% prevalence) unless stated otherwise.

### Binary detection (GraphSAGE)

The threshold of 0.861 is tuned on the validation split.

| Model | Attack labels | PR-AUC | ROC-AUC | Precision | Recall | F1 | False-positive rate |
|---|---|---|---|---|---|---|---|
| Full-data GraphSAGE | 779 | 0.739 | 0.992 | 0.566 | 0.871 | 0.686 | 0.28% |
| 1% few-shot GraphSAGE | 8 | 0.622 | 0.959 | 0.297 | 0.758 | 0.427 | 0.74% |

The full model finds 834 of 958 attacks at the cost of 640 false alarms, which is 1.8 alerts per real attack.

The few-shot results vary strongly by seed: validation PR-AUC for 1% ranged from 0.39 to 0.88 across seeds. The 100% control was the most stable (std 0.055). The 1% model used about 99% fewer labels at the price of lower precision.

### GNN versus zero-shot LLM baseline

Gemma 4 31B (zero-shot) ran on a balanced sample of 200 attack and 200 normal edges. Precision and F1 are projected to the test prevalence.

| Metric | GraphSAGE | Gemma 4 31B zero-shot |
|---|---|---|
| Recall | 0.871 | 0.670 |
| False-positive rate | 0.0028 | 0.360 |
| Precision | 0.566 | 0.008 |
| F1 | 0.686 | 0.015 |
| Alerts per real attack | 1.8 | about 131 |

The GNN raises about 130 times fewer false alarms. Among the zero-shot LLMs tried, Gemma 4 performed best. Qwen 3.8 27B reached a recall of only 0.045. The full write-up, with confidence intervals and caveats, is in `evaluation/model_b/comparison_gnn_vs_gemma4.md`. The few-shot Gemma analysis is in `evaluation/model_b/few_shot_gemma4_analysis.md`.

### MITRE classification

These models are early and underperform the binary detector:

| Task | Test metric | Value |
|---|---|---|
| Technique (multi-label, threshold 0.70) | Micro-F1 | 0.021 |
| Technique | Micro-PR-AUC | 0.068 |
| Tactic | Accuracy | 0.636 |
| Tactic | Macro-F1 | 0.112 |
| Technique via Gemma 4 zero-shot | Accuracy on 134 detected attacks | 0.216 |

Technique labels are heavily skewed toward T1595 and T1046, which limits macro-level scores.

## 7. Limitations and next steps

- **Distribution shift.** Validation (17.9% attack) and test (0.41% attack) differ sharply from training (0.52%). Validation PR-AUC (0.566) is lower than test PR-AUC (0.739), so threshold tuning on validation may not transfer cleanly.
- **Early stopping.** `demo/2026-10-06_meeting/app/data/models/binary_graphsage_v2.json` records `best_epoch: 1`. We will check whether the model is under-trained.
- **MITRE classification.** Technique and tactic models need class rebalancing and better features before they support the RAG explanation layer.
- **LLM baselines.** Each LLM ran once with one prompt, and the sample covers 400 edges. Prompt variations and few-shot examples may change the ranking.

## 8. Reproducing the results

**Notebooks.** Run the notebooks in this order. They expect Google Colab with a GPU (we used an NVIDIA L4) and a mounted Google Drive.

1. `notebooks/eda_data_prep/` (data gathering, EDA, windowed preprocessing)
2. `notebooks/gnn_rag/1_Threat_Detection_GNN_training.ipynb`
3. `notebooks/gnn_rag/2_Threat_Detection_Few_shot.ipynb`
4. `notebooks/gnn_rag/3_Threat_Detection_MITRE_Classification_v2.ipynb` and `notebooks/gnn_rag/4_Threat_Detection_Tactic_Classification.ipynb`
5. `notebooks/gnn_rag/5_Combined_Model_Inference_v2.ipynb`

**LLM baseline.** Copy `.env.example` to `.env` and set `LLM_API_KEY`. Then run `intelligence/baseline_llm.py`. Tests live in `intelligence/test_baseline_llm.py`.

**Ingestion pipeline.** The `pipeline/` directory targets Python 3.11 or later and uses `uv`. Configure `pipeline/.env` with the S3 and ClickHouse settings, then start the stack with `docker compose up` from `pipeline/`.

**Demo.** From `demo/2026-10-06_meeting/app/`, install `requirements.txt`, then run `streamlit run streamlit_app.py`. See that folder's README for secrets setup.
