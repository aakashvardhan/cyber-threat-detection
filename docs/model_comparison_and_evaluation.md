# 4.3 Model Comparison and Justification, and 4.4 Model Evaluation Method

Project: cyber-threat detection on UWF network logs, comparing a graph neural network (GNN) with LLM-based detectors.
This document covers the models that have results in this repository: a **GraphSAGE GNN** and **baseline LLMs** (zero-shot and few-shot). Other planned models are listed in 4.3.2 but are not evaluated here.

All figures come from `gnn_edge_data/` (GNN) and `evaluation/model_b/` (LLMs). Items marked **TODO** need information that is not in those files.

---

## 4.3 Model Comparison and Justification

### 4.3.1 Targeted problem and data

**Problem.** Edge-level attack detection: given one (source IP, destination IP, 5-minute window) record built from Zeek connection logs, decide whether it is part of an attack. LLMs are also asked for the MITRE ATT&CK technique ID.

**Data.** 150,914 train, 295,052 validation and 232,088 test edges (UWF). The splits are chronological and differ sharply in attack rate and attack mix, which shapes every evaluation choice below:

| Split | Period | Edges | Attack rate | Dominant attack techniques |
|---|---|---|---|---|
| Train | Dec 2021 – Oct 2022 | 150,914 | 0.52% (779 attacks) | T1590 37%, T1589 6%, T1595 3.5%; 44% have no technique |
| Validation | Feb – Dec 2024 | 295,052 | 17.9% (52,913 attacks) | T1595 69%, T1078 10%, T1110 9%, T1190 9% |
| Test | May – Jul 2025 | 232,088 | **0.41%** (958 attacks) | T1595 69%, T1046 28% |

Consequences: the test split is extremely imbalanced, so accuracy is meaningless (predicting "normal" for everything scores 99.6%), and a decision threshold tuned on the validation split (17.9% attacks) does not transfer automatically to the test split (0.41%).

### 4.3.2 Models in the project

| Model | Project folder | Status in this document |
|---|---|---|
| GraphSAGE edge classifier (binary) | `gnn_edge_data/models/` | Evaluated (full-data and few-label variants) |
| Baseline LLM, zero-shot | `notebooks/baseline_llm`, `intelligence/baseline_llm.py` | Evaluated (4 LLMs) |
| Baseline LLM, few-shot | same | Evaluated (Gemma 4 31B, 3 example draws) |
| Fine-tuned LLM | `notebooks/fine_tuned_llm` | Planned, no results here (**TODO**) |
| GNN + RAG | `notebooks/gnn_rag` | Planned, no results here (**TODO**) |
| GNN + RAG + fine-tuned LLM | `notebooks/gnn_rag_finetuned_llm` | Planned, no results here (**TODO**) |
| GNN + RAG + verdict stage | `notebooks/gnn_rag_jev_verdict` | Planned, no results here (**TODO**) |
| Previous-semester GAT | `notebooks/previous_semester_gat` | Reference model, no results here (**TODO**) |
| Statistical / classical ML baseline | none | **Not implemented**; see gaps in 4.3.6 |

### 4.3.3 Comparison of the evaluated models

| | **GraphSAGE GNN** | **Baseline LLM, zero-shot** | **Baseline LLM, few-shot** |
|---|---|---|---|
| Approach family | Deep learning (graph neural network), supervised | Deep learning (pretrained transformer), prompting only, no training | Same, with labelled examples in the prompt (in-context learning) |
| Targeted problem | Binary attack vs normal per edge | Attack vs normal per edge, plus MITRE technique ID | Same as zero-shot |
| Input features | Node features (6-dim; names not stored in the artifacts I read, **TODO**) and 10 edge features: log connection count, log total / maximum duration, log bytes and packets in each direction, TCP / UDP / ICMP ratios; scaled with a fitted scaler | A text summary of one edge: window time, source and destination IP (optional), connection count, bytes and packets each way, total and maximum duration, protocol mix. Built by the shared `edge_serializer.py` | Same text, preceded by 8 labelled example edges (4 attack, 4 normal) |
| Uses graph context? | **Yes**: two message-passing layers aggregate each host's neighbourhood | No: each edge is judged in isolation | No |
| Architecture | 2 × SAGEConv (hidden size 64), then an edge classifier on [source embedding ‖ destination embedding ‖ 10 edge features] (138 → 64 → 1) | Pretrained LLM, temperature 0, JSON answer | Same |
| Training / label need | 779 train attack labels; class-weighted loss (positive weight 13.9 recorded); also tested with 1%, 5% and 10% of labels | None | 8 examples per prompt (no weight updates) |
| Output | Probability per edge (threshold 0.861 chosen on validation) | Hard label + technique (no probability) | Same |
| Cost / speed | Scores all 232,088 test edges in one pass | About 20 s per edge for Gemma 4 31B (long reasoning), so 400 edges ≈ 2.5 h | Slightly slower (longer prompt) |
| **Strengths** | Highest accuracy; very low false-alarm rate; uses host-neighbourhood context; scalable; produces a score so the operating point can be tuned; keeps 84% of PR-AUC with 99% fewer attack labels | No labelled data or training; gives a MITRE technique and a natural-language rationale; easy to swap models; useful lower bound for LLM pipelines | Can adapt to the task without training; one draw (seed 1) beat zero-shot on both recall and false alarms |
| **Limitations** | Needs labelled attacks; threshold depends on class balance (validation 17.9% vs test 0.41%); no technique output; training history and loss curves not saved (**TODO**) | Near-chance detection for most models; many false alarms; cannot see network context; hard labels give no ROC; slow and costly per edge; some models break the JSON format | Result depends heavily on which examples are shown (recall 0.545 to 0.885 across three draws); same blindness to context; longer, costlier prompts |

### 4.3.4 Justification for each model

**GraphSAGE.** Network traffic is naturally a graph of hosts, and attacks (scans, lateral movement) show up as patterns across a host's neighbours, not in a single connection. GraphSAGE is inductive (it learns to aggregate neighbours, not a fixed embedding per node), so it handles hosts not seen in training, which matters because the splits are 5 to 16 months apart and their host populations may differ (75, 122 and 73 distinct source hosts). It is also cheap enough to score hundreds of thousands of edges. The class-weighted loss addresses the 0.5% attack rate. I did not benchmark it against other GNNs in this repository, so the choice is a reasoned design decision, not a measured winner. The few-label variants test how it behaves when labels are scarce.

**Baseline LLM (zero-shot).** It is the reference point for all LLM-based models in the project (fine-tuned, GNN + RAG): any later LLM pipeline has to beat it to justify its cost. It needs no labels, produces MITRE technique IDs the GNN cannot, and its prompt is shared across models through `edge_serializer.py`, so differences come from the model and not the wording. Four LLMs were tried to see whether size or family matters: local `qwen3:8b` (cheap, open weights), `qwen3.8-27b` and `gpt-oss-20b` (free on Groq; `gpt-oss-20b` is small enough for the planned AWS deployment), and `gemma-4-31b-it` (best zero-shot result).

**Baseline LLM (few-shot).** Tests whether a handful of labelled edges lifts a general model without training. Examples are drawn from the validation split in proportion to its technique mix, so they match what the model will meet at test time. An earlier version, which took the top techniques from the train split, was unfair, because the train and test attack mixes differ (T1590 37% versus T1595 69%). The report `evaluation/model_b/few_shot_gemma4_analysis.md` documents the fix.

### 4.3.5 Head-to-head results

Test split. LLM rows use a balanced sample of 400 edges (200 attack, 200 normal), except partial runs. Precision is projected to the real 0.41% attack rate. "Alerts per attack" is how many alerts an analyst would triage to find one real attack.

| Model | Setting | Recall (95% CI) | False-positive rate (95% CI) | Precision at 0.41% | Alerts per attack |
|---|---|---|---|---|---|
| **GraphSAGE** | Full data, all 232,088 test edges | **0.871** | **0.0028** | **0.566** | **1.8** |
| GraphSAGE | 1% of attack labels (8 attacks) | 0.758 | 0.0074 | 0.297 | 3.4 |
| Gemma 4 31B | Zero-shot | 0.670 (0.60–0.73) | 0.360 (0.30–0.43) | 0.0077 | 130 |
| Gemma 4 31B | Few-shot, best of 3 draws (seed 1) | 0.885 (0.83–0.92) | 0.215 (0.16–0.28) | 0.0168 | 60 |
| Gemma 4 31B | Few-shot, mean ± sd of 3 draws | 0.668 ± 0.188 | 0.382 ± 0.160 | 0.004–0.017 | 60–240 |
| `qwen3.8-27b` (Groq) | Zero-shot | 0.045 (0.02–0.08) | 0.040 (0.02–0.08) | 0.0046 | 217 |
| `gpt-oss-20b` (Groq) | Zero-shot, partial: 285 of 400 edges | 0.329 (0.24–0.43) | 0.315 (0.25–0.38) | about 0.004 | about 230 |
| `qwen3:8b` (local) | Zero-shot, partial: 276 of 400 edges | 0.803 (0.70–0.88) | 0.550 (0.48–0.62) | about 0.006 | about 170 |

Reading the table: the GNN is better than every LLM by about two orders of magnitude on false alarms. Among LLMs, only Gemma 4 shows real signal (recall above false-positive rate). The best few-shot draw should not be quoted alone because it was identified using test results (see 4.4.4).

### 4.3.6 Gaps relative to this rubric

- **No statistical or classical machine-learning model** is in the repository. Literature on LLM intrusion detection reports classical models (random forest, LSTM) as strong baselines on flow data. A logistic regression or random forest on the same 10 edge features would complete the statistics / machine learning / deep learning comparison. I did not build one.
- **Planned models** (fine-tuned LLM, GNN + RAG variants, GAT) have no results here.
- **GNN node-feature names and training loss curves** are not stored in the artifacts I read.

---

## 4.4 Model Evaluation Method

### 4.4.1 Metrics used and why

| Metric | Definition | Why it is used |
|---|---|---|
| Recall (true-positive rate) | TP / (TP + FN) | Missed attacks are the costly error in this domain, so it is the priority metric |
| False-positive rate | FP / (FP + TN) | Measures analyst workload from false alarms |
| Precision | TP / (TP + FP) | Fraction of alerts that are real. For LLMs on a balanced sample it is **re-weighted to the real prevalence** π: precision = recall·π / (recall·π + FPR·(1 − π)), π = 0.0041 |
| F1 | 2·P·R / (P + R) | Single-number summary of precision and recall |
| PR-AUC | Area under the precision–recall curve | Primary threshold-free metric for the GNN, because positives are only 0.41% |
| ROC-AUC | Area under the ROC curve | Threshold-free ranking quality; reported for the GNN only (LLMs return hard labels, so a ROC curve is not defined) |
| Confusion matrix | TP, FP, FN, TN | Full error breakdown (GNN: 834 / 640 / 124 / 230,490) |
| MITRE technique accuracy | Share of detected attacks whose predicted technique's parent ID (T1595.001 → T1595) matches a true technique | Only LLMs predict techniques |
| Unusable replies | Replies that are not valid JSON or have no label | Format reliability. Counted as "attack" (see 4.4.3) |
| Loss | GNN: class-weighted loss (positive weight 13.9 is recorded; the exact loss function is not stored, **TODO**) | Used for training; loss curves are not stored (**TODO**). Not applicable to LLMs (no training) |
| Accuracy | (TP + TN) / total | **Deliberately not used**: at 0.41% prevalence it is dominated by the normal class |

### 4.4.2 GraphSAGE evaluation method

1. **Chronological split**: train (2021–22), validation (2024), test (2025). No test data is used for training or tuning.
2. **Class imbalance**: positive-class weight of 13.9 in the loss.
3. **Model selection and threshold**: the results file records a validation PR-AUC (0.566), a validation-tuned threshold (0.861) and a best epoch (1), so I take the epoch and threshold to have been chosen on the validation split (the training code is not in this repository, **TODO** confirm); the test split is scored once.
4. **Reported test metrics**: PR-AUC 0.739, ROC-AUC 0.992, precision 0.566, recall 0.871, F1 0.686, false-positive rate 0.0028 on all 232,088 edges.
5. **Label-scarcity study**: 1%, 5%, 10% and 100% of train attack labels (8, 39, 78, 779 attacks), three seeds each, validation results as mean ± sd, then one test comparison.

| Attack labels | Validation PR-AUC (mean) | Validation recall (mean) | Validation F1 (mean ± sd) |
|---|---|---|---|
| 1% (8) | 0.694 | 0.841 | 0.745 ± 0.126 |
| 5% (39) | 0.624 | 0.659 | 0.669 ± 0.078 |
| 10% (78) | 0.609 | 0.703 | 0.657 ± 0.087 |
| 100% (779) | 0.585 | 0.528 | 0.597 ± 0.034 |

On the test split the 1% model keeps 84% of the full model's PR-AUC and 87% of its recall, at the cost of 1,075 more false positives and 108 more missed attacks.

Notes: validation metrics are not directly comparable with test metrics because the validation split has 17.9% attacks and the test split 0.41% (the full model's validation PR-AUC is 0.566, its test PR-AUC 0.739). The 1% model's validation score is also noisy (seed 42: PR-AUC 0.875; seed 43: 0.394).

### 4.4.3 LLM evaluation method

1. **Same edges for every model**: a fixed sample of 200 attack and 200 normal test edges (seed 42), because a call costs about 20 s per edge and the full test split has 232,088 edges. The 400-edge sample is 21% of the attacks and 0.09% of the normal edges.
2. **Deterministic decoding**: temperature 0, JSON-only answer, one shared prompt (`edge_serializer.py`).
3. **Prevalence correction**: precision and F1 are projected to the real 0.41% rate (formula in 4.4.1), since the sample is 50% attacks.
4. **Uncertainty**: 95% Wilson confidence intervals on recall and false-positive rate (200 edges per class).
5. **Unparseable replies count as "attack"**, a label-independent rule chosen because a missed attack costs more than a false alarm. The count is always reported (it was 0 for Gemma and `qwen3.8-27b`, 8 of 285 for `gpt-oss-20b`, 33 of 276 for `qwen3:8b`). Reasoning blocks (`<thought>…</thought>`) are removed before parsing; raw replies are saved.
6. **Technique accuracy** on parent technique IDs, over the attacks the model flagged.

### 4.4.4 Controls for fair few-shot evaluation

- **No test leakage**: examples come from the validation split, never from the evaluated test edges.
- **Matched example mix**: attack techniques are sampled in proportion to the validation technique mix (earlier the train mix was used, which misrepresented test).
- **Independent seeds**: `--shot-seed` (the example draw) is separate from `--seed` (the evaluated edges), so all runs score identical edges.
- **Several draws, not one**: three draws; report mean ± sd (recall 0.668 ± 0.188; false-positive rate 0.382 ± 0.160). A single draw ranged from chance (0.545 / 0.535) to strong (0.885 / 0.215).
- **Paired significance test** against zero-shot on the same edges (McNemar): seed 1 is better on both recall and false alarms (p < 0.001); seed 0 is worse on both; seed 2 is worse on recall and unchanged on false alarms (p = 0.53).
- **Do not select the best draw by its test score**; that would overstate few-shot. The proper route is to choose examples on a validation sample, then run the test once.

### 4.4.5 Evaluation summary per model

| Model | Method | Metrics reported | Threshold-free metric |
|---|---|---|---|
| GraphSAGE (full) | Chronological split, validation-tuned threshold, full test split | PR-AUC, ROC-AUC, precision, recall, F1, false-positive rate, confusion matrix | PR-AUC 0.739, ROC-AUC 0.992 |
| GraphSAGE (few-label) | 1 / 5 / 10 / 100% of labels × 3 seeds, validation mean ± sd, one test comparison | PR-AUC, precision, recall, F1, retention percentages | PR-AUC |
| LLM zero-shot (4 models) | 400-edge balanced test sample, temperature 0, shared prompt | Recall, false-positive rate, prevalence-adjusted precision and F1, technique accuracy, unusable count, Wilson CIs | None (hard labels) |
| LLM few-shot (Gemma 4) | As above + validation-drawn examples, 3 draws, paired McNemar test | Same, plus mean ± sd across draws and p-values vs zero-shot | None (hard labels) |

### 4.4.6 Limitations of the evaluation

- LLM and GNN numbers are measured on different test populations (400-edge sample versus all edges); LLM precision and F1 are projections that assume the sample is representative.
- Each LLM was run once per setting (three draws only for few-shot Gemma), with one prompt, IPs visible, and k = 4. Reruns at temperature 0 on hosted APIs may not be identical; this was not measured.
- Two LLM rows (`gpt-oss-20b`, `qwen3:8b`) are partial runs with fewer attack edges, so their intervals are wide.
- Loss curves, GNN node-feature names and any classical-ML baseline are missing (see 4.3.6).

## Where the data lives

- GNN: `gnn_edge_data/binary_graphsage_v2.json`, `gnn_edge_data/models/fewshot_*.csv`
- LLMs: `evaluation/model_b/` (`.jsonl` predictions, `.metrics.csv`, `.shots.json`)
- Related reports: `evaluation/model_b/comparison_gnn_vs_gemma4.md`, `evaluation/model_b/few_shot_gemma4_analysis.md`
