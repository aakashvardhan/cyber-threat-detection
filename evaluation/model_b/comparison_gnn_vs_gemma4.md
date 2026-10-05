# GNN vs. Gemma 4 (zero-shot): comparison

Task: classify a 5-minute (src IP, dst IP) UWF edge as attack or normal.

| | GraphSAGE (`binary_graphsage_v2`) | Gemma 4 31B, zero-shot (`gemma-4-31b-it`) |
|---|---|---|
| Evaluated on | full test split: 232,088 edges, 958 attacks (0.41%) | random balanced sample: 200 attack + 200 normal |
| Operating point | threshold 0.861, tuned on validation | single label from the model, no threshold |
| Training | supervised, 779 attack labels | none (prompt only) |

## Headline result

| Metric (full test prevalence, 0.41%) | GraphSAGE | Gemma 4 31B | Gemma 95% CI |
|---|---|---|---|
| Recall | **0.871** | 0.670 | 0.60 – 0.73 |
| False-positive rate | **0.0028** | 0.360 | 0.30 – 0.43 |
| Precision | **0.566** | 0.008 | 0.006 – 0.010 |
| F1 | **0.686** | 0.015 | 0.011 – 0.020 |
| ROC-AUC | **0.992** | n/a (hard label only) | |
| MITRE technique accuracy | n/a (binary model) | 0.216 (29 of 134 hits) | |

The GNN catches more attacks and raises about 130x fewer false alarms.

## What that means at deployment scale

Applied to the whole test split (958 attacks, 231,130 normal edges):

| | True attacks caught | False alarms | Alerts per real attack |
|---|---|---|---|
| GraphSAGE | 834 | 640 | 1.8 |
| Gemma 4 31B (expected) | about 640 | about 83,000 | about 131 |

An analyst would have to triage roughly 130 alerts to find one real attack with Gemma, versus fewer than two with the GNN. This is the decisive difference, and it holds even at the optimistic ends of Gemma's confidence intervals (68,000 or more false alarms).

## Context: other zero-shot LLMs on the same 400 edges

| Model | Recall | False-positive rate | Unusable replies |
|---|---|---|---|
| Gemma 4 31B (Gemini API) | 0.670 | 0.360 | 0 |
| qwen3.8-27b (Groq) | 0.045 | 0.040 | 0 |
| gpt-oss-20b (Groq), partial: 285 of 400 edges, not yet scored | about 0.33 | about 0.32 | 8 of 285 |

Gemma 4 is the best zero-shot LLM tried, and the only one clearly above chance (recall exceeds false-positive rate by a wide margin).

## How the GNN does with very few labels

| GraphSAGE variant | Attack labels used | Recall | False-positive rate | Precision |
|---|---|---|---|---|
| Full data | 779 | 0.871 | 0.0028 | 0.566 |
| 1% few-shot | 8 | 0.758 | 0.0074 | 0.297 |

Even with 8 attack labels the GNN's false-positive rate (0.74%) is about 50x lower than Gemma's (36%), at a similar recall to Gemma's. Few-shot GNN is therefore a stronger low-label baseline than zero-shot LLM prompting.

## Caveats

- **Different test sets.** Gemma's precision and F1 are projected from a balanced 400-edge sample to the 0.41% test prevalence, assuming the sample is representative. Its recall and false-positive rate are measured directly, but on only 200 edges per class (see the intervals above). The GNN figures come from all 232,088 test edges.
- **Single run.** Gemma ran once on one prompt (IPs shown, zero-shot). Different prompts, few-shot examples, or `--no-ips` could change the result. Not tested.
- **Unequal tuning.** The GNN's threshold was tuned on the validation split. The LLM has no tunable threshold, and its hard label cannot be traded off between recall and false alarms.
- **Not the same task.** The GNN is binary and does not output a MITRE technique. Gemma's technique accuracy (0.216) has no GNN counterpart. Most attack edges are T1595 (145 of 200 in the sample) or T1046 (49 of 200).
- **GNN training note.** `binary_graphsage_v2.json` reports `best_epoch: 1`, which suggests early stopping on validation PR-AUC. Worth checking that it's not under-trained, since the validation PR-AUC (0.566) is far below the test PR-AUC (0.739).
- **Cost and speed.** Gemma took about 2.5 hours for 400 edges because each reply carries a long reasoning block. The GNN scores all 232,088 edges in one pass.

## Takeaway

For this task the supervised GNN is far better than the best zero-shot LLM: similar or higher recall, about 130x fewer false alarms, and a usable precision. Gemma 4's zero-shot detection is real but not deployable. Its more plausible role is as a second-stage explainer or triage helper on edges the GNN has already flagged, not as the detector.

Sources: `gnn_edge_data/binary_graphsage_v2.json`, `gnn_edge_data/models/fewshot_test_comparison.csv`, `evaluation/model_b/zero_ip_models-gemma-4-31b-it.metrics.csv`, `evaluation/model_b/zero_ip_qwen-qwen3.8-27b.metrics.csv`.
