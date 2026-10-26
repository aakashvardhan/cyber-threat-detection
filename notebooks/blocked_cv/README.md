# Evaluation methods for the GNN detector (SJSU-118)

`UWF_GNN_Blocked_CV.ipynb` rebuilds Sai's pipeline from the raw UWF Zeek files and compares ways of
splitting the data, so that every edge is tested once and no attack campaign is in both training and test.

## What the notebook does

| Section | Content |
|---|---|
| 1-4 | Raw files from `Shareddrives/298B/uwf_raw_backup`, Sai's label cleaning and year split, 5-minute edges with the recording (`capture`) kept in the edge key |
| 5-6 | Blocks (attack stretches split at gaps over 65 min, normal days), `StratifiedGroupKFold` folds, roles with a 65-minute purge |
| 7-8 | Sai's 1-hour context graphs and GraphSAGE recipe |
| 9 | Runs: Sai's year split (reference), blocked 5-fold CV (3 repeats), leave-one-year-out |
| 9b | Shortcut baselines on the same splits: edge features only, window activity only |
| 9c | **Leave-one-recording-out** (6 folds, one per UWF recording), extra training seeds, leakage checks |
| 9d | Per-recording rescaling experiment (rejected) |
| 10 | Results tables |

Outputs are written to `Shareddrives/298B/blocked_cv/`. The notebook was run in Colab over several sessions, so cell
execution order is not linear.

## Parity with Sai's pipeline

Same 27,111,594 raw logs and label counts; with the recording left out of the key, the edges match Sai's exactly
(150,914 / 295,052 / 232,088 edges; 779 / 52,913 / 958 attack edges). Keeping the recording in the key gives
726,307 edges: 48,253 of Sai's edges combined traffic from two recordings made at the same time
(ZeekData22 + Fall22, Sum25-1 + Sum25-2). Only about 2% of those had identical counts, so they are different traffic.

## Results (binary detection, PR-AUC)

| Evaluation | Result | What it measures |
|---|---|---|
| Sai's year split, rebuilt | 0.923 | One future period (2025, 2% of attacks) |
| Blocked CV, attack stretches cut into 24 h chunks | 0.994 pooled | Leaks: days of the same scripted ZeekData24 campaign in train and test |
| Blocked CV, whole stretches, 3 repeats | 0.938 / 0.975 / 0.995 pooled; 0.828 per-recording average | Within-recording; the pooled score depends on whether ZeekData24's three blocks are split across folds |
| Leave-one-year-out | 0.302 / 0.494 / 0.911 (2021-22 / 2024 / 2025 held out) | A whole unseen period |
| **Leave-one-recording-out (main)** | **0.888 pooled, 0.683 per-recording average; recall 0.83, precision 0.77, FPR 2.0%** | A recording never seen in training |

Leave-one-recording-out, per recording (GraphSAGE mean ± std over training seeds 42, 43, 44; baselines seed 42):

| Recording held out | GraphSAGE | Edge only | Window only |
|---|---|---|---|
| ZeekData24 | 0.965 ± 0.007 | 0.821 | 0.616 |
| Sum25-1 | 0.939 ± 0.006 | 0.899 | 1.000 |
| Sum25-2 | 0.789 ± 0.171 | 0.976 | 1.000 |
| Fall22 | 0.624 ± 0.035 | 0.359 | 0.224 |
| ZeekData22 | 0.582 ± 0.071 | 0.041 | 0.833 |
| Fall24-2 | 0.084 ± 0.029 | 0.466 | 1.000 |

Seeds 43 and 44 were run in a separate Colab session; the saved output of that cell shows a `NameError` from a
restarted runtime. Their per-recording scores were: seed 43 - 0.648, 0.974, 0.663, 0.077, 0.932, 0.885;
seed 44 - 0.507, 0.963, 0.613, 0.060, 0.942, 0.592 (ZeekData22, ZeekData24, Fall22, Fall24-2, Sum25-1, Sum25-2).

## Checks

- No two recordings contain attacks in the same 5-minute window.
- Attacks from addresses that never attacked in training are caught as often as attacks from familiar ones
  (ZeekData24: 83.4% vs 82.9%).
- 99.4% of attack edges are in windows with no normal traffic, so window activity alone ranks attacks well within a
  recording (window-only 0.78 per-recording average) but not across recordings (0.11 pooled). Treat UWF scores as an
  upper bound for mixed real-world traffic.
- Rescaling features per recording raised Fall24-2 from 0.12 to 0.54 but dropped the pooled score from 0.89 to 0.04,
  so it is not used.

## Running

Open in Colab with a GPU runtime and run all cells. Settings are in the `CFG` dictionary (section 0). Leave-one-recording-out
needs `GRAPH_SCOPE = "capture"`, because recordings overlap in time and a shared graph would mix test and training edges.
Finished runs are saved under `results_<scope>_max<hours>h/` and skipped when the notebook is rerun.
