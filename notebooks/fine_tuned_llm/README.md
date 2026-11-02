# Fine-tuned LLM, Model 3 (SJSU-119)

`UWF_LLM_Finetune.ipynb` fine-tunes Qwen2.5-7B-Instruct with QLoRA (Unsloth) to read one 5-minute connection summary
and answer Sai's three targets as JSON: `{"attack": ..., "tactics": [...], "techniques": [...]}`
(`binary_target`, `tactic_targets`, `mitre_targets`).

## What the notebook does

| Section | Content |
|---|---|
| 1-2 | Colab setup (Drive, Unsloth) and settings: `SPLIT`, `SPLIT_DIR`, `TEST_FILE`, `PILOT` |
| 3 | Reads Sai's split files from `SPLIT_DIR` (default `Shareddrives/298B/07 GraphSAGE - data prep artifacts/processed_edges/`: `train_edges.parquet` and `validation_edges.parquet`; the test file from `TEST_FILE` once available), in raw units (saved before log1p and scaling). With the other `SPLIT` options it reads `blocked_cv/sai_edges_5min_capture.parquet` (SJSU-118, section 11). Turns each connection into plain text: counts, bytes, packets, duration, ports, service, connection state, and what the source and destination did in the same window. No IPs, timestamps, dataset names or labels |
| 4 | Split (default `sai_files`: Sai's random 80/10/10 window split, the same files as the Laya notebook; `leave_one_dataset_out`, `year` and `random_window` are still available). Training set: up to `TRAIN_CAP_PER_COMBO` connections per attack combination plus the same number of normal connections, duplicate texts removed. Validation: sampled the same way from the validation file (`VAL_CAP_PER_COMBO`), texts already in training dropped. Test set: sampled per attack combination and normal traffic, with weights so scores reflect the test file's real attack rate |
| 5-6 | Prompt (allowed tactics and techniques listed), answer parsing (labels outside the list counted as invalid), scoring |
| 7-8 | Untrained model scored first (zero-shot); skipped while there is no test file |
| 9 | QLoRA fine-tuning, loss on the answer only; the adapter is saved to Drive |
| 10 | Before/after comparison and per-technique recall; skipped while there is no test file |

Outputs go to `Shareddrives/298B/llm_finetune/sai_split[__pilot]/` (other splits: `<split>__<held-out dataset>[__pilot]/`). Finished steps (predictions,
adapter) are reused on rerun; delete the file to redo a step.

## Earlier pilot result (leave-one-dataset-out)

Before the switch to Sai's split files: Sum25-1 held out, `PILOT = True` (~2,500 training examples, 1 epoch, ~30 min on Colab GPU).

| | Zero-shot | Fine-tuned |
|---|---|---|
| Attack PR-AUC | 0.002 | 0.965 |
| Attack recall | 0.00 | 0.81 |
| Attack precision | 0.00 | 1.00 |
| False-alarm rate | 0.005 | 0.000 |
| Tactic micro-F1 | 0.00 | 0.48 |
| Technique micro-F1 | 0.00 | 0.38 |

The fine-tuned model finds T1595 (Active Scanning) on 53% of its test connections; the other techniques in Sum25-1
have 1-15 test connections each. It often answers Reconnaissance where the label is Discovery.

## How to run

1. Check that `SPLIT_DIR` points to Sai's `train_edges.parquet` and `validation_edges.parquet`.
2. Open the notebook in Colab with a GPU runtime (L4 or A100 recommended) and run all cells. Without a test file it
   trains (`TRAIN_CAP_PER_COMBO = 500`, 1 epoch) and saves the adapter to `OUT_DIR/adapter`.
3. When the test file is available, set `TEST_FILE` to its path, restart the runtime and run all cells again: training is
   skipped (the saved adapter is loaded) and the zero-shot and fine-tuned scores are written.

Zero-shot must run on the untrained model: after training, restart the runtime before rerunning section 8.
For a quick end-to-end check use `PILOT = True`; for leave-one-dataset-out set `SPLIT` and `HOLD_OUT`.

## Limitations

- Sai's split shuffles whole 5-minute windows, so windows of the same attack campaign can be in both the training
  and test files; scores on it are not comparable with leave-one-dataset-out scores
- 99.4% of UWF attack edges are in windows with no normal traffic, so the window-context lines make detection easier
  than on mixed real traffic (this affects the GNN too)
- Tactics and techniques are listed sorted, not ranked, so "first correct" is not the same as the GNN's top-1
- The zero-shot column is untrained Qwen, not Model 2 (Gemma prompting)
