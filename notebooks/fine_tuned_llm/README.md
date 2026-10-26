# Fine-tuned LLM, Model 3 (SJSU-119)

`UWF_LLM_Finetune.ipynb` fine-tunes Qwen2.5-7B-Instruct with QLoRA (Unsloth) to read one 5-minute connection summary
and answer Sai's three targets as JSON: `{"attack": ..., "tactics": [...], "techniques": [...]}`
(`binary_target`, `tactic_targets`, `mitre_targets`).

## What the notebook does

| Section | Content |
|---|---|
| 1-2 | Colab setup (Drive, Unsloth) and settings: `SPLIT`, `HOLD_OUT`, `PILOT` |
| 3 | Reads `Shareddrives/298B/blocked_cv/sai_edges_5min_capture.parquet` (written by the SJSU-118 notebook, section 11) and turns each connection into plain text: counts, bytes, packets, duration, ports, service, connection state, and what the source and destination did in the same window. No IPs, timestamps, dataset names or labels |
| 4 | Split (default: leave-one-dataset-out, same as the GNN evaluation). Training set: up to `TRAIN_CAP_PER_COMBO` connections per attack combination plus the same number of normal connections, duplicate texts removed, 10% validation. Test set: sampled per attack combination and normal traffic, with weights so scores reflect the held-out dataset's real attack rate |
| 5-6 | Prompt (allowed tactics and techniques listed), answer parsing (labels outside the list counted as invalid), scoring |
| 7-8 | Untrained model scored first (zero-shot) |
| 9 | QLoRA fine-tuning, loss on the answer only; the adapter is saved to Drive |
| 10 | Before/after comparison and per-technique recall |

Outputs go to `Shareddrives/298B/llm_finetune/<split>__<held-out dataset>[__pilot]/`. Finished steps (predictions,
adapter) are reused on rerun; delete the file to redo a step.

## Pilot result

Leave-one-dataset-out, Sum25-1 held out, `PILOT = True` (~2,500 training examples, 1 epoch, ~30 min on Colab GPU).

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

1. Open the notebook in Colab with a GPU runtime (L4 or A100 recommended).
2. Run sections 1-10 in order with `PILOT = True`, then set `PILOT = False` for the full run.
3. For other folds change `HOLD_OUT` (`UWF-ZeekData24`, `UWF-ZeekDataFall24-2`, ...) and rerun from section 2.

Zero-shot must run on the untrained model: after training, restart the runtime before rerunning section 8.

## Limitations

- 99.4% of UWF attack edges are in windows with no normal traffic, so the window-context lines make detection easier
  than on mixed real traffic (this affects the GNN too)
- Tactics and techniques are listed sorted, not ranked, so "first correct" is not the same as the GNN's top-1
- The zero-shot column is untrained Qwen, not Model 2 (Gemma prompting)
