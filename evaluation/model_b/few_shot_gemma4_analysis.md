# Few-shot prompting with Gemma 4 31B: does it help, and how much does the choice of examples matter?

Model: `gemma-4-31b-it` via the Gemini API, temperature 0. Task: label a 5-minute UWF edge as attack or normal and, for attacks, give a MITRE technique. Every run below scores the same 400 test edges (200 attack, 200 normal, seed 42). The test split has 232,088 edges and 958 attacks (0.41%).

## Summary

- **Few-shot is no better than zero-shot on average.** Across three random draws of the examples, mean recall is 0.668 (zero-shot 0.670) and mean false-positive rate is 0.382 (zero-shot 0.360).
- **The draw matters enormously.** One draw reaches recall 0.885 at false-positive rate 0.215. Another falls to recall 0.545 at 0.535, which is chance. The spread (sd 0.19 for recall) is far larger than the sampling error on 200 edges.
- **A single few-shot run is not a reliable result.** The first run (see below) looked like "few-shot hurts", and a single lucky draw would have looked like "few-shot is excellent". Neither claim holds.
- **The GNN is still far ahead.** The best draw has 1.7% precision at the real attack rate, against 56.6% for GraphSAGE. See `comparison_gnn_vs_gemma4.md`.

## Why the first few-shot run was not a fair test

The first few-shot run picked its 4 attack examples as the top-4 techniques by frequency in the **train** split. The splits have very different attack mixes:

| Split | Attack edges | No technique | Most common techniques |
|---|---|---|---|
| Train | 779 | 44% | T1590 37%, T1589 6%, T1595 3.5%, T1046 1.4% |
| Validation | 52,913 | about 0% | T1595 69%, T1078 10%, T1110 9%, T1190 9% |
| Test | 958 | 0% | T1595 69%, T1046 28% |

The examples were therefore T1589, T1590, T1595 and T1587, and the dominant test technique (T1595, 145 of the 200 sampled attacks) appeared once, with an example that looks like a normal edge (4 connections, 0 bytes). That run scored recall 0.395 and false-positive rate 0.405 (no better than chance), and lost 55 of the 134 attacks zero-shot had caught, almost all T1595.

## Fixes made to the test

1. **Examples drawn from the validation split**, never the evaluated split. Validation's technique mix is close to the test's, and using it is legitimate because it is the tuning split.
2. **Attack techniques drawn in proportion to their validation frequency**, instead of the top-k. Attacks with no technique are skipped, and no row repeats.
3. **Separate seeds.** `--shot-seed` controls the examples and `--seed` controls the evaluated edges, so every run is scored on identical edges.
4. **Three independent draws** (shot seeds 0, 1, 2), reported with mean and spread, so one lucky or unlucky draw cannot decide the result.
5. **Paired comparison** with zero-shot on the same edges (McNemar test), per class.
6. **Unparseable replies count as "attack"** in all metrics, as a missed attack costs more than a false alarm. All runs here had zero unparseable replies, so this did not affect them.

## Results

| Run | Recall (95% CI) | False-positive rate (95% CI) | Precision at 0.41% | F1 at 0.41% | Technique acc. |
|---|---|---|---|---|---|
| Zero-shot | 0.670 (0.60–0.73) | 0.360 (0.30–0.43) | 0.0077 | 0.0151 | 0.216 |
| Few-shot, old selection (train top-k) | 0.395 (0.33–0.46) | 0.405 (0.34–0.47) | 0.0040 | 0.0080 | 0.190 |
| Few-shot, seed 0 | 0.545 (0.48–0.61) | 0.535 (0.47–0.60) | 0.0042 | 0.0083 | 0.220 |
| Few-shot, seed 1 | **0.885** (0.83–0.92) | **0.215** (0.16–0.28) | 0.0168 | 0.0329 | 0.192 |
| Few-shot, seed 2 | 0.575 (0.51–0.64) | 0.395 (0.33–0.46) | 0.0060 | 0.0119 | 0.339 |
| **Few-shot mean ± sd (seeds 0–2)** | **0.668 ± 0.188** | **0.382 ± 0.160** | | | |

Precision and F1 are projected from the balanced sample to the real 0.41% attack rate. Technique accuracy is the share of correct MITRE parent IDs among attacks the model flagged (79 to 177 detections per run).

### Paired comparison with zero-shot (same 400 edges)

"Lost" means zero-shot flagged the edge as attack and few-shot did not; "gained" is the reverse.

| Draw | Attack edges (recall) | Normal edges (false alarms) |
|---|---|---|
| Seed 0 | lost 32, gained 7 (p<0.001): worse | removed 18, added 53 (p<0.001): worse |
| Seed 1 | lost 0, gained 43 (p<0.001): better | removed 35, added 6 (p<0.001): better |
| Seed 2 | lost 25, gained 6 (p<0.001): worse | removed 43, added 50 (p=0.53): no change |

Seed 1 is strictly better than zero-shot (it never lost a detection). Seeds 0 and 2 are worse on recall, and seed 0 is also worse on false alarms.

### Examples shown in each draw

| Draw | Attack examples | Normal examples |
|---|---|---|
| Seed 0 | T1078, T1595, T1595, T1595 | 4 |
| Seed 1 | T1595, T1595, T1595, T1078 | 4 |
| Seed 2 | T1595 ×4 | 4 |

Seeds 0 and 1 have the same technique mix but opposite results, so technique mix alone does not explain the difference. The specific example rows must matter. The exact rows are in each run's `.shots.json`. I have not yet compared them.

## Interpretation

- Few-shot prompting with 8 examples gives this model no reliable gain on these edges. The examples change many individual answers (between 41 and 93 of the 200 normal edges changed their answer in each draw), but the net effect depends on the particular examples.
- T1046, which is 28% of test attacks but under 1% of validation edges, is absent from all example sets. The zero-shot model already caught it (49 of 49), and the old selection kept that. Whether the new draws kept it was not checked.
- High variance across draws means that few-shot results from a single run, here or in other work, should be treated with caution.

## Caveats

- **Do not pick the best draw by its test score.** Reporting seed 1 as "the few-shot result" because it scored highest on test would be selection on the test set and would overstate few-shot. Choose examples by their score on a validation sample, then run the test once, or report the mean and spread as above.
- **Three draws** give a rough estimate of the spread; the sd estimates themselves are uncertain.
- One model, one prompt, IPs shown in every prompt (`--no-ips` not tested), and k=4 only. Other `k` values, other models and prompts may behave differently.
- 400 edges per run (200 per class). Recall and false-positive rate are measured directly. Precision and F1 are projections.
- Temperature 0 does not guarantee identical replies from a hosted API; reruns were not checked.
- Cost and time: each run takes about 2.5 to 3 hours because every reply includes a long reasoning block.

## Suggested next steps

1. Choose examples on the validation split: score several draws on a validation sample, take the best, and run it once on test.
2. Rerun with `--no-ips` to remove the host-identity shortcut.
3. Add a score (probability or token log-probability) so that a threshold can be tuned on validation. See the discussion of thresholds in the project notes.
4. Compare the example rows of seeds 0 and 1 to see what the model reacted to.

## Reproduce

```
python3 intelligence/baseline_llm.py --model models/gemma-4-31b-it \
  --base-url https://generativelanguage.googleapis.com/v1beta/openai \
  --api-key-env GEMINI_API_KEY --mode few --k 4 \
  --shot-split validation --shot-seed 0 --n 200      # seeds 0, 1, 2
```

Files in `evaluation/model_b/`:
- `few4-validation-s{0,1,2}_ip_models-gemma-4-31b-it.{jsonl,metrics.csv,shots.json}` (new selection, three draws)
- `few_ip_models-gemma-4-31b-it.{jsonl,metrics.csv}` (first run, train top-k selection)
- `zero_ip_models-gemma-4-31b-it.{jsonl,metrics.csv}` (zero-shot)
