# /// script
# dependencies = ["pandas", "pyarrow"]
# ///
"""Model B: baseline LLM (zero-shot / few-shot) on UWF 5-minute edges.

Unit of prediction = one (src IP, dst IP, 5-minute window) row of
gnn_edge_data/{train,validation,test}_edges_5min_enriched.parquet, the same edges the GNN
models score. Prompts are built and replies parsed by ../edge_serializer.py, shared with the
other text-based models, so only the model differs. Queries an OpenAI-compatible chat endpoint
(Ollama locally, vLLM/Groq/etc. elsewhere).

  uv run intelligence/baseline_llm.py --mode zero
  uv run intelligence/baseline_llm.py --mode few --k 4 --no-ips

Predictions are appended to a .jsonl file, so an interrupted run resumes where it stopped.
"""
import argparse, json, os, sys, time, urllib.error, urllib.request
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent.parent   # repo root, so defaults work from any cwd
sys.path.insert(0, str(ROOT.parent))            # edge_serializer.py lives next to the repo
from edge_serializer import build_prompt, parse_answer  # noqa: E402

env = ROOT / ".env"   # KEY=value lines; real environment variables take precedence
for line in env.read_text().splitlines() if env.exists() else []:
    k, _, v = line.partition("=")
    if k.strip() and not k.lstrip().startswith("#") and v.strip():
        os.environ.setdefault(k.strip(), v.strip().strip("\"'"))

SYSTEM = ("You are a SOC analyst reviewing aggregated Zeek network logs. "
          "Decide whether each activity summary is an attack or normal traffic.")


def load(data_dir, split):
    return pd.read_parquet(Path(data_dir) / f"{split}_edges_5min_enriched.parquet")


def first_mitre(codes):
    return codes[0] if codes is not None and len(codes) > 0 else None


def parent(code):
    return code.split(".")[0] if isinstance(code, str) else None


def pick_examples(train, k, seed):
    # k attack rows (one per most common technique) + k normal rows, shuffled.
    att = train[train.binary_target == 1]
    tech = att.mitre_targets.map(first_mitre)
    top = tech.value_counts().index[:k]
    ex = pd.concat([att[tech == t].sample(1, random_state=seed) for t in top]
                   + [train[train.binary_target == 0].sample(k, random_state=seed)])
    return [r for _, r in ex.sample(frac=1, random_state=seed).iterrows()]


def ask(base_url, model, prompt):
    body = {"model": model, "temperature": 0, "response_format": {"type": "json_object"},
            "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}]}
    req = urllib.request.Request(f"{base_url}/chat/completions", json.dumps(body).encode(),
                                 {"Content-Type": "application/json", "User-Agent": "baseline-llm/1.0",   # default urllib UA is blocked by Cloudflare (Groq)
                                  "Authorization": f"Bearer {os.environ.get('LLM_API_KEY', 'none')}"})
    for attempt in range(6):   # retry rate limits (429) and transient server errors with backoff
        try:
            with urllib.request.urlopen(req, timeout=300) as resp:
                return json.load(resp)["choices"][0]["message"]["content"]
        except urllib.error.HTTPError as e:
            if e.code not in (429, 500, 502, 503) or attempt == 5:
                raise
            time.sleep(float(e.headers.get("Retry-After") or 2 ** attempt))


def metrics(p, prevalence):
    # p: rows with y, pred (None = unparseable, counted as "normal"), technique, true_techniques (list).
    # Sample is class-balanced, so precision is re-weighted to the test split's true prevalence.
    y, yhat = p.y.to_numpy(), p.pred.fillna(0).to_numpy()
    tpr = (yhat[y == 1] == 1).mean() if (y == 1).any() else float("nan")
    fpr = (yhat[y == 0] == 1).mean() if (y == 0).any() else float("nan")
    d = tpr * prevalence + fpr * (1 - prevalence)
    prec = tpr * prevalence / d if d > 0 else float("nan")
    hit = p[(p.y == 1) & (p.pred == 1) & p.true_techniques.map(len).gt(0)]
    tech_acc = (hit.apply(lambda r: parent(r.technique) in {parent(t) for t in r.true_techniques}, axis=1).mean()
                if len(hit) else float("nan"))
    return pd.Series(dict(n=len(p), n_attack=int(y.sum()), unusable=int(p.pred.isna().sum()),
                          recall=tpr, fpr=fpr, test_prevalence=prevalence, precision_at_prevalence=prec,
                          f1_at_prevalence=2 * prec * tpr / (prec + tpr) if prec + tpr > 0 else float("nan"),
                          technique_acc=tech_acc)).round(4)


def main():
    a = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    a.add_argument("--data", default=ROOT.parent / "gnn_edge_data")
    a.add_argument("--split", choices=["validation", "test"], default="test")
    a.add_argument("--mode", choices=["zero", "few"], default="zero")
    a.add_argument("--k", type=int, default=4, help="few-shot: k attack (top-k techniques) + k normal examples")
    a.add_argument("--n", type=int, default=200, help="edges per class to evaluate")
    a.add_argument("--no-ips", action="store_true", help="hide IPs in prompts (removes the host-identity shortcut)")
    a.add_argument("--model", default="qwen2.5:7b-instruct")
    a.add_argument("--base-url", default="http://localhost:11434/v1")
    a.add_argument("--seed", type=int, default=42)
    a.add_argument("--out", default=None)
    args = a.parse_args()
    ips = "noip" if args.no_ips else "ip"
    out = Path(args.out or ROOT / f"evaluation/model_b/{args.mode}_{ips}_{args.model.replace(':', '-').replace('/', '-')}.jsonl")
    out.parent.mkdir(parents=True, exist_ok=True)

    evals = load(args.data, args.split)
    prevalence = float(evals.binary_target.mean())
    sample = evals.sample(frac=1, random_state=args.seed).groupby("binary_target").head(args.n)
    print(sample.binary_target.value_counts().to_string(), "\n")

    shots = pick_examples(load(args.data, "train"), args.k, args.seed) if args.mode == "few" else None
    done = {json.loads(l)["edge_idx"] for l in out.open()} if out.exists() else set()
    with out.open("a") as f:
        for i, (idx, r) in enumerate(sample.iterrows()):
            if idx in done:
                continue
            raw = ask(args.base_url, args.model, build_prompt(r, shots, include_ips=not args.no_ips))
            pred, tech = parse_answer(raw)
            f.write(json.dumps(dict(edge_idx=int(idx), y=int(r.binary_target), pred=pred, technique=tech,
                                    true_techniques=list(r.mitre_targets) if r.mitre_targets is not None else [],
                                    raw=raw)) + "\n")
            f.flush()
            if i % 50 == 0:
                print(f"{i}/{len(sample)}", flush=True)

    p = pd.read_json(out, lines=True)
    p = p[p.edge_idx.isin(sample.index)]
    m = metrics(p, prevalence)
    m.to_frame("value").to_csv(out.with_suffix(".metrics.csv"))
    print(m.to_string())


if __name__ == "__main__":
    main()
