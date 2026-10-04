# /// script
# dependencies = ["pandas", "pyarrow"]
# ///
"""Model B: baseline LLM (zero-shot / few-shot) on UWF windowed edges.

Unit of prediction = one (src IP, dst IP, 15-min window) edge from edges_win_15min.parquet,
the same unit the GNN models score. Each edge is serialised to text and sent to an
OpenAI-compatible chat endpoint (Ollama locally, vLLM/Groq/etc. elsewhere).

  uv run intelligence/baseline_llm.py --mode zero
  uv run intelligence/baseline_llm.py --mode few --k 4

Predictions are appended to a .jsonl file, so an interrupted run resumes where it stopped.
"""
import argparse, json, math, os, urllib.request
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent   # repo root, so defaults work from any cwd

SYSTEM = """You are a SOC analyst reviewing Zeek network logs.
Each record aggregates every Zeek conn.log connection from one source IP to one destination IP inside one 15-minute window.
Decide whether the traffic is part of an attack (adversary activity) or normal traffic.
If it is an attack, give the single most likely MITRE ATT&CK technique ID (for example T1595, T1046, T1110, T1190).

Field notes:
- conn_state share: SF = established and closed normally; S0 = SYN sent, no reply; REJ = connection rejected;
  RST = reset by either side; OTH = no SYN seen (mid-stream); partial = half-open or other incomplete states.
- Zeek history flags are the mean count per connection of: S = SYN, h = SYN-ACK, A = pure ACK, D = data,
  F = FIN, R = RST, T = retransmission.
- "typical" per-connection values are geometric means over the connections in the record.

Respond with JSON only:
{"label": "attack" or "normal", "attack_probability": number between 0 and 1, "technique": "T####" or null, "rationale": "one or two sentences"}"""


def load(data_dir):
    d = Path(data_dir)
    e = pd.read_parquet(d / "edges_win_15min.parquet")
    w = pd.read_parquet(d / "windows_15min.parquet", columns=["win_id", "source_dataset"])
    e["source_dataset"] = e.win_id.map(w.set_index("win_id").source_dataset)
    return e, pd.read_csv(d / "node_static.csv", index_col="node_id")


def to_text(r, ips):
    def host(i):
        n = ips.loc[i]
        return f"{n.ip} ({'special' if n.is_special else 'internal' if n.is_internal else 'external'})"
    x = math.expm1
    pct = lambda v: f"{100 * v:.0f}%"
    return "\n".join([
        f"window_start_utc: {datetime.fromtimestamp(r.ts_first, timezone.utc):%Y-%m-%d %H:%M:%S}",
        f"src: {host(r.src_id)} -> dst: {host(r.dst_id)}",
        f"connections: {r.n_logs} over {x(r.log_span):.1f} s",
        f"protocols: tcp={r.total_tcp:.0f} udp={r.total_udp:.0f} icmp={r.total_icmp:.0f}",
        f"services: http={r.total_http:.0f} dns={r.total_dns:.0f} ssl={r.total_ssl:.0f} ssh={r.total_ssh:.0f} unknown={r.total_unknown:.0f}",
        f"conn_state share: SF={pct(r.f_cs_sf)} S0={pct(r.f_cs_s0)} REJ={pct(r.f_cs_rej)} RST={pct(r.f_cs_rst)} "
        f"OTH={pct(r.f_cs_oth)} partial={pct(r.f_cs_partial)}",
        f"history flags per conn: S={r.m_h_S:.2f} h={r.m_h_h:.2f} A={r.m_h_ack:.2f} D={r.m_h_data:.2f} "
        f"F={r.m_h_fin:.2f} R={r.m_h_rst:.2f} T={r.m_h_retx:.2f} (mean history length {r.m_h_len:.1f})",
        f"distinct ports: dst={r.n_dst_ports} src={r.n_src_ports}",
        f"dst port groups: web={pct(r.f_pg_web)} ssh={pct(r.f_pg_ssh)} smb/rdp={pct(r.f_pg_smb_rdp)} dns={pct(r.f_pg_dns)} "
        f"other_well_known={pct(r.f_pg_other_wk)} registered={pct(r.f_pg_registered)} ephemeral={pct(r.f_pg_ephemeral)}",
        f"typical per conn: duration={x(r.avg_log_duration):.2f} s orig_bytes={x(r.avg_log_orig_bytes):.0f} "
        f"resp_bytes={x(r.avg_log_resp_bytes):.0f} orig_pkts={x(r.avg_log_orig_pkts):.1f} resp_pkts={x(r.avg_log_resp_pkts):.1f}",
    ])


def tid(tech):
    return tech if isinstance(tech, str) and tech.startswith("T") else None


def fewshot_block(e, ips, target, k, seed):
    # Examples come from the train split of the OTHER datasets: same-dataset examples would be
    # near-duplicate twins of the test edges (96% have one), i.e. leakage, not few-shot.
    pool = e[(e.split == 0) & (e.source_dataset != target)]
    att = pool[pool.y == 1]
    top = att.tech_mode.value_counts().index[:k]
    ex = pd.concat([att[att.tech_mode == t].sample(1, random_state=seed) for t in top]
                   + [pool[pool.y == 0].sample(k, random_state=seed)]).sample(frac=1, random_state=seed)
    shots = [f"{to_text(r, ips)}\n=> " + json.dumps({"label": "attack" if r.y else "normal",
                                                       "technique": tid(r.tech_mode) if r.y else None})
             for r in ex.itertuples()]
    return "Labelled examples from other networks:\n\n" + "\n\n".join(shots) + "\n\nNow classify this record:\n"


def ask(base_url, model, prompt):
    body = {"model": model, "temperature": 0, "response_format": {"type": "json_object"},
            "messages": [{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}]}
    req = urllib.request.Request(f"{base_url}/chat/completions", json.dumps(body).encode(),
                                 {"Content-Type": "application/json",
                                  "Authorization": f"Bearer {os.environ.get('LLM_API_KEY', 'none')}"})
    with urllib.request.urlopen(req, timeout=300) as resp:
        return json.load(resp)["choices"][0]["message"]["content"]


def parse(raw):
    # Returns (pred 0/1/None, attack_probability, technique). None = unusable answer.
    try:
        o = json.loads(raw)
        label = str(o.get("label", "")).strip().lower()
        pred = {"attack": 1, "normal": 0}.get(label)
        p = float(o.get("attack_probability", pred if pred is not None else 0.5))
        tech = o.get("technique")
        return pred, min(max(p, 0.0), 1.0), tech if isinstance(tech, str) and tech.strip() else None
    except (ValueError, TypeError, AttributeError):
        return None, 0.5, None


def auc(y, s):
    y, s = np.asarray(y), np.asarray(s)
    n1 = y.sum(); n0 = len(y) - n1
    if n1 == 0 or n0 == 0:
        return np.nan
    r = pd.Series(s).rank().to_numpy()
    return (r[y == 1].sum() - n1 * (n1 + 1) / 2) / (n1 * n0)


def metrics(p, prevalence):
    # p: rows with y, pred (unusable answers count as "normal"), p_attack, technique, tech_mode, source_dataset.
    # Sample is class-balanced, so precision is re-weighted to the dataset's true test prevalence.
    rows = []
    for name, g in [*p.groupby("source_dataset"), ("ALL", p)]:
        y, yhat = g.y.to_numpy(), g.pred.fillna(0).to_numpy()
        tpr = (yhat[y == 1] == 1).mean() if (y == 1).any() else np.nan
        fpr = (yhat[y == 0] == 1).mean() if (y == 0).any() else np.nan
        pi = prevalence[name]
        prec = tpr * pi / (tpr * pi + fpr * (1 - pi)) if tpr * pi + fpr * (1 - pi) > 0 else np.nan
        hit = g[(g.y == 1) & (g.pred == 1) & g.tech_mode.map(tid).notna()]
        tech_acc = (hit.technique.fillna("").str.split(".").str[0] == hit.tech_mode).mean() if len(hit) else np.nan
        rows.append(dict(dataset=name, n=len(g), n_attack=int(y.sum()), unusable=int(g.pred.isna().sum()),
                         recall=tpr, fpr=fpr, roc_auc=auc(y, g.p_attack), test_prevalence=pi,
                         precision_at_prevalence=prec,
                         f1_at_prevalence=2 * prec * tpr / (prec + tpr) if prec + tpr > 0 else np.nan,
                         technique_acc=tech_acc))
    return pd.DataFrame(rows).set_index("dataset").round(4)


def main():
    a = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    a.add_argument("--data", default=ROOT / "data/uwf_graph_v2")
    a.add_argument("--mode", choices=["zero", "few"], default="zero")
    a.add_argument("--k", type=int, default=4, help="few-shot: k attack (top-k techniques) + k normal examples")
    a.add_argument("--n", type=int, default=100, help="test edges per dataset per class")
    a.add_argument("--model", default="qwen2.5:7b-instruct")
    a.add_argument("--base-url", default="http://localhost:11434/v1")
    a.add_argument("--seed", type=int, default=42)
    a.add_argument("--out", default=None)
    args = a.parse_args()
    out = Path(args.out or ROOT / f"evaluation/model_b/{args.mode}_{args.model.replace(':', '-').replace('/', '-')}.jsonl")
    out.parent.mkdir(parents=True, exist_ok=True)

    e, ips = load(args.data)
    test = e[e.split == 2]
    prevalence = {**test.groupby("source_dataset").y.mean().to_dict(), "ALL": test.y.mean()}
    sample = test.sample(frac=1, random_state=args.seed).groupby(["source_dataset", "y"]).head(args.n)
    print(sample.groupby(["source_dataset", "y"]).size().unstack(), "\n")

    done = {json.loads(l)["edge_idx"] for l in out.open()} if out.exists() else set()
    shots = {} if args.mode == "zero" else {
        t: fewshot_block(e, ips, t, args.k, args.seed) for t in sample.source_dataset.unique()}
    with out.open("a") as f:
        for i, (idx, r) in enumerate(sample.iterrows()):
            if idx in done:
                continue
            raw = ask(args.base_url, args.model, shots.get(r.source_dataset, "") + to_text(r, ips))
            pred, p, tech = parse(raw)
            f.write(json.dumps(dict(edge_idx=int(idx), source_dataset=r.source_dataset, y=int(r.y),
                                    tech_mode=r.tech_mode if r.y else None, pred=pred, p_attack=p, technique=tech, raw=raw)) + "\n")
            f.flush()
            if i % 50 == 0:
                print(f"{i}/{len(sample)}", flush=True)

    p = pd.read_json(out, lines=True)
    p = p[p.edge_idx.isin(sample.index)]
    m = metrics(p, prevalence)
    m.to_csv(out.with_suffix(".metrics.csv"))
    print(m.to_string())


if __name__ == "__main__":
    main()
