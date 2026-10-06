"""Gemma 4 zero-shot vs few-shot prompting: saved runs, prompts as sent, and an optional live call."""
from __future__ import annotations

import html
import json
import os
import random
import sys
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

APP_DIR = Path(__file__).resolve().parent.parent
PROJECT_ROOT = APP_DIR.parent
sys.path = [p for p in sys.path if Path(p).resolve() != APP_DIR]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.config import BINARY_METRICS, GEMMA_MODEL  # noqa: E402
from app.llm_demo import prompts, replay  # noqa: E402
from app.llm_demo.live import LiveCallError, ask_gemma  # noqa: E402
from app.llm_demo.serializer import parse_answer  # noqa: E402

st.set_page_config(page_title="Gemma 4 Prompting", page_icon="🛡️", layout="wide")

# Design tokens match the main demo's dark theme (.streamlit/config.toml). Chart colours are
# categorical slots 1 (blue) and 2 (orange) of the dark palette; both exceed 3:1 on the surface.
st.markdown(
    """
<style>
  :root {
    --bg: #0B1220; --surface: #111C2E; --surface-2: #16243A; --border: #1E293B; --border-strong: #334155;
    --text: #E5E7EB; --muted: #94A3B8; --cyan: #22D3EE;
    --good: #22C55E; --bad: #EF4444; --warn: #F59E0B;
    --series-1: #3987e5; --series-2: #d95926; --radius: 12px;
  }
  .block-container { max-width: 1240px; padding-top: 2rem; padding-bottom: 3rem; }
  h1 { font-weight: 700; letter-spacing: -0.01em; margin-bottom: .15rem; }
  h3 { font-size: 1.15rem !important; margin: .2rem 0 .5rem 0 !important; }
  .lede { color: var(--muted); font-size: .95rem; margin: 0 0 1.1rem 0; max-width: 62ch; line-height: 1.5; }
  .eyebrow { color: var(--muted); font-size: .72rem; font-weight: 600; letter-spacing: .08em; text-transform: uppercase; margin: 0 0 .35rem 0; }

  /* edge summary strip */
  .edge-card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius);
               padding: 1rem 1.25rem; display: flex; flex-wrap: wrap; gap: .6rem 1.75rem; align-items: center; margin-bottom: 1.25rem; }
  .edge-card .flow { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 1rem; color: var(--text); }
  .edge-card .flow .arrow { color: var(--muted); padding: 0 .4rem; }
  .fact { display: flex; flex-direction: column; gap: 2px; }
  .fact .k { color: var(--muted); font-size: .7rem; text-transform: uppercase; letter-spacing: .06em; }
  .fact .v { color: var(--text); font-size: .95rem; font-weight: 600; font-variant-numeric: tabular-nums; }

  /* pills: colour is never the only signal, each carries an icon and a word */
  .pill { display: inline-flex; align-items: center; gap: .4rem; padding: .22rem .7rem; border-radius: 999px;
          font-size: .85rem; font-weight: 600; border: 1px solid transparent; white-space: nowrap; }
  .pill.good { color: #86EFAC; background: rgba(34,197,94,.12); border-color: rgba(34,197,94,.35); }
  .pill.bad  { color: #FCA5A5; background: rgba(239,68,68,.12); border-color: rgba(239,68,68,.35); }
  .pill.warn { color: #FCD34D; background: rgba(245,158,11,.12); border-color: rgba(245,158,11,.35); }
  .pill.info { color: #67E8F9; background: rgba(34,211,238,.10); border-color: rgba(34,211,238,.30); }
  .pill.muted { color: var(--muted); background: rgba(148,163,184,.10); border-color: rgba(148,163,184,.25); }

  /* result card */
  .result { background: var(--surface-2); border: 1px solid var(--border); border-radius: var(--radius); padding: 1rem 1.1rem; margin: .4rem 0 .6rem 0; }
  .result .outcome { display: flex; align-items: center; justify-content: space-between; gap: .8rem; margin-bottom: .9rem; }
  .result .title { font-weight: 600; font-size: 1rem; }
  .result .grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: .75rem; }
  .result .cell .k { color: var(--muted); font-size: .7rem; text-transform: uppercase; letter-spacing: .06em; margin-bottom: .3rem; }
  .result .cell .v { font-size: .95rem; font-weight: 600; }

  /* KPI tiles */
  .tiles { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 1rem; margin: .3rem 0 1.4rem 0; }
  .tile { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 1.1rem 1.25rem; }
  .tile.hero { border-color: rgba(34,211,238,.45); background: linear-gradient(180deg, rgba(34,211,238,.07), var(--surface)); }
  .tile .name { color: var(--muted); font-size: .8rem; font-weight: 600; margin-bottom: .5rem; }
  .tile .big { font-size: 2.3rem; font-weight: 700; line-height: 1.05; font-variant-numeric: tabular-nums; }
  .tile .unit { color: var(--muted); font-size: .8rem; margin: .15rem 0 .8rem 0; }
  .tile .sub { color: var(--muted); font-size: .82rem; font-variant-numeric: tabular-nums; }
  .tile .sub b { color: var(--text); font-weight: 600; }

  /* quieter chrome */
  [data-testid="stExpander"] { border-radius: 10px !important; border-color: var(--border) !important; }
  [data-testid="stCode"] pre { font-size: .8rem !important; }
  [data-testid="stSidebar"] h2 { font-size: .8rem !important; text-transform: uppercase; letter-spacing: .08em; color: var(--muted); }
  button[role="tab"] { font-size: 1rem; padding-bottom: .6rem; }
  @media (max-width: 900px) { .tiles, .result .grid { grid-template-columns: 1fr; } }
</style>
""",
    unsafe_allow_html=True,
)

EDGES = replay.common_edges()
RUN_NAMES = list(replay.RUNS)
FEW_RUNS = RUN_NAMES[1:]
ZERO_REF = replay.load_run("Zero-shot")


@st.cache_resource(show_spinner=False)
def _prompt_config(secret_value: str | None):
    """Private prompt wording and examples. None when not configured (replay still works)."""
    try:
        return prompts.load_config(secret_value), None
    except (ValueError, OSError) as e:
        return None, f"The prompt configuration could not be read: {e}"


def _secret(name: str) -> str:
    try:
        return st.secrets.get(name, "") or ""
    except Exception:
        return ""


PROMPT_CFG, PROMPT_ERR = _prompt_config(_secret("GEMMA_PROMPT_CONFIG") or None)


def _esc(x) -> str:
    return html.escape(str(x))


def _pill(text: str, kind: str, icon: str = "") -> str:
    return f'<span class="pill {kind}">{icon + " " if icon else ""}{_esc(text)}</span>'


def _verdict_pill(label: int | None, *, unknown: str = "unparseable") -> str:
    if label is None:
        return _pill(unknown, "warn" if unknown == "unparseable" else "muted", "?" if unknown == "unparseable" else "–")
    return _pill("attack", "bad", "⚠") if label == 1 else _pill("normal", "good", "●")


def _secret_key() -> str:
    """Deployer-provided key, if any. Viewers normally supply their own."""
    try:
        return st.secrets.get("GEMINI_API_KEY", "") or os.environ.get("GEMINI_API_KEY", "")
    except Exception:
        return os.environ.get("GEMINI_API_KEY", "")


def _edge_card(edge_idx: int) -> None:
    row = replay.edge_row(edge_idx)
    n = int(row.connection_count)
    proto = max((("TCP", row.tcp_count), ("UDP", row.udp_count), ("ICMP", row.icmp_count)), key=lambda p: p[1])
    ref = ZERO_REF[edge_idx]
    truth = _verdict_pill(ref.y)
    tech = f' {_pill(", ".join(ref.true_techniques), "muted")}' if ref.true_techniques else ""
    st.markdown(
        f"""<div class="edge-card">
  <div><div class="eyebrow">Edge {edge_idx} · {_esc(pd.Timestamp(row.window_start).strftime('%Y-%m-%d %H:%M'))} UTC</div>
       <div class="flow">{_esc(row.src_ip_zeek)}<span class="arrow">→</span>{_esc(row.dest_ip_zeek)}</div></div>
  <div class="fact"><span class="k">Connections</span><span class="v">{n:,}</span></div>
  <div class="fact"><span class="k">Dominant protocol</span><span class="v">{proto[0]} {100 * proto[1] / max(n, 1):.0f}%</span></div>
  <div class="fact"><span class="k">Bytes out / in</span><span class="v">{int(row.total_orig_bytes):,} / {int(row.total_resp_bytes):,}</span></div>
  <div class="fact"><span class="k">Ground truth</span><span class="v">{truth}{tech}</span></div>
</div>""",
        unsafe_allow_html=True,
    )


def _prompt_view(run: str, edge_idx: int) -> None:
    draw = replay.draw_of(run)
    if draw is None:
        st.caption("No examples. The model sees only the event and the question.")
    elif PROMPT_CFG:
        total, n_att = prompts.example_counts(PROMPT_CFG, draw)
        st.caption(f"The prompt starts with {total} labelled examples ({n_att} attack, {total - n_att} normal), "
                   "then the event below. The examples are not shown in this demo.")
    else:
        st.caption("The prompt starts with labelled examples, then the event below. The examples are not shown in this demo.")
    st.caption("The edge summarised above is sent to the model as a structured event. "
               "The GNN's output and the ground truth are never part of the prompt.")


def _result_card(reply: replay.Reply, *, live: bool = False) -> None:
    if reply.pred is None:
        outcome = _pill("Unparseable reply", "warn", "?")
    elif reply.y is None:
        outcome = _pill("Not scored (no true label)", "muted", "–")
    elif reply.pred == reply.y:
        outcome = _pill("Correct", "good", "✓")
    else:
        outcome = _pill("Incorrect", "bad", "✗")
    source = _pill("Live call", "info", "●") if live else _pill("Saved run", "muted")
    truth = ", ".join(reply.true_techniques) or ("none" if reply.y is not None else "")
    st.markdown(
        f"""<div class="result">
  <div class="outcome"><span class="title">Result</span><span>{source} {outcome}</span></div>
  <div class="grid">
    <div class="cell"><div class="k">Model says</div><div class="v">{_verdict_pill(reply.pred)}</div></div>
    <div class="cell"><div class="k">MITRE technique</div><div class="v">{_esc(reply.technique or "none")}</div></div>
    <div class="cell"><div class="k">True label</div><div class="v">{_verdict_pill(reply.y, unknown="unknown")} <span style="color:var(--muted);font-weight:500">{_esc(truth)}</span></div></div>
  </div>
</div>""",
        unsafe_allow_html=True,
    )


def _saved_result(run: str, edge_idx: int) -> None:
    st.markdown('<div class="eyebrow">Saved result</div>', unsafe_allow_html=True)
    st.markdown(_pill("Earlier plain-text prompt", "warn", "!") +
                ' <span style="color:var(--muted);font-size:.82rem">this reply came from an earlier prompt format, so a live run may differ</span>',
                unsafe_allow_html=True)
    _result_card(replay.load_run(run)[edge_idx])


# ---- sidebar -----------------------------------------------------------------------------
with st.sidebar:
    st.header("Pick an edge")
    cls = st.radio("Class", ["Any", "Attack", "Normal"], horizontal=True, key="cls")
    pool = [e for e in EDGES if cls == "Any" or ZERO_REF[e].y == (cls == "Attack")]
    if "edge_idx" not in st.session_state or st.session_state.edge_idx not in pool:
        st.session_state.edge_idx = pool[0]
    if st.button("🎲  Random edge"):
        st.session_state.edge_idx = random.choice(pool)
    edge_idx = st.selectbox("Edge id", pool, key="edge_idx", help=f"{len(pool)} edges in this class")

    st.header("Live call")
    typed = st.text_input("Gemini API key", type="password", key="gemini_key", placeholder="Paste your key to enable",
                          help="Held only in this browser session. It is sent to the Gemini API over HTTPS "
                               "and is never saved, logged or shown.")
    api_key = typed or _secret_key()
    st.caption("🔒 Never stored or logged. Replay works without a key.")

# ---- header ------------------------------------------------------------------------------
st.title("Gemma 4: zero-shot vs few-shot")
st.markdown(
    f'<p class="lede">How well does <code>{_esc(GEMMA_MODEL)}</code> spot attacks in a 5-minute network summary with no '
    "training, and does showing it a few examples help? Browse any edge below, or compare the saved runs.</p>",
    unsafe_allow_html=True,
)

tab_edge, tab_compare = st.tabs(["Prompt & result", "Compare runs"])

with tab_edge:
    _edge_card(edge_idx)
    few_run = st.selectbox("Few-shot example draw", FEW_RUNS, key="few_run",
                           help="Each draw picks a different 4 attack + 4 normal examples from the validation split.")

    left, right = st.columns(2, gap="large")
    for col, run in ((left, "Zero-shot"), (right, few_run)):
        with col, st.container(border=True):
            st.markdown(f"### {run}")
            _prompt_view(run, edge_idx)
            st.divider()
            _saved_result(run, edge_idx)

    def _load_current_edge() -> None:
        st.session_state.custom_text = replay.target_event_text(st.session_state.edge_idx)

    st.markdown("### Try it live")
    with st.container(border=True):
        source = st.radio("Event to send", ["Selected edge", "Paste my own"], horizontal=True, key="live_source")
        live_run = st.radio("Prompt style", RUN_NAMES, horizontal=True, key="live_run",
                            help="Few-shot prompts include the 8 labelled examples before your event.")
        custom_record, ignored = None, []
        if source == "Paste my own":
            st.text_area("Event JSON", key="custom_text", height=300, placeholder=(
                '{\n  "event_id": "my-event",\n  "row_id": 1,\n  "event": {\n    "window_start": "2025-05-30T16:25:00",\n'
                '    "source_ip": "143.88.3.14",\n    "destination_ip": "143.88.3.11",\n    "traffic_features": { ... }\n  }\n}'),
                help="Paste a full record or just the event block. gnn_detection and ground_truth are removed before sending.")
            st.button("Fill with the selected edge's event", on_click=_load_current_edge)
            text = st.session_state.get("custom_text", "").strip()
            if text:
                try:
                    custom_record, ignored = replay.parse_custom_event(text)
                    if ignored:
                        st.caption(f"Ignored {', '.join(f'`{k}`' for k in ignored)}: these never reach the model.")
                except ValueError as e:
                    st.error(str(e), icon="⚠️")
        can_run = bool(api_key) and PROMPT_CFG is not None and (source == "Selected edge" or custom_record is not None)
        go = st.button("▶  Run live", disabled=not can_run, type="primary")
        if PROMPT_ERR:
            st.error(PROMPT_ERR, icon="🚫")
        elif PROMPT_CFG is None:
            st.info("Live calls are unavailable: the private prompt configuration is not set up on this server. "
                    "Everything above still works.", icon="🔒")
        if not api_key:
            st.info("Add a Gemini API key in the sidebar to enable this. Everything above works without one.", icon="🔑")
        else:
            st.caption("One event per click. Gemma 4 takes about 20 seconds to answer.")
        if go:
            try:
                with st.spinner("Waiting for Gemma 4…"):
                    if source == "Selected edge":
                        prompt, ref = replay.prompt_for(PROMPT_CFG, live_run, edge_idx), ZERO_REF[edge_idx]
                        truth = (ref.y, ref.true_techniques)
                    else:
                        prompt, truth = replay.prompt_for_record(PROMPT_CFG, live_run, custom_record), (None, [])
                    raw = ask_gemma(prompt, api_key, PROMPT_CFG["system"])
                label, tech = parse_answer(replay.THOUGHT.sub("", raw))
                st.session_state.live_result = (source, live_run, edge_idx, replay.Reply(
                    edge_idx, truth[0], label, tech, truth[1], raw))
            except LiveCallError as e:
                st.session_state.pop("live_result", None)
                st.error(str(e), icon="🚫")
        result = st.session_state.get("live_result")
        if result and result[0] == source and result[1] == live_run and (source == "Paste my own" or result[2] == edge_idx):
            _result_card(result[3], live=True)

# ---- compare -----------------------------------------------------------------------------
with tab_compare:
    prevalence = replay.test_prevalence()
    metrics = {run: replay.run_metrics(run, prevalence) for run in RUN_NAMES}
    g = json.loads(BINARY_METRICS.read_text())
    g_fpr = g["false_positives"] / (g["false_positives"] + g["true_negatives"])
    few = [metrics[r] for r in FEW_RUNS]
    few_recall = sum(m["recall"] for m in few) / 3
    few_fpr = sum(m["fpr"] for m in few) / 3
    few_prec = sum(m["precision"] for m in few) / 3
    lo, hi = min(m["recall"] for m in few), max(m["recall"] for m in few)
    z = metrics["Zero-shot"]

    st.markdown(
        f"""<div class="tiles">
  <div class="tile"><div class="name">Gemma 4, zero-shot</div>
    <div class="big">≈{1 / z['precision']:.0f}</div><div class="unit">alerts per real attack</div>
    <div class="sub">Recall <b>{z['recall']:.2f}</b> · false alarms on <b>{z['fpr']:.0%}</b> of normal edges</div></div>
  <div class="tile"><div class="name">Gemma 4, few-shot (mean of 3 draws)</div>
    <div class="big">≈{1 / few_prec:.0f}</div><div class="unit">alerts per real attack</div>
    <div class="sub">Recall <b>{few_recall:.2f}</b> (draws range <b>{lo:.2f}–{hi:.2f}</b>) · false alarms <b>{few_fpr:.0%}</b></div></div>
  <div class="tile hero"><div class="name">GraphSAGE (trained GNN)</div>
    <div class="big">{1 / g['test_precision']:.1f}</div><div class="unit">alerts per real attack</div>
    <div class="sub">Recall <b>{g['test_recall']:.2f}</b> · false alarms <b>{g_fpr:.1%}</b> of normal edges</div></div>
</div>""",
        unsafe_allow_html=True,
    )
    st.caption(f"Alerts per real attack = 1 ÷ precision at the real test attack rate ({prevalence:.2%}). "
               "Lower is better for an analyst's workload.")

    st.markdown("### Recall and false-positive rate")
    st.markdown('<p class="lede" style="margin-bottom:.4rem">Higher recall is better; a lower false-positive rate is better. '
                "A useful detector is tall in blue and short in orange.</p>", unsafe_allow_html=True)
    GNN = "GraphSAGE (full test)"
    order = RUN_NAMES + [GNN]
    chart_rows = []
    for run in RUN_NAMES:
        chart_rows += [{"Run": run, "Measure": "Recall", "Value": metrics[run]["recall"]},
                       {"Run": run, "Measure": "False-positive rate", "Value": metrics[run]["fpr"]}]
    chart_rows += [{"Run": GNN, "Measure": "Recall", "Value": g["test_recall"]},
                   {"Run": GNN, "Measure": "False-positive rate", "Value": g_fpr}]
    cdf = pd.DataFrame(chart_rows)
    measures = ["Recall", "False-positive rate"]
    colour = alt.Color("Measure:N", sort=measures, scale=alt.Scale(domain=measures, range=["#3987e5", "#d95926"]),
                       legend=alt.Legend(orient="top", title=None, labelColor="#E5E7EB", symbolType="square"))
    base = alt.Chart(cdf).encode(
        x=alt.X("Run:N", sort=order, title=None, axis=alt.Axis(labelAngle=0, labelColor="#E5E7EB", labelLimit=140,
                                                               domain=False, ticks=False)),
        xOffset=alt.XOffset("Measure:N", sort=measures),
        y=alt.Y("Value:Q", scale=alt.Scale(domain=[0, 1]), title=None,
                axis=alt.Axis(format="%", labelColor="#94A3B8", gridColor="#1E293B", domain=False, ticks=False, tickCount=5)),
        color=colour,
        tooltip=[alt.Tooltip("Run:N"), alt.Tooltip("Measure:N"), alt.Tooltip("Value:Q", format=".1%")],
    )
    bars = base.mark_bar(size=26, cornerRadiusTopLeft=4, cornerRadiusTopRight=4, stroke="#0B1220", strokeWidth=2)
    labels = (base.transform_filter(alt.FieldOneOfPredicate(field="Run", oneOf=["Zero-shot", GNN]))
              .mark_text(dy=-8, fontSize=12, fontWeight=600, color="#E5E7EB")
              .encode(text=alt.Text("Value:Q", format=".1%")))
    st.altair_chart((bars + labels).properties(height=330, background="transparent").configure_view(strokeWidth=0),
                    use_container_width=True)
    st.caption("Few-shot results swing widely with which examples are drawn. GraphSAGE is scored on all 232,088 test "
               "edges; Gemma on a balanced 400-edge sample, so its precision is projected.")

    st.info("These Gemma runs used the earlier plain-text prompt. The page now sends the JSON event prompt, so live "
            "results may differ until the runs are repeated.", icon="ℹ️")

    with st.expander("Data table (all numbers, with 95% confidence intervals)"):
        rows = []
        for run in RUN_NAMES:
            m = metrics[run]
            rows.append({"Run": run, "Recall": m["recall"], "Recall 95% CI": f"{m['recall_ci'][0]:.2f} – {m['recall_ci'][1]:.2f}",
                         "False-positive rate": m["fpr"], "FPR 95% CI": f"{m['fpr_ci'][0]:.2f} – {m['fpr_ci'][1]:.2f}",
                         f"Precision at {prevalence:.2%}": m["precision"], "F1 at prevalence": m["f1"],
                         "MITRE technique accuracy": m["technique_acc"]})
        rows.append({"Run": GNN, "Recall": g["test_recall"], "Recall 95% CI": "n/a",
                     "False-positive rate": g_fpr, "FPR 95% CI": "n/a",
                     f"Precision at {prevalence:.2%}": g["test_precision"], "F1 at prevalence": g["test_f1"],
                     "MITRE technique accuracy": float("nan")})
        df = pd.DataFrame(rows)
        st.dataframe(df.style.format({c: "{:.3f}" for c in df.columns if c not in ("Run", "Recall 95% CI", "FPR 95% CI")},
                                     na_rep="n/a"), hide_index=True)

    st.markdown("### What this shows")
    st.markdown(
        "- **Few-shot is no better than zero-shot on average.** Recall ranges from 0.55 to 0.89 depending on which "
        "examples are drawn, so a single few-shot run is not a reliable result.\n"
        "- **False alarms are the problem.** At the real attack rate Gemma raises about 130 alerts per real attack; "
        "GraphSAGE raises fewer than 2.\n"
        "- **Likely role for the LLM:** explain alerts the GNN has already flagged, not detect attacks itself."
    )
