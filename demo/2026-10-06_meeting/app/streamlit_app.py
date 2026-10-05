"""Streamlit demo for 5-minute GNN threat detection intervals."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

APP_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = APP_DIR.parent
sys.path = [p for p in sys.path if Path(p).resolve() != APP_DIR]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    from dotenv import load_dotenv

    load_dotenv(APP_DIR / ".env", override=False)
except ImportError:
    pass

from app.config import (  # noqa: E402
    WINDOW_MINUTES,
    live_inference_available,
    missing_artifacts,
)
from app.data_loader import (  # noqa: E402
    events_to_summary_table,
    parse_window_start,
    window_interval_label,
)

st.set_page_config(
    page_title="Threat Detection Demo",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Chronological demo scenarios (UTC) with predicted attacks.
DEMO_ATTACK_WINDOWS = [
    ("2025-05-30T16:25:00", "Scattered attacks", "4 attacks / 42 events"),
    ("2025-06-02T19:55:00", "Mixed traffic with attacks", "5 attacks / 38 events"),
    ("2025-06-03T16:35:00", "Burst of attacks", "254 attacks / 288 events"),
]
DEFAULT_DEMO_WINDOW = None  # Start at window 0001 on fresh open.

st.markdown(
    """
<style>
  :root {
    --bg: #0B1220;
    --surface: #111C2E;
    --border: #1E293B;
    --border-strong: #334155;
    --text: #E5E7EB;
    --muted: #94A3B8;
    --cyan: #22D3EE;
    --cyan-dim: rgba(34, 211, 238, 0.14);
    --red: #EF4444;
    --amber: #F59E0B;
    --green: #22C55E;
    --radius: 10px;
  }

  .block-container {
    padding-top: 1.4rem;
    padding-bottom: 2rem;
    max-width: 100%;
  }

  [data-testid="stAppViewContainer"],
  .stApp {
    background-color: var(--bg);
    color: var(--text);
  }

  [data-testid="stHeader"] {
    background: rgba(11, 18, 32, 0.85);
    border-bottom: 1px solid var(--border);
  }

  [data-testid="stSidebar"] {
    background-color: var(--surface) !important;
    border-right: 1px solid var(--border);
  }
  [data-testid="stSidebar"] .stMarkdown p,
  [data-testid="stSidebar"] .stMarkdown strong {
    color: var(--text) !important;
  }
  [data-testid="stSidebar"] .stCaption,
  [data-testid="stSidebar"] small {
    color: var(--muted) !important;
  }

  h1 {
    font-size: 1.7rem !important;
    font-weight: 700 !important;
    color: var(--text) !important;
    letter-spacing: -0.02em;
    margin-bottom: 0.4rem !important;
  }
  h2, h3, h4, h5, h6 {
    color: var(--text) !important;
    font-weight: 600 !important;
  }
  .stCaption, [data-testid="stCaptionContainer"] {
    color: var(--muted) !important;
  }
  label[data-testid="stWidgetLabel"] p {
    color: var(--text) !important;
  }

  hr {
    border-color: var(--border) !important;
    margin: 0.9rem 0 1.1rem 0 !important;
  }

  /* Buttons */
  .stButton > button {
    border-radius: 8px !important;
    border: 1px solid var(--border-strong) !important;
    background: var(--surface) !important;
    color: var(--text) !important;
    transition: border-color 0.15s ease, background 0.15s ease, box-shadow 0.15s ease;
  }
  .stButton > button:hover {
    border-color: var(--cyan) !important;
    background: var(--cyan-dim) !important;
    color: var(--text) !important;
    box-shadow: 0 0 0 1px rgba(34, 211, 238, 0.25);
  }
  .stButton > button[kind="primary"],
  .stButton > button[data-testid="baseButton-primary"] {
    background: var(--cyan) !important;
    border-color: var(--cyan) !important;
    color: #0B1220 !important;
    font-weight: 600 !important;
  }
  .stButton > button[kind="primary"]:hover,
  .stButton > button[data-testid="baseButton-primary"]:hover {
    background: #67E8F9 !important;
    border-color: #67E8F9 !important;
    color: #0B1220 !important;
  }

  /* Closed select / inputs */
  div[data-baseweb="select"] > div,
  .stTextInput input,
  .stNumberInput input {
    background-color: var(--surface) !important;
    border-color: var(--border-strong) !important;
    color: var(--text) !important;
    border-radius: 8px !important;
  }
  div[data-baseweb="select"] span,
  div[data-baseweb="select"] div {
    color: var(--text) !important;
  }
  div[data-baseweb="select"]:hover > div {
    border-color: var(--cyan) !important;
  }

  /* Open dropdown menus (BaseWeb portals) — force dark + readable text */
  div[data-baseweb="popover"],
  div[data-baseweb="menu"],
  ul[role="listbox"],
  li[role="option"] {
    background-color: #111C2E !important;
    color: #E5E7EB !important;
  }
  ul[role="listbox"] {
    border: 1px solid #334155 !important;
  }
  li[role="option"] {
    background-color: #111C2E !important;
    color: #E5E7EB !important;
  }
  li[role="option"] *,
  li[role="option"] span,
  li[role="option"] div {
    color: #E5E7EB !important;
  }
  li[role="option"]:hover,
  li[aria-selected="true"] {
    background-color: rgba(34, 211, 238, 0.16) !important;
  }

  [data-testid="stCheckbox"] label,
  [data-testid="stCheckbox"] label span,
  [data-testid="stCheckbox"] label p,
  [data-testid="stCheckbox"] p,
  [data-testid="stSidebar"] [data-testid="stCheckbox"] label,
  [data-testid="stSidebar"] [data-testid="stCheckbox"] label span,
  [data-testid="stSidebar"] [data-testid="stCheckbox"] label p,
  [data-testid="stSidebar"] [data-testid="stCheckbox"] p {
    color: #FFFFFF !important;
  }
  [data-testid="stCheckbox"] svg {
    fill: #FFFFFF !important;
  }

  div[data-testid="stMetric"] {
    background: var(--surface);
    border: 1px solid var(--border);
    padding: 0.9rem 1rem;
    border-radius: var(--radius);
  }
  div[data-testid="stMetric"] label {
    color: var(--muted) !important;
    font-size: 0.78rem !important;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }
  div[data-testid="stMetric"] [data-testid="stMetricValue"] {
    color: var(--text) !important;
    font-size: 1.3rem !important;
  }

  .interval-card {
    padding: 1rem 1.1rem;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--surface);
    min-height: 5.5rem;
    transition: border-color 0.15s ease;
  }
  .interval-card:hover {
    border-color: var(--border-strong);
  }
  .interval-label {
    font-size: 0.72rem;
    color: var(--muted);
    margin-bottom: 0.4rem;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    font-weight: 600;
  }
  .interval-value {
    font-size: 1.12rem;
    font-weight: 600;
    font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
    line-height: 1.4;
    color: var(--text);
    word-break: break-word;
  }

  [data-testid="stExpander"] {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
  }
  [data-testid="stDataFrame"] {
    border: 1px solid var(--border);
    border-radius: var(--radius);
    overflow: hidden;
    background: var(--surface);
  }

  .event-table-wrap {
    width: 100%;
    max-height: 720px;
    overflow: auto;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--surface);
  }
  .event-table {
    border-collapse: separate;
    border-spacing: 0;
    width: max-content;
    min-width: 100%;
    color: var(--text);
    font-size: 0.9rem;
  }
  .event-table thead th {
    position: sticky;
    top: 0;
    z-index: 1;
    background: #0F172A;
    color: #E5E7EB !important;
    font-weight: 700 !important;
    text-align: left;
    padding: 0.75rem 0.9rem;
    border-bottom: 1px solid var(--border-strong);
    white-space: nowrap;
  }
  .event-table tbody td {
    padding: 0.65rem 0.9rem;
    border-bottom: 1px solid var(--border);
    color: #E5E7EB;
    white-space: nowrap;
  }
  .event-table tbody td.rag-reason,
  .event-table tbody td[style*="white-space:normal"] {
    white-space: normal !important;
  }
  .event-table tbody tr:hover td {
    background: rgba(34, 211, 238, 0.08);
  }
  .rag-source-badge {
    display: inline-flex;
    align-items: center;
    gap: 0.25rem;
    padding: 0.2rem 0.55rem;
    border-radius: 999px;
    border: 1px solid rgba(34, 211, 238, 0.45);
    background: rgba(34, 211, 238, 0.12);
    color: #67E8F9 !important;
    font-weight: 600;
    font-size: 0.85rem;
    cursor: help;
  }
  .rag-source-badge.muted {
    border-color: #334155;
    background: #0F172A;
    color: #94A3B8 !important;
  }

  .stAlert {
    border-radius: var(--radius);
  }

  .stDownloadButton > button {
    border-radius: 8px !important;
    border: 1px solid var(--cyan) !important;
    background: var(--cyan-dim) !important;
    color: var(--cyan) !important;
  }
  .stDownloadButton > button:hover {
    background: rgba(34, 211, 238, 0.24) !important;
  }

  /* Readable JSON panel */
  .json-panel {
    background: #0F172A;
    border: 1px solid #1E293B;
    border-radius: 10px;
    padding: 0.85rem 1rem;
    color: #E5E7EB;
    font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
    font-size: 0.85rem;
    line-height: 1.45;
    white-space: pre-wrap;
    word-break: break-word;
    max-height: 520px;
    overflow: auto;
  }
  .stCodeBlock, [data-testid="stCode"] {
    background: #0F172A !important;
    border: 1px solid #1E293B !important;
    border-radius: 10px !important;
  }
  .stCodeBlock pre, [data-testid="stCode"] pre,
  .stCodeBlock code, [data-testid="stCode"] code {
    color: #E5E7EB !important;
  }
</style>
""",
    unsafe_allow_html=True,
)


@st.cache_resource(show_spinner="Loading models and graphs...")
def cached_inference_engine():
    from app.inference.pipeline import CombinedInferenceEngine

    return CombinedInferenceEngine()


@st.cache_resource(show_spinner="Preparing RAG knowledge base...")
def cached_rag_engine():
    from app.rag.bootstrap import ensure_rag_ready
    from app.rag.retrieve import RAGEngine

    if not ensure_rag_ready():
        raise FileNotFoundError("RAG artifacts could not be prepared under app/data/rag.")
    return RAGEngine()


def run_rag_for_attacks(events: list[dict]) -> dict[str, dict]:
    from app.rag import explain_attack_event

    engine = cached_rag_engine()
    explanations: dict[str, dict] = {}
    attacks = [
        e for e in events if e["gnn_detection"]["binary_prediction"]["label"] == "attack"
    ]
    progress = st.progress(0.0, text="Running RAG reasoning for attack events...")
    for i, event in enumerate(attacks):
        explanations[event["event_id"]] = explain_attack_event(event, engine=engine)
        progress.progress((i + 1) / max(len(attacks), 1))
    progress.empty()
    return explanations


def _sources_hover_text(rag: dict | None) -> str:
    if not rag:
        return "No RAG sources"
    lines = []
    for src in rag.get("sources") or []:
        label = src.get("id") or src.get("title") or src.get("type")
        snippet = (src.get("text") or "").replace('"', "'").replace("\n", " ")
        lines.append(f"{src.get('type')}: {label} — {snippet[:220]}")
    return " | ".join(lines) if lines else (rag.get("source_summary") or "No RAG sources")


def render_summary_table(
    events: list[dict],
    rag_by_event_id: dict | None = None,
) -> None:
    df = events_to_summary_table(events, rag_by_event_id=rag_by_event_id)
    rag_by_event_id = rag_by_event_id or {}

    column_widths = {
        "Event ID": 140,
        "Source IP": 130,
        "Destination IP": 140,
        "Prediction": 100,
        "Attack Probability": 140,
        "Binary Confidence": 140,
        "MITRE Technique": 130,
        "MITRE Confidence": 140,
        "Tactic": 150,
        "Tactic Confidence": 140,
        "RAG Reasoning": 560,
        "RAG Sources": 100,
    }

    def fmt_cell(value, col: str, event_id: str | None = None) -> str:
        if value is None or (isinstance(value, float) and pd.isna(value)):
            return ""
        if isinstance(value, float):
            return f"{value:.4f}"
        if col == "RAG Sources":
            rag = rag_by_event_id.get(event_id or "", {})
            count = int(rag.get("source_count") or 0)
            if count <= 0 and value:
                count = max(1, str(value).count(";") + 1) if str(value).strip() else 0
            hover = _sources_hover_text(rag).replace('"', "&quot;")
            if count <= 0:
                return '<span class="rag-source-badge muted" title="No sources">0</span>'
            return f'<span class="rag-source-badge" title="{hover}">📎 {count}</span>'
        if col == "RAG Reasoning":
            return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\n\n", "<br><br>").replace("\n", "<br>")
        return str(value)

    header_html = "".join(
        f'<th style="min-width:{column_widths.get(col, 120)}px;">{col}</th>' for col in df.columns
    )
    body_rows = []
    for _, row in df.iterrows():
        prediction = str(row.get("Prediction", "")).lower()
        pred_color = (
            "#EF4444" if prediction == "attack" else "#22C55E" if prediction == "normal" else "#E5E7EB"
        )
        event_id = str(row.get("Event ID", ""))
        cells = []
        for col in df.columns:
            if col == "Prediction":
                style = f' style="color:{pred_color};font-weight:600;"'
            elif col == "RAG Reasoning":
                style = (
                    ' style="white-space:normal;min-width:560px;max-width:760px;'
                    'line-height:1.45;vertical-align:top;"'
                )
            elif col == "RAG Sources":
                style = ' style="text-align:center;white-space:nowrap;vertical-align:top;"'
            else:
                style = ""
            cells.append(f"<td{style}>{fmt_cell(row[col], col, event_id)}</td>")
        body_rows.append("<tr>" + "".join(cells) + "</tr>")

    table_html = f"""
<div class="event-table-wrap">
  <table class="event-table">
    <thead><tr>{header_html}</tr></thead>
    <tbody>{"".join(body_rows)}</tbody>
  </table>
</div>
"""
    st.markdown(table_html, unsafe_allow_html=True)


def init_session_state(windows: list[str], default_idx: int = 0) -> None:
    if "window_idx" not in st.session_state:
        st.session_state.window_idx = default_idx
    if "last_run_idx" not in st.session_state:
        st.session_state.last_run_idx = default_idx
    st.session_state.window_idx = max(0, min(st.session_state.window_idx, len(windows) - 1))


def advance_window(delta: int, window_count: int) -> None:
    st.session_state.window_idx = (st.session_state.window_idx + delta) % window_count
    st.session_state.last_run_idx = st.session_state.window_idx


def run_live_window(window_start: str, include_ground_truth: bool) -> list[dict]:
    engine = cached_inference_engine()
    ts = pd.Timestamp(parse_window_start(window_start))
    bundle = engine.run_window(ts, include_ground_truth=include_ground_truth)
    return bundle.json_events


def find_window_index(windows: list[str], target: str) -> int | None:
    target_ts = pd.Timestamp(parse_window_start(target))
    for i, window in enumerate(windows):
        if pd.Timestamp(parse_window_start(window)) == target_ts:
            return i
    return None


def main() -> None:
    st.header("Threat Detection & Intelligence Console")
    st.subheader("GNN-Powered Detection, MITRE Mapping, and Threat Intelligence")

    missing = missing_artifacts()
    if missing:
        st.sidebar.warning("Missing under app/data:\n\n" + "\n".join(f"- `{m}`" for m in missing))

    if not live_inference_available():
        st.error(
            "Live inference requires `data/models/*.pt`, "
            "`data/prepared_graphs/test_graphs.pt`, and "
            "`data/test_edges_5min_enriched.parquet`."
        )
        st.stop()

    include_ground_truth = st.sidebar.checkbox(
        "Include ground_truth in JSON",
        value=True,
        help=(
            "When enabled, each event JSON also contains labeled truth from the test set "
            "(binary / MITRE / tactic). Useful for evaluation demos; turn off for "
            "production-style RAG output."
        ),
    )
    enable_rag = st.sidebar.checkbox(
        "Enable RAG reasoning for attacks",
        value=True,
        help=(
            "Retrieve MITRE/procedure evidence and generate Groq LLM reasoning "
            "for predicted attacks. Key is read from app/.env or Streamlit secrets."
        ),
    )
    from app.rag.secrets import get_groq_api_key, get_groq_model

    try:
        groq_key = get_groq_api_key()
        groq_model = get_groq_model()
    except Exception:
        groq_key = None
        groq_model = "openai/gpt-oss-20b"

    if groq_key:
        st.sidebar.success(f"Groq key loaded · model `{groq_model}`")
    else:
        st.sidebar.warning(
            "No Groq key found. Add `GROQ_API_KEY` to `app/.env` or "
            "`app/.streamlit/secrets.toml` (see secrets.toml.example)."
        )

    engine = cached_inference_engine()
    windows = [ts.isoformat() for ts in engine.available_windows()]
    if not windows:
        st.error("No prediction windows found.")
        st.stop()

    default_demo = 0
    if DEFAULT_DEMO_WINDOW:
        default_demo = find_window_index(windows, DEFAULT_DEMO_WINDOW) or 0
    init_session_state(windows, default_idx=default_demo)
    idx = st.session_state.window_idx
    current_window = windows[idx]
    start_label, end_label = window_interval_label(current_window)

    st.sidebar.markdown("**Demo scenarios**")
    for target, scenario, note in DEMO_ATTACK_WINDOWS:
        target_idx = find_window_index(windows, target)
        if target_idx is None:
            continue
        is_selected = target_idx == idx
        button_type = "primary" if is_selected else "secondary"
        label = f"{scenario}\n{target.replace('T', ' ')} · {note}"
        if st.sidebar.button(
            label,
            key=f"demo_{target}",
            use_container_width=True,
            type=button_type,
        ):
            st.session_state.window_idx = target_idx
            st.session_state.last_run_idx = target_idx
            st.rerun()

    st.markdown("##### Prediction interval")
    st.markdown(
        f"""
<div style="display:grid;grid-template-columns:1.4fr 1.4fr 0.8fr;gap:1rem;margin:0.25rem 0 1rem 0;">
  <div class="interval-card">
    <div class="interval-label">Window start (UTC)</div>
    <div class="interval-value">{start_label}</div>
  </div>
  <div class="interval-card">
    <div class="interval-label">Window end (UTC)</div>
    <div class="interval-value">{end_label}</div>
  </div>
  <div class="interval-card">
    <div class="interval-label">Interval length</div>
    <div class="interval-value">{WINDOW_MINUTES} minutes</div>
  </div>
</div>
""",
        unsafe_allow_html=True,
    )

    st.divider()

    control_cols = st.columns([1, 1, 1, 2])
    if control_cols[0].button("◀ Previous 5 min", use_container_width=True):
        advance_window(-1, len(windows))
        st.rerun()

    if control_cols[1].button("▶ Next 5 min interval", type="primary", use_container_width=True):
        advance_window(1, len(windows))
        st.rerun()

    if control_cols[2].button("Run detection", use_container_width=True):
        st.session_state.last_run_idx = idx
        st.rerun()

    jump_options = {f"{i + 1:04d} — {w}": i for i, w in enumerate(windows)}
    selected_label = control_cols[3].selectbox(
        "Jump to window",
        options=list(jump_options.keys()),
        index=idx,
    )
    if jump_options[selected_label] != idx:
        st.session_state.window_idx = jump_options[selected_label]
        st.session_state.last_run_idx = st.session_state.window_idx
        st.rerun()

    show_results = st.session_state.last_run_idx == idx
    if not show_results:
        st.info(
            "Select a 5-minute interval and click **Run detection** (or **Next 5 min interval**) "
            "to display predictions and JSON output."
        )
        st.stop()

    with st.spinner("Running detection for this window..."):
        events = run_live_window(current_window, include_ground_truth=include_ground_truth)

    rag_by_event_id: dict[str, dict] = {}
    if enable_rag:
        attack_events = [
            e for e in events if e["gnn_detection"]["binary_prediction"]["label"] == "attack"
        ]
        if attack_events:
            with st.spinner(f"Running RAG for {len(attack_events)} attack event(s)..."):
                rag_by_event_id = run_rag_for_attacks(attack_events)
            # Attach reasoning onto event payloads for download/JSON view.
            for event in events:
                rag = rag_by_event_id.get(event["event_id"])
                if rag:
                    event["rag_explanation"] = {
                        "reasoning": rag.get("reasoning"),
                        "mode": rag.get("mode"),
                        "model": rag.get("model"),
                        "technique_id": rag.get("technique_id"),
                        "sources": rag.get("sources"),
                        "retrieval": rag.get("retrieval"),
                    }

    attack_count = sum(
        1 for e in events if e["gnn_detection"]["binary_prediction"]["label"] == "attack"
    )
    normal_count = len(events) - attack_count
    metric_cols = st.columns(4)
    metric_cols[0].metric("Events in window", len(events))
    metric_cols[1].markdown(
        f"""
<div class="interval-card" style="border-color:rgba(239,68,68,0.45);">
  <div class="interval-label">Predicted attacks</div>
  <div class="interval-value" style="color:#EF4444;">{attack_count}</div>
</div>
""",
        unsafe_allow_html=True,
    )
    metric_cols[2].markdown(
        f"""
<div class="interval-card" style="border-color:rgba(34,197,94,0.45);">
  <div class="interval-label">Predicted normal</div>
  <div class="interval-value" style="color:#22C55E;">{normal_count}</div>
</div>
""",
        unsafe_allow_html=True,
    )
    metric_cols[3].metric("Window index", f"{idx + 1} / {len(windows)}")

    st.divider()

    only_attacks = st.checkbox("Show only predicted attacks", value=False)
    filtered_events = events
    if only_attacks:
        filtered_events = [
            e for e in events if e["gnn_detection"]["binary_prediction"]["label"] == "attack"
        ]

    st.markdown("##### Event summary")
    if filtered_events:
        render_summary_table(filtered_events, rag_by_event_id=rag_by_event_id)
    else:
        st.warning("No events match the current filter.")

    st.markdown("##### Complete GNN JSON (per event)")
    event_labels = [
        f"{e['event_id']} — {e['gnn_detection']['binary_prediction']['label']} — "
        f"{e['event']['source_ip']} → {e['event']['destination_ip']}"
        for e in filtered_events
    ]
    if not event_labels:
        st.stop()

    selected = st.selectbox("Select event", options=event_labels)
    selected_event = filtered_events[event_labels.index(selected)]

    selected_rag = rag_by_event_id.get(selected_event["event_id"])
    if selected_rag and selected_rag.get("reasoning"):
        st.markdown("##### RAG reasoning")
        st.markdown(selected_rag["reasoning"].replace("\n", "  \n"))
        st.caption(
            f"Mode: {selected_rag.get('mode')} · "
            f"Model: {selected_rag.get('model') or 'n/a'} · "
            f"Technique: {selected_rag.get('technique_id') or 'n/a'} · "
            f"Sources: {selected_rag.get('source_count', 0)}"
        )
        with st.expander("RAG sources (retrieved)", expanded=False):
            st.code(json.dumps(selected_rag.get("sources") or [], indent=2), language="json")

    st.markdown("##### Event JSON")
    st.code(json.dumps(selected_event, indent=2), language="json")

    window_payload = {
        "prediction_interval": {
            "window_start": start_label,
            "window_end": end_label,
            "duration_minutes": WINDOW_MINUTES,
        },
        "event_count": len(events),
        "predicted_attack_count": attack_count,
        "events": events,
    }
    st.download_button(
        label="Download full window JSON",
        data=json.dumps(window_payload, indent=2),
        file_name=f"gnn_window_{idx:04d}.json",
        mime="application/json",
    )


if __name__ == "__main__":
    main()
