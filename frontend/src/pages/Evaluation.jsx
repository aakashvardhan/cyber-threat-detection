import { useEffect, useState } from 'react';
import { api } from '../api/client.js';
import { ReplayStrip } from '../components/ReplayBar.jsx';

// Model comparison from GET /metrics. Two test sets are kept apart: the full test split (graph models)
// and the 7,882-edge shared sample every model was scored on (the LLMs are too slow for 69k edges).

const SHORT = { 'Mistral-7B multi-LoRA': 'Mistral (LoRA)', 'Qwen2.5-7B QLoRA': 'Qwen (QLoRA)' };
const KIND = { GraphSAGE: 'Graph', HGT: 'Graph', 'Mistral-7B multi-LoRA': 'LLM', 'Qwen2.5-7B QLoRA': 'LLM' };
const ORDER = ['GraphSAGE', 'HGT', 'Mistral-7B multi-LoRA', 'Qwen2.5-7B QLoRA'];
const COLS = [
  { key: 'precision', label: 'Precision', group: 'Attack detection' },
  { key: 'recall', label: 'Recall', group: 'Attack detection' },
  { key: 'f1', label: 'F1', group: 'Attack detection' },
  { key: 'pr_auc', label: 'PR-AUC', group: 'Attack detection' },
  { key: 'tactic_micro_f1', label: 'Micro F1', group: 'Tactic' },
  { key: 'tactic_macro_f1', label: 'Macro F1', group: 'Tactic' },
  { key: 'technique_micro_f1', label: 'Micro F1', group: 'Technique' },
  { key: 'technique_macro_f1', label: 'Macro F1', group: 'Technique' },
];

const fmt = (v) => (v == null ? '—' : Number(v).toFixed(3));
const pct = (v) => (v == null ? '—' : `${Math.round(v * 100)}%`);

function flat(m) {
  const d = m.detection || {};
  const t = m.technique || {};
  return { precision: d.precision, recall: d.recall, f1: d.f1 ?? d.macro_f1, pr_auc: d.pr_auc, roc_auc: d.roc_auc,
    tactic_micro_f1: t.tactic_micro_f1, tactic_macro_f1: t.tactic_macro_f1,
    technique_micro_f1: t.micro_f1, technique_macro_f1: t.macro_f1 };
}

function isSample(m) { return /sample/i.test(m.test_set || ''); }

function ScoreTable({ rows, caption }) {
  const best = Object.fromEntries(COLS.map((c) => [c.key, Math.max(...rows.map((r) => r.scores[c.key] ?? -1))]));
  const groups = [...new Set(COLS.map((c) => c.group))];
  return (
    <div className="table-scroll">
      <table className="eval-table">
        <caption className="sr-only">{caption}</caption>
        <thead>
          <tr>
            <th rowSpan={2} scope="col">Model</th>
            {groups.map((g) => <th key={g} colSpan={COLS.filter((c) => c.group === g).length} scope="colgroup" className="group">{g}</th>)}
          </tr>
          <tr>{COLS.map((c) => <th key={c.key + c.group} scope="col" className="num">{c.label}</th>)}</tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.name}>
              <th scope="row" title={r.full}>
                <span className="eval-model">{r.name}</span>
                <span className="small muted">{r.kind}{r.note ? ` · ${r.note}` : ''}</span>
              </th>
              {COLS.map((c) => {
                const v = r.scores[c.key];
                const top = v != null && v === best[c.key] && rows.length > 1;
                return (
                  <td key={c.key} className={`num mono${top ? ' is-best' : ''}`}>
                    <span className="cell-bar" style={{ width: `${(v ?? 0) * 100}%` }} aria-hidden="true" />
                    <span className="cell-val">{fmt(v)}</span>
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Stat({ label, value, sub }) {
  return (
    <div className="kpi">
      <span className="kpi-label">{label}</span>
      <span className="kpi-value" style={{ fontSize: 24 }}>{value}</span>
      {sub && <span className="kpi-sub muted">{sub}</span>}
    </div>
  );
}

function ExplanationLayer({ m }) {
  const r = m.retrieval || {};
  const e = m.explanation || {};
  const q = [['Event queries', r.golden_event_queries], ['Technique queries', r.golden_technique_queries]].filter(([, v]) => v);
  return (
    <section className="panel">
      <div className="panel-head"><h2>Explanation layer ({m.model})</h2><span className="small muted">Detection is unchanged by RAG; these measure the explanation</span></div>
      <div className="kpis" style={{ borderTop: '1px solid var(--border)', borderBottom: '1px solid var(--border)' }}>
        <Stat label="Groundedness" value={e.groundedness != null ? fmt(e.groundedness) : 'Not run yet'}
          sub="Share of explanation sentences that cite evidence" />
        <Stat label="GNNExplainer: top-5 features" value={e.gnnexplainer_logit_drop_top5 != null ? `−${fmt(e.gnnexplainer_logit_drop_top5)}` : '—'}
          sub={e.gnnexplainer_logit_drop_random5 != null ? `logit drop when removed, vs −${fmt(e.gnnexplainer_logit_drop_random5)} for 5 random` : null} />
        <Stat label="Top features beat random" value={pct(e.gnnexplainer_top_beats_random)} sub="of incidents" />
        {r.behaviour_check_hit_at_5_range && (
          <Stat label="Behaviour check hit@5" value={r.behaviour_check_hit_at_5_range.map(fmt).join('–')} sub="leave-one-family-out, by attack family" />
        )}
      </div>
      {q.length > 0 && (
        <div className="panel-body" style={{ paddingTop: 16 }}>
          <h3 className="mini-head">Retrieval on the golden query set</h3>
          <div className="table-scroll">
            <table className="eval-table compact">
              <thead><tr><th scope="col">Queries</th><th className="num" scope="col">Hit@5</th><th className="num" scope="col">Precision@5</th><th className="num" scope="col">MRR</th><th className="num" scope="col">nDCG@10</th></tr></thead>
              <tbody>
                {q.map(([label, v]) => (
                  <tr key={label}><th scope="row">{label}</th><td className="num mono">{fmt(v.hit_at_5)}</td><td className="num mono">{fmt(v.precision_at_5)}</td><td className="num mono">{fmt(v.mrr)}</td><td className="num mono">{fmt(v.ndcg_at_10)}</td></tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </section>
  );
}

function Ablations({ items }) {
  if (!items?.length) return null;
  return (
    <section className="panel">
      <div className="panel-head"><h2>RAG ablations</h2><span className="small muted">Can retrieval do more than explain?</span></div>
      <div className="panel-body" style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
        {items.map((a) => (
          <div key={a.id} style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            <h3 className="mini-head" style={{ margin: 0 }}>{a.question}</h3>
            <p className="small muted" style={{ margin: 0 }}>{a.setup}</p>
            {a.rows && (
              <div className="table-scroll">
                <table className="eval-table compact">
                  <thead>
                    <tr><th scope="col">Model</th><th className="num" scope="col">Technique F1 as is (micro / macro)</th><th className="num" scope="col">Check replaces</th><th className="num" scope="col">Check is added</th><th className="num" scope="col">Fixed / broken</th></tr>
                  </thead>
                  <tbody>
                    {[...a.rows].sort((x, y) => ORDER.indexOf(x.model) - ORDER.indexOf(y.model)).map((r) => (
                      <tr key={r.model}>
                        <th scope="row">{SHORT[r.model] ?? r.model}</th>
                        <td className="num mono">{fmt(r.base.micro_f1)} / {fmt(r.base.macro_f1)}</td>
                        <td className="num mono worse">{fmt(r.replace.micro_f1)} / {fmt(r.replace.macro_f1)}</td>
                        <td className="num mono worse">{fmt(r.add.micro_f1)} / {fmt(r.add.macro_f1)}</td>
                        <td className="num mono">{r.fixed} / {r.broken}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            {a.auroc && (
              <div className="table-scroll">
                <table className="eval-table compact">
                  <thead><tr><th scope="col">Signal (AUROC for a wrong technique)</th><th className="num" scope="col">All incidents</th>
                    {Object.keys(a.within_technique || {}).map((t) => <th key={t} className="num" scope="col">Within {t}</th>)}</tr></thead>
                  <tbody>
                    {[['model_conf', "Model's technique confidence"], ['rag_combined', 'Retrieval signals', 'rag'], ['model_conf+rag', 'Both']].map(([k, label, wk]) => (
                      <tr key={k}>
                        <th scope="row">{label}</th>
                        <td className="num mono">{fmt(a.auroc[k])}</td>
                        {Object.entries(a.within_technique || {}).map(([t, v]) => <td key={t} className="num mono">{fmt(v[wk ?? k])}</td>)}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <p className="finding">{a.finding}</p>
          </div>
        ))}
      </div>
    </section>
  );
}

export default function Evaluation() {
  const [m, setM] = useState(null);
  const [error, setError] = useState(null);
  useEffect(() => { api.metrics().then(setM).catch((e) => setError(e.message)); }, []);

  if (error) return (<><ReplayStrip /><div className="page"><section className="panel empty">{error}</section></div></>);
  if (!m) return (<><ReplayStrip /><div className="page"><section className="panel empty">Loading metrics…</section></div></>);

  const models = (m.models || []).filter((x) => x.detection);
  const detectors = models.filter((x) => !/\+ RAG/.test(x.model));
  const rag = models.find((x) => x.retrieval || x.explanation);
  const row = (x, scores, note) => ({ name: SHORT[x.model] ?? x.model, full: x.description, kind: KIND[x.model] ?? 'Model', note, scores });
  const full = detectors.filter((x) => !isSample(x)).map((x) => row(x, flat(x), x.model === m.primary_model ? 'primary' : null));
  const shared = detectors.map((x) => (isSample(x) ? row(x, flat(x)) : x.on_shared_sample ? row(x, x.on_shared_sample) : null)).filter(Boolean);
  const caveats = detectors.filter((x) => x.caveat);

  return (
    <>
      <ReplayStrip />
      <div className="page">
        <header className="page-head">
          <div>
            <h1>Evaluation</h1>
            <p>{m.primary_model ? <>Primary model: <strong>{m.primary_model}</strong>. {m.primary_reason}</> : 'Model comparison on the test split.'}</p>
          </div>
        </header>

        {shared.length > 1 && (
          <section className="panel">
            <div className="panel-head">
              <h2>All models on the shared sample</h2>
              <span className="small muted">7,882 test edges (5,000 normal + up to 1,000 per attack type); detection weighted back to the full split</span>
            </div>
            <ScoreTable rows={shared} caption="Scores on the shared sample" />
          </section>
        )}

        {full.length > 0 && (
          <section className="panel">
            <div className="panel-head">
              <h2>Graph models on the full test split</h2>
              <span className="small muted">{m.test_edges ? `${m.test_edges.toLocaleString('en-US')} edges, ` : ''}scored one window at a time, as the console runs them</span>
            </div>
            <ScoreTable rows={full} caption="Scores on the full test split" />
          </section>
        )}

        {rag && <ExplanationLayer m={rag} />}
        <Ablations items={m.rag_ablation} />

        {(caveats.length > 0 || m.notes?.length > 0) && (
          <section className="panel">
            <div className="panel-head"><h2>How to read these numbers</h2></div>
            <div className="panel-body">
              <ul className="notes">
                <li>Technique and tactic F1 are on true-attack edges. Macro F1 averages over the techniques present, so rare techniques weigh as much as common ones; micro F1 follows the common ones.</li>
                {caveats.map((x) => <li key={x.model}><strong>{x.model}:</strong> {x.caveat}{x.reported_in_notebook ? ` The training notebook reports F1 ${fmt(x.reported_in_notebook.f1)} (${x.reported_in_notebook.note}).` : ''}</li>)}
                {(m.notes || []).map((n) => <li key={n}>{n}</li>)}
              </ul>
            </div>
          </section>
        )}
      </div>
    </>
  );
}
