import { useEffect, useState } from 'react';
import { api } from '../api/client.js';
import { ReplayStrip } from '../components/ReplayBar.jsx';

// Model comparison from GET /metrics. Two test sets are kept apart: the full test split (graph models)
// and the 7,882-edge shared sample every model was scored on (the 7B LLMs are too slow for 69k edges).

// Team numbering: five detection models; RAG is a separate explanation layer on top of the live detector
const NUM = { GraphSAGE: 1, 'Mistral-7B multi-LoRA': 2, 'Qwen2.5-7B QLoRA': 3, HGT: 4, Laya: 5 };
const SHORT = { GraphSAGE: 'GraphSAGE', 'Mistral-7B multi-LoRA': 'Mistral (LoRA)', 'Qwen2.5-7B QLoRA': 'Qwen (QLoRA)', HGT: 'HGT', Laya: 'Laya', 'GNN + RAG': 'GraphSAGE + RAG layer' };
const ORDER = ['GraphSAGE', 'Mistral-7B multi-LoRA', 'Qwen2.5-7B QLoRA', 'HGT', 'Laya'];
const label = (name) => (NUM[name] ? `Model ${NUM[name]} · ${SHORT[name]}` : SHORT[name] ?? name);

const fmt = (v) => (v == null ? '—' : Number(v).toFixed(3));
const pct = (v) => (v == null ? '—' : `${Math.round(v * 100)}%`);
const delta = (v) => (v == null ? '—' : `${v > 0.0005 ? '+' : v < -0.0005 ? '−' : '±'}${Math.abs(v).toFixed(3)}`);
const isSample = (m) => /sample/i.test(m.test_set || '');

function flat(m) {
  const d = m.detection || {};
  const t = m.technique || {};
  return { precision: d.precision, recall: d.recall, f1: d.f1 ?? d.macro_f1, pr_auc: d.pr_auc, roc_auc: d.roc_auc,
    tactic_micro_f1: t.tactic_micro_f1, tactic_macro_f1: t.tactic_macro_f1,
    technique_micro_f1: t.micro_f1, technique_macro_f1: t.macro_f1 };
}

/** Scores per model on one test set (pilot results are shown separately; 'GNN + RAG' only for the RAG comparison). */
function scoresOn(m, set, names = ORDER) {
  const byName = Object.fromEntries((m.models || []).map((x) => [x.model, x]));
  const rows = [];
  for (const name of names) {
    const x = byName[name];
    if (!x?.detection || x.pilot) continue;
    let s = null;
    if (set === 'sample') s = isSample(x) ? flat(x) : x.on_shared_sample ?? (name === 'GNN + RAG' ? byName.GraphSAGE?.on_shared_sample : null);
    else s = isSample(x) ? null : flat(x);
    if (s) rows.push({ name, scores: s, primary: name === m.primary_model });
  }
  return rows;
}

function PilotPanel({ m, cols }) {
  const pilots = (m.models || []).filter((x) => x.pilot && x.detection);
  if (!pilots.length) return null;
  return (
    <section className="panel">
      <div className="panel-head"><h2>Pilot results</h2><span className="small muted">Different test rows and metric definitions, so not comparable with the tables above yet</span></div>
      <div className="table-scroll">
        <table className="eval-table compact">
          <thead><tr><th scope="col">Model</th>{cols.map(([k, l]) => <th key={k} scope="col" className="num">{l}</th>)}</tr></thead>
          <tbody>
            {pilots.map((x) => (
              <tr key={x.model}><th scope="row">{label(x.model)}</th>{cols.map(([k]) => <td key={k} className="num mono">{fmt(flat(x)[k])}</td>)}</tr>
            ))}
          </tbody>
        </table>
      </div>
      {pilots.map((x) => <p key={x.model} className="small muted" style={{ margin: 0, padding: '10px 20px 16px' }}>{label(x.model)}: {x.test_set}</p>)}
      {cols === DETECTION && pilots.filter((x) => x.pilot_variants).map((x) => (
        <div key={x.model + '-v'} className="panel-body">
          <h3 className="mini-head">{label(x.model)}: zero-shot vs fine-tuned on the pilot (attack detection)</h3>
          <div className="table-scroll">
            <table className="eval-table compact">
              <thead><tr><th scope="col">Variant</th>{['Precision', 'Recall', 'F1', 'PR-AUC'].map((h) => <th key={h} scope="col" className="num">{h}</th>)}</tr></thead>
              <tbody>
                {x.pilot_variants.map((v) => (
                  <tr key={v.variant}><th scope="row">{v.variant}</th>{['precision', 'recall', 'f1', 'pr_auc'].map((k) => <td key={k} className="num mono">{fmt(v[k])}</td>)}</tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="small muted" style={{ margin: '8px 0 0' }}>On the pilot, the base model with tuned thresholds already detects well; fine-tuning mainly adds tactic and technique answers.</p>
        </div>
      ))}
    </section>
  );
}

const DETECTION = [['precision', 'Precision'], ['recall', 'Recall'], ['f1', 'F1'], ['pr_auc', 'PR-AUC'], ['roc_auc', 'ROC-AUC']];
const TECHNIQUE = [['tactic_micro_f1', 'Tactic micro-F1'], ['tactic_macro_f1', 'Tactic macro-F1'], ['technique_micro_f1', 'Technique micro-F1'], ['technique_macro_f1', 'Technique macro-F1']];

function MetricTable({ rows, cols, note }) {
  const shown = cols.filter(([k]) => rows.some((r) => r.scores[k] != null));
  const best = Object.fromEntries(shown.map(([k]) => [k, Math.max(...rows.map((r) => r.scores[k] ?? -1))]));
  return (
    <section className="panel eval-main">
      <div className="table-scroll">
        <table className="eval-table">
          <thead><tr><th scope="col">Model</th>{shown.map(([k, l]) => <th key={k} scope="col" className="num">{l}</th>)}</tr></thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.name} className={r.primary ? 'is-primary' : ''}>
                <th scope="row">{label(r.name)}{r.primary && ' (primary)'}</th>
                {shown.map(([k]) => {
                  const v = r.scores[k];
                  return <td key={k} className={`num mono${v != null && v === best[k] && rows.length > 1 ? ' is-best' : ''}`}>{fmt(v)}</td>;
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="small muted" style={{ margin: 0, padding: '12px 20px 16px' }}>Best value in each column in blue. {note}</p>
    </section>
  );
}

function BarPanel({ title, rows, k, note }) {
  const max = Math.max(...rows.map((r) => r.scores[k] ?? 0), 0.0001);
  return (
    <section className="panel eval-side">
      <div className="panel-head"><h2>{title}</h2></div>
      <div className="panel-body" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        {rows.map((r) => (
          <div key={r.name} className="eval-bar-row">
            <div className="eval-bar-label"><span>{label(r.name)}</span><span className="mono">{fmt(r.scores[k])}</span></div>
            <div className="eval-bar"><span style={{ width: `${((r.scores[k] ?? 0) / max) * 100}%` }} className={r.primary ? 'is-primary' : ''} /></div>
          </div>
        ))}
        <span className="small muted">{note}</span>
      </div>
    </section>
  );
}

function SetToggle({ set, onChange }) {
  return (
    <div className="seg" role="group" aria-label="Test set">
      <button type="button" aria-pressed={set === 'sample'} onClick={() => onChange('sample')}>Shared sample · all models</button>
      <button type="button" aria-pressed={set === 'full'} onClick={() => onChange('full')}>Full test split · graph models</button>
    </div>
  );
}

const SET_NOTE = {
  sample: '7,882 test edges (5,000 normal + up to 1,000 per attack type); detection weighted back to the full split.',
  full: '69,161 test edges, scored one window at a time as the console runs them. The 7B LLMs were only scored on the shared sample.',
};

function Comparisons({ m }) {
  const get = (set, name) => scoresOn(m, set, [...ORDER, 'GNN + RAG']).find((r) => r.name === name)?.scores;
  const cards = [
    { a: 'GNN + RAG', b: 'GraphSAGE', set: 'full', q: 'Does adding the RAG layer change detection?', extra: 'RAG adds cited explanations, not new predictions.' },
    { a: 'HGT', b: 'GraphSAGE', set: 'full', q: 'Graph transformer vs GraphSAGE on the same window graphs' },
    { a: 'Qwen2.5-7B QLoRA', b: 'Mistral-7B multi-LoRA', set: 'sample', q: 'Which fine-tuned LLM is better?' },
    { a: 'Mistral-7B multi-LoRA', b: 'GraphSAGE', set: 'sample', q: 'Fine-tuned LLM vs graph model on the same edges' },
  ].map((c) => ({ ...c, sa: get(c.set, c.a), sb: get(c.set, c.b) })).filter((c) => c.sa && c.sb);
  if (!cards.length) return null;
  const tone = (v) => (v > 0.0005 ? 'up' : v < -0.0005 ? 'down' : '');
  return (
    <section>
      <h2 className="eval-sub">Key comparisons</h2>
      <div className="eval-cards">
        {cards.map((c) => {
          const f1 = c.sa.f1 - c.sb.f1;
          const tech = (c.sa.technique_macro_f1 ?? 0) - (c.sb.technique_macro_f1 ?? 0);
          return (
            <div key={c.a + c.b} className="panel eval-card">
              <strong>{label(c.a)} vs {label(c.b)}</strong>
              <span className="muted">{c.q}</span>
              <span>Detection F1 change <span className={`mono delta ${tone(f1)}`}>{delta(f1)}</span></span>
              <span>Technique macro-F1 change <span className={`mono delta ${tone(tech)}`}>{delta(tech)}</span></span>
              <span className="small muted">{c.extra ?? (c.set === 'sample' ? 'On the shared sample' : 'On the full test split')}</span>
            </div>
          );
        })}
      </div>
    </section>
  );
}

function download(m) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(m, null, 2)], { type: 'application/json' }));
  const a = document.createElement('a');
  a.href = url; a.download = 'metrics.json'; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
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

const JUDGE = [
  ['contextual_precision', 'Contextual precision', 'Retriever', 'Evidence useful for the true technique is ranked above the rest'],
  ['contextual_recall', 'Contextual recall', 'Retriever', 'Key statements of the true technique that the evidence supports'],
  ['contextual_relevancy', 'Contextual relevancy', 'Retriever', 'Retrieved evidence relevant to the incident'],
  ['faithfulness', 'Faithfulness', 'Generator', 'Explanation claims supported by the incident record or the evidence'],
  ['answer_relevancy', 'Answer relevancy', 'Generator', 'Explanation sentences that address the incident'],
];

function RagJudge({ j }) {
  return (
    <div className="panel-body" style={{ paddingTop: 16 }}>
      <h3 className="mini-head">RAG metrics with an LLM judge ({j.incidents} incidents; judge {j.judge_model})</h3>
      <div className="table-scroll">
        <table className="eval-table compact">
          <thead><tr><th scope="col">Metric</th><th scope="col">Part</th><th scope="col">Measures</th>
            <th className="num" scope="col">All</th><th className="num" scope="col">Technique right</th><th className="num" scope="col">Technique wrong</th></tr></thead>
          <tbody>
            {JUDGE.map(([k, name, part, what]) => (
              <tr key={k}>
                <th scope="row">{name}</th><td className="small muted">{part}</td><td className="small muted">{what}</td>
                <td className="num mono">{fmt(j.all?.[k])}</td>
                <td className="num mono">{fmt(j.technique_right?.[k])}</td>
                <td className={`num mono${(j.technique_wrong?.[k] ?? 1) < 0.5 ? ' worse' : ''}`}>{fmt(j.technique_wrong?.[k])}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="finding" style={{ marginTop: 10 }}>The generator stays faithful ({fmt(j.all?.faithfulness)}; {j.unsupported_claims_per_explanation} unsupported claims per explanation). Retrieval is strong when the detector's technique is right and finds nothing useful when it is wrong, because evidence is retrieved for the predicted technique.</p>
    </div>
  );
}

function ExplanationLayer({ m }) {
  const r = m.retrieval || {};
  const e = m.explanation || {};
  const j = m.rag_judge;
  const q = [['Event queries', r.golden_event_queries], ['Technique queries', r.golden_technique_queries]].filter(([, v]) => v);
  return (
    <section className="panel">
      <div className="panel-head"><h2>RAG explanation layer (on {m.model === 'GNN + RAG' ? 'GraphSAGE' : m.model})</h2><span className="small muted">Detection is unchanged by RAG; these measure the explanation</span></div>
      <div className="kpis" style={{ borderTop: '1px solid var(--border)', borderBottom: '1px solid var(--border)' }}>
        {j?.all?.faithfulness != null && <Stat label="Faithfulness" value={fmt(j.all.faithfulness)} sub="Explanation claims supported by the input (LLM judge)" />}
        <Stat label="Groundedness" value={e.groundedness != null ? fmt(e.groundedness) : 'Not run yet'}
          sub="Share of explanation sentences that cite evidence" />
        <Stat label="GNNExplainer: top-5 features" value={e.gnnexplainer_logit_drop_top5 != null ? `−${fmt(e.gnnexplainer_logit_drop_top5)}` : '—'}
          sub={e.gnnexplainer_logit_drop_random5 != null ? `logit drop when removed, vs −${fmt(e.gnnexplainer_logit_drop_random5)} for 5 random` : null} />
        <Stat label="Top features beat random" value={pct(e.gnnexplainer_top_beats_random)} sub="of incidents" />
        {r.behaviour_check_hit_at_5_range && (
          <Stat label="Behaviour check hit@5" value={r.behaviour_check_hit_at_5_range.map(fmt).join('–')} sub="leave-one-family-out, by attack family" />
        )}
      </div>
      {m.rag_judge && <RagJudge j={m.rag_judge} />}
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

const TABS = [['detection', 'Detection'], ['technique', 'Technique'], ['rag', 'RAG & explanation'], ['ablation', 'RAG ablation']];

export default function Evaluation() {
  const [m, setM] = useState(null);
  const [error, setError] = useState(null);
  const [tab, setTab] = useState('detection');
  const [set, setSet] = useState('sample');
  useEffect(() => { api.metrics().then(setM).catch((e) => setError(e.message)); }, []);

  if (error) return (<><ReplayStrip /><div className="page"><section className="panel empty">{error}</section></div></>);
  if (!m) return (<><ReplayStrip /><div className="page"><section className="panel empty">Loading metrics…</section></div></>);

  const rows = scoresOn(m, set);
  const rag = (m.models || []).find((x) => x.retrieval || x.explanation);
  const caveats = (m.models || []).filter((x) => x.caveat);
  const attackShare = m.test_attack_edges && m.test_edges ? m.test_attack_edges / m.test_edges : null;

  return (
    <>
      <ReplayStrip />
      <div className="page">
        <header className="page-head">
          <div>
            <h1>Evaluation</h1>
            <p>Five detection models on the same test data, and the RAG layer that explains the live detector. Sources the RAG pipeline cites are on the Knowledge base page.</p>
          </div>
          <button className="btn" onClick={() => download(m)}>Download metrics</button>
        </header>

        <section className="panel eval-hero">
          <div>
            <span className="small muted">Primary model in the console</span>
            <strong className="eval-hero-name">{label(m.primary_model)}</strong>
            <span className="muted small">with the RAG explanation layer</span>
          </div>
          <p className="muted" style={{ margin: 0 }}>{m.primary_reason}</p>
          <div className="eval-hero-stats">
            {m.test_edges && <div><span className="small muted">Test edges</span><strong className="mono">{m.test_edges.toLocaleString('en-US')}</strong></div>}
            {attackShare != null && <div><span className="small muted">Attack share</span><strong className="mono">{(attackShare * 100).toFixed(1)}%</strong></div>}
          </div>
        </section>

        <div role="tablist" className="tabs">
          {TABS.map(([k, l]) => <button key={k} role="tab" className="tab" aria-selected={tab === k} onClick={() => setTab(k)}>{l}</button>)}
        </div>

        {(tab === 'detection' || tab === 'technique') && (
          <>
            <SetToggle set={set} onChange={setSet} />
            <div className="eval-grid">
              {tab === 'detection' ? (
                <>
                  <MetricTable rows={rows} cols={DETECTION} note={SET_NOTE[set]} />
                  <BarPanel title="Detection F1" rows={rows} k="f1" note="Attack vs normal. Higher is better." />
                </>
              ) : (
                <>
                  <MetricTable rows={rows} cols={TECHNIQUE} note={`${SET_NOTE[set]} Tactic and technique F1 are on true-attack edges; macro-F1 weighs rare techniques as much as common ones.`} />
                  <BarPanel title="Technique macro-F1" rows={rows} k="technique_macro_f1" note="Rare techniques count as much as common ones. Higher is better." />
                </>
              )}
            </div>
            <PilotPanel m={m} cols={tab === 'detection' ? DETECTION : TECHNIQUE} />
          </>
        )}
        {tab === 'rag' && (rag ? <ExplanationLayer m={rag} /> : <section className="panel empty">No explanation metrics yet.</section>)}
        {tab === 'ablation' && (m.rag_ablation?.length ? <Ablations items={m.rag_ablation} /> : <section className="panel empty">No ablation results yet.</section>)}

        <Comparisons m={m} />

        {(caveats.length > 0 || m.notes?.length > 0) && (
          <details className="panel eval-notes">
            <summary>How to read these numbers</summary>
            <ul className="notes">
              <li>Technique and tactic F1 are on true-attack edges. Macro F1 averages over the techniques present, so rare techniques weigh as much as common ones; micro F1 follows the common ones.</li>
              {caveats.map((x) => <li key={x.model}><strong>{x.model}:</strong> {x.caveat}{x.reported_in_notebook ? ` The training notebook reports F1 ${fmt(x.reported_in_notebook.f1)} (${x.reported_in_notebook.note}).` : ''}</li>)}
              {(m.notes || []).map((n) => <li key={n}>{n}</li>)}
            </ul>
          </details>
        )}
      </div>
    </>
  );
}
