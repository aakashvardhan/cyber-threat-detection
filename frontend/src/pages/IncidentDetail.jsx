import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { api } from '../api/client.js';
import { ErrorNote, SeverityChip } from '../components/badges.jsx';
import EvidenceFunnel from '../components/EvidenceFunnel.jsx';
import WindowGraph from '../components/WindowGraph.jsx';
import { WarnTriangle } from '../components/icons.jsx';
import { useReplay } from '../state/ReplayContext.jsx';
import { bytes, dateTime, hhmm, num, pct, plural, prob, service, shortDate, timeSpan } from '../utils/format.js';
import { byPriority, NEXT_ACTION, REOPEN_TO, STATUSES, STATUS_LABEL, WORKFLOW, techniqueOf } from '../utils/incidents.js';

const POLL_MS = 2000;
const EDGE_PAGE = 10;
const SOURCE_LABEL = { mitre: 'MITRE', procedure: 'Procedure', cti: 'CTI-HAL', cve: 'CVE' };
const TABS = [['triage', 'Triage'], ['response', 'Response'], ['research', 'Research']];

export default function IncidentDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { incidents, refresh: refreshList } = useReplay();
  const [inc, setInc] = useState(null);
  const [loadError, setLoadError] = useState(null);
  const [actionError, setActionError] = useState(null);
  const [saving, setSaving] = useState(false);
  // The tab lives in the URL, so a refresh or a shared link opens the same tab.
  const [params, setParams] = useSearchParams();
  const tab = TABS.some(([k]) => k === params.get('tab')) ? params.get('tab') : 'triage';
  const setTab = (k) => setParams(k === 'triage' ? {} : { tab: k }, { replace: true });

  const load = useCallback(async (opts) => {
    try {
      setInc(await api.getIncident(id, opts));
      setLoadError(null);
    } catch (e) {
      setLoadError(e.status === 404 ? `${id} doesn't exist. The backend may have restarted, which clears incidents.` : e.message);
    }
  }, [id]);

  useEffect(() => { setInc(null); load(); }, [load]);

  // The explanation is written in the background; poll until it is ready.
  useEffect(() => {
    if (inc?.explanation?.status !== 'generating') return undefined;
    const t = setTimeout(load, POLL_MS);
    return () => clearTimeout(t);
  }, [inc, load]);

  // Previous / next in the same order as the incident list.
  const order = useMemo(() => [...incidents].sort(byPriority).map((i) => i.incident_id), [incidents]);
  const pos = order.indexOf(id);

  async function update(change) {
    setSaving(true);
    setActionError(null);
    try {
      await api.updateIncident(id, change);
      await Promise.all([load(), refreshList()]);
    } catch (e) {
      setActionError(e.message);
    } finally {
      setSaving(false);
    }
  }

  if (loadError) {
    return <div className="page"><Breadcrumb id={id} /><ErrorNote message={loadError} onRetry={() => load()} /></div>;
  }
  if (!inc) return <div className="page"><Breadcrumb id={id} /><p className="muted">Loading {id}…</p></div>;

  const next = NEXT_ACTION[inc.status];
  const technique = techniqueOf(inc);

  return (
    <>
      <section className="detail-head" aria-label="Incident summary and actions">
        <div className="detail-top">
          <Breadcrumb id={id} />
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="btn btn-sm" disabled={pos <= 0} onClick={() => navigate(`/incidents/${order[pos - 1]}`)}>Previous</button>
            <button className="btn btn-sm" disabled={pos < 0 || pos >= order.length - 1} onClick={() => navigate(`/incidents/${order[pos + 1]}`)}>Next</button>
          </div>
        </div>
        <div className="detail-main">
          <div style={{ minWidth: 0 }}>
            <h1>{inc.technique_name}</h1>
            <p className="muted" style={{ marginTop: 6 }}>
              From <span className="mono" style={{ color: 'var(--text)' }}>{inc.source_ip}</span> to {plural(inc.target_count, 'host')}
              <span className="sep">{plural(inc.edge_count, 'edge')}</span>
              <span className="sep">{timeSpan(inc.first_seen, inc.last_seen)}</span>
            </p>
            <div className="chips">
              {inc.verdict === 'attack'
                ? <span className="sev sev-high"><WarnTriangle fill="var(--on-accent)" on="var(--sev-high)" />Attack</span>
                : <span className="sev sev-low">Normal</span>}
              <span className="tag">Attack probability <strong className="mono">{prob(inc.max_attack_probability)}</strong></span>
              <SeverityChip severity={inc.severity} />
              <span className="tag">Confidence <strong className={inc.low_confidence ? 'warn-text' : ''}>{inc.low_confidence ? 'low' : 'normal'}</strong></span>
            </div>
          </div>
          <div className="detail-actions">
            <div className="status" style={{ gap: 8, flexWrap: 'wrap' }}>
              <label className="status" style={{ gap: 8 }}>
                <span className="muted">Technique</span>
                <select className="ctl" value={technique} disabled={saving}
                  onChange={(e) => update({ technique_override: e.target.value === inc.technique_id ? null : e.target.value })}>
                  {inc.mitre_candidates.map((c) => (
                    <option key={c.technique_id} value={c.technique_id}>{c.technique_id} {c.technique_id === inc.technique_id ? '(model)' : `(${prob(c.confidence)})`}</option>
                  ))}
                  {!inc.mitre_candidates.some((c) => c.technique_id === technique) && <option value={technique}>{technique} (analyst)</option>}
                </select>
              </label>
              {inc.status !== 'dismissed' && inc.status !== 'closed' && (
                <button className="btn" disabled={saving} onClick={() => update({ status: 'dismissed' })}>Dismiss</button>
              )}
              {next && <button className="btn btn-primary" disabled={saving} onClick={() => update({ status: next.to })}>{next.label}</button>}
              {REOPEN_TO[inc.status] && (
                <button className="btn btn-primary" disabled={saving} onClick={() => update({ status: REOPEN_TO[inc.status] })}>
                  Reopen
                </button>
              )}
              <label className="status" style={{ gap: 8 }}>
                <span className="sr-only">Change status</span>
                <select className="ctl" value="" disabled={saving} title="Correct the status, for example after a mistaken click"
                  onChange={(e) => e.target.value && update({ status: e.target.value })}>
                  <option value="">Change status…</option>
                  {STATUSES.filter((s) => s !== inc.status).map((s) => <option key={s} value={s}>{STATUS_LABEL[s]}</option>)}
                </select>
              </label>
            </div>
            <ol className="stepper" aria-label="Status">
              {WORKFLOW.map((s) => {
                const reached = WORKFLOW.indexOf(inc.status) >= WORKFLOW.indexOf(s);
                return <li key={s} className={inc.status === s ? 'is-current' : reached ? 'is-done' : ''} aria-current={inc.status === s ? 'step' : undefined}>{STATUS_LABEL[s]}</li>;
              })}
              {inc.status === 'dismissed' && <li className="is-current">Dismissed</li>}
            </ol>
          </div>
        </div>
        <div role="tablist" className="tabs" style={{ borderBottom: 'none' }}>
          {TABS.map(([k, label]) => (
            <button key={k} role="tab" className="tab" aria-selected={tab === k} onClick={() => setTab(k)}>{label}</button>
          ))}
        </div>
      </section>

      <div className="page">
        <ErrorNote message={actionError} />
        {tab === 'triage' && (
          <Triage inc={inc} saving={saving} onRegenerate={() => load({ refresh: true })}
            onUseTechnique={(t) => update({ technique_override: t === inc.technique_id ? null : t })} />
        )}
        {tab === 'response' && <Response inc={inc} saving={saving} update={update} />}
        {tab === 'research' && <Research inc={inc} />}
      </div>
    </>
  );
}

function Breadcrumb({ id }) {
  return <div className="small"><Link to="/incidents">Incidents</Link><span className="muted"> / </span><span className="mono">{id}</span></div>;
}

/* ---------------- Triage ---------------- */

function Triage({ inc, saving, onRegenerate, onUseTechnique }) {
  const [selected, setSelected] = useState(0);
  const ex = inc.explanation || {};
  const sentences = ex.sentences || [];
  const cited = sentences.filter((s) => s.citations?.length).length;
  const active = new Set(sentences[selected]?.citations || []);
  const evidenceNo = Object.fromEntries(inc.evidence.map((e, i) => [e.evidence_id, i + 1]));

  return (
    <>
      <div className="row-wrap">
        <section className="panel" style={{ flex: '3 1 620px', minWidth: 0 }}>
          <div className="panel-head">
            <h2>Why it was flagged</h2>
            {ex.status === 'ready' && <span className="small muted">{cited} of {sentences.length} sentences cite evidence{ex.groundedness != null && ` · groundedness ${ex.groundedness.toFixed(2)}`}</span>}
          </div>
          <div className="panel-body">
            {ex.stale && (
              <div className="note note-warn" style={{ marginBottom: 14, display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
                <span>This incident gained {num(inc.edge_count - (ex.based_on_edge_count ?? inc.edge_count))} edges or changed technique after the explanation was written.</span>
                <button className="btn btn-sm" onClick={onRegenerate}>Regenerate</button>
              </div>
            )}
            {ex.status === 'error' && <div className="note note-error" style={{ marginBottom: 14 }}>The explanation couldn't be written: {ex.message || 'unknown error'}. <button className="btn btn-sm btn-ghost" onClick={onRegenerate}>Try again</button></div>}
            <div className="why">
              <div className="why-text">
                {ex.status === 'generating' && (
                  <div className="generating">
                    <span className="pulse" />Writing the explanation from {plural(inc.evidence.length, 'retrieved source')}. You can confirm or dismiss now; the evidence is on the right.
                  </div>
                )}
                {sentences.map((s, i) => (
                  <button key={i} className={`sentence ${i === selected ? 'is-selected' : ''}`} onClick={() => setSelected(i)} aria-pressed={i === selected}>
                    {s.text}{' '}
                    {s.citations?.length
                      ? <span className="mono cite">{s.citations.map((c) => `[${evidenceNo[c] ?? c}]`).join(' ')}</span>
                      : <span className="no-cite">No evidence cited</span>}
                  </button>
                ))}
                {ex.status === 'ready' && (
                  <p className="small muted" style={{ padding: '6px 12px 0' }}>
                    {ex.mode === 'llm' ? `Written by ${ex.model || 'the LLM'} from ${plural(inc.evidence.length, 'retrieved source')}.` : 'Evidence-only summary: no LLM is configured on the backend.'} Select a sentence to see its sources.
                  </p>
                )}
              </div>
              <div className="why-evidence">
                <span className="small muted">Evidence</span>
                {inc.evidence.map((e) => (
                  <article key={e.evidence_id} className={`evidence ${active.has(e.evidence_id) ? 'is-active' : ''}`}>
                    <div className="evidence-meta small">
                      <span className="mono" style={{ color: 'var(--accent)' }}>[{evidenceNo[e.evidence_id]}]</span>
                      <span className="tag">{SOURCE_LABEL[e.source] || e.source}</span>
                      <span className={`tag ${e.level === 'tactic' ? 'warn-text' : ''}`}>{e.level === 'tactic' ? 'Tactic fallback' : e.level === 'procedure' ? 'Procedure' : 'Technique'}</span>
                      <span className="mono muted" style={{ marginLeft: 'auto' }}>{e.score != null ? e.score.toFixed(2) : ''}</span>
                    </div>
                    <strong>{e.url ? <a href={e.url} target="_blank" rel="noreferrer">{e.title}</a> : e.title}</strong>
                    <p className="small muted clamp">{e.text}</p>
                  </article>
                ))}
                <p className="small muted">{inc.cve_status === 'applicable' ? 'CVE records were searched for this technique.' : 'No CVE applies to this technique.'}</p>
              </div>
            </div>
            <details className="trace" open>
              <summary>How the evidence was found</summary>
              <EvidenceFunnel trace={inc.retrieval_trace} explanation={ex} evidenceCount={inc.evidence.length} />
            </details>
          </div>
        </section>

        <div style={{ flex: '1 1 300px', minWidth: 0, display: 'flex', flexDirection: 'column', gap: 24 }}>
          <MitrePanel inc={inc} />
          <BehaviorPanel inc={inc} saving={saving} onUse={onUseTechnique} />
          <TrafficSummary edges={inc.edges} />
        </div>
      </div>
      <WindowGraph inc={inc} />
      <EdgesTable edges={inc.edges} />
    </>
  );
}

function MitrePanel({ inc }) {
  const top = inc.mitre_candidates[0];
  return (
    <section className="panel">
      <div className="panel-head"><h2>MITRE ATT&amp;CK</h2></div>
      <div className="panel-body" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
        {inc.mitre_candidates.map((c) => (
          <div key={c.technique_id} style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            <span style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
              <span><span className="mono muted">{c.technique_id}</span> {c.name}</span>
              <span className="mono">{prob(c.confidence)}</span>
            </span>
            <span className="bar-track"><span className="bar-fill" style={{ width: pct(c.confidence, 0), background: 'var(--accent)' }} /></span>
          </div>
        ))}
        <div className="divider" />
        <span style={{ display: 'flex', justifyContent: 'space-between' }}>
          <span className="muted">Tactic</span>
          <span>{inc.tactic_prediction?.label ?? inc.tactic} <span className="mono muted">{prob(inc.tactic_prediction?.confidence)}</span></span>
        </span>
        {inc.technique_override && <span className="small muted">Analyst changed the technique to <span className="mono">{inc.technique_override}</span>.</span>}
        {top && <a href={`https://attack.mitre.org/techniques/${top.technique_id.replace('.', '/')}`} target="_blank" rel="noreferrer">{top.technique_id} on MITRE ATT&amp;CK</a>}
      </div>
    </section>
  );
}

/** Techniques the traffic pattern itself matches, searched over all of ATT&CK without the model's technique. */
function BehaviorPanel({ inc, saving, onUse }) {
  const check = inc.retrieval_trace?.behavior_check;
  if (!check) return null;            // older backend without the behaviour check
  if (!check.candidates?.length) {
    return (
      <section className="panel" aria-label="Behaviour check">
        <div className="panel-head"><h2>Behaviour check</h2></div>
        <p className="panel-body small muted">No distinctive traffic pattern (scan, logins, web requests, large transfer) to compare with the model's technique.</p>
      </section>
    );
  }
  const current = techniqueOf(inc);
  const alt = check.candidates[0];
  return (
    <section className="panel" aria-label="Behaviour check">
      <div className="panel-head"><h2>Behaviour check</h2><span className="small muted">Traffic pattern vs all of ATT&amp;CK</span></div>
      <div className="panel-body" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        {check.agrees_with_detector === false ? (
          <div className="note note-warn">
            The traffic looks more like <strong>{alt.technique_id} {alt.name}</strong> than the model's {inc.technique_id}. Verify before acting.
          </div>
        ) : (
          <span className="small" style={{ color: 'var(--ok)' }}>The traffic pattern agrees with the model's technique.</span>
        )}
        <ul className="reading small muted">{check.reading.map((r) => <li key={r}>{r}</li>)}</ul>
        <ol className="check-list">
          {check.candidates.slice(0, 3).map((c) => (
            <li key={c.technique_id}>
              <span><span className="mono muted">{c.technique_id}</span> {c.name}
                {c.technique_id === inc.technique_id && <span className="tag" style={{ marginLeft: 6 }}>model</span>}</span>
              {c.technique_id !== current && (
                <button className="btn btn-sm btn-ghost" disabled={saving} onClick={() => onUse(c.technique_id)}
                  aria-label={`Use ${c.technique_id} as the technique`}>Use</button>
              )}
            </li>
          ))}
        </ol>
        <details className="small muted">
          <summary>Traffic facts searched</summary>
          <p className="mono small" style={{ marginTop: 6 }}>{check.facts}</p>
        </details>
      </div>
    </section>
  );
}

function TrafficSummary({ edges }) {
  const t = useMemo(() => {
    const s = { conn: 0, out: 0, in: 0, tcp: 0, udp: 0, icmp: 0 };
    for (const e of edges) {
      const f = e.traffic_features || {};
      s.conn += f.connection_count || 0;
      s.out += f.total_orig_bytes || 0;
      s.in += f.total_resp_bytes || 0;
      s.tcp += f.tcp_count || 0;
      s.udp += f.udp_count || 0;
      s.icmp += f.icmp_count || 0;
    }
    s.proto = s.tcp + s.udp + s.icmp;
    return s;
  }, [edges]);
  const parts = [['TCP', t.tcp, 'var(--accent)'], ['UDP', t.udp, 'var(--normal)'], ['ICMP', t.icmp, 'var(--sev-low)']].filter((p) => p[1] > 0);

  return (
    <section className="panel">
      <div className="panel-head"><h2>Traffic</h2><span className="small muted">All edges in this incident</span></div>
      <div className="panel-body" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
        <div className="stat-grid">
          <div><span className="small muted">Connections</span><strong className="stat">{num(t.conn)}</strong></div>
          <div><span className="small muted">Per edge</span><strong className="stat">{edges.length ? num(Math.round(t.conn / edges.length)) : '—'}</strong></div>
          <div><span className="small muted">Bytes out / in</span><span className="mono">{bytes(t.out)} / {bytes(t.in)}</span></div>
          <div><span className="small muted">Bytes per connection</span><span className="mono">{t.conn ? bytes(t.out / t.conn) : '—'}</span></div>
        </div>
        {t.proto > 0 && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            <span className="small muted">Protocol</span>
            <span className="stack-bar">{parts.map(([k, v, c]) => <span key={k} style={{ width: `${(v / t.proto) * 100}%`, background: c }} />)}</span>
            <span className="small muted" style={{ display: 'flex', gap: 12 }}>{parts.map(([k, v]) => <span key={k}>{k} {pct(v / t.proto, 0)}</span>)}</span>
          </div>
        )}
      </div>
    </section>
  );
}

function EdgesTable({ edges }) {
  const [shown, setShown] = useState(EDGE_PAGE);
  const newest = useMemo(() => [...edges].reverse(), [edges]);
  return (
    <section className="panel">
      <div className="panel-head"><h2>Edges in this incident</h2><span className="small muted">{plural(edges.length, 'edge')}, newest first</span></div>
      <div className="table-scroll">
        <div style={{ minWidth: 760 }}>
          <div className="edge-cols thead"><span>Window (UTC)</span><span>Target</span><span>Service</span><span>Connections</span><span>Bytes out / in</span><span>p</span></div>
          {newest.slice(0, shown).map((e) => (
            <div key={e.event_id} className="edge-cols trow mono">
              <span className="muted">{shortDate(e.window_start)} {hhmm(e.window_start)}</span>
              <span>{e.destination_ip}</span>
              <span>{service(e)}</span>
              <span>{num(e.traffic_features?.connection_count)}</span>
              <span>{bytes(e.traffic_features?.total_orig_bytes)} / {bytes(e.traffic_features?.total_resp_bytes)}</span>
              <span>{prob(e.attack_probability)}</span>
            </div>
          ))}
        </div>
      </div>
      {shown < newest.length && (
        <div style={{ padding: 16, display: 'flex', gap: 8 }}>
          <button className="btn" onClick={() => setShown(shown + 50)}>Show 50 more</button>
          <span className="small muted" style={{ alignSelf: 'center' }}>Showing {num(shown)} of {num(newest.length)}</span>
        </div>
      )}
    </section>
  );
}

/* ---------------- Response ---------------- */

function Response({ inc, saving, update }) {
  const [note, setNote] = useState('');
  // Show the tick at once; the server copy replaces it when the save returns.
  const [applied, setApplied] = useState(() => new Set(inc.mitigations_applied || []));
  useEffect(() => { setApplied(new Set(inc.mitigations_applied || [])); }, [inc.mitigations_applied]);
  const toggle = (m) => {
    const nextSet = new Set(applied);
    nextSet.has(m) ? nextSet.delete(m) : nextSet.add(m);
    setApplied(nextSet);
    update({ mitigations_applied: [...nextSet] });
  };

  return (
    <div className="row-wrap">
      <div style={{ flex: '3 1 560px', minWidth: 0, display: 'flex', flexDirection: 'column', gap: 24 }}>
        <section className="panel">
          <div className="panel-head"><h2>Recommended mitigations</h2><span className="small muted">From MITRE ATT&amp;CK; tick when applied</span></div>
          <div className="panel-body" style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {inc.mitigations.length === 0 && <p className="muted">ATT&amp;CK lists no mitigations for this technique.</p>}
            {inc.mitigations.map((m) => (
              <label key={m.mitigation_id} className="check-row">
                <input type="checkbox" checked={applied.has(m.mitigation_id)} disabled={saving} onChange={() => toggle(m.mitigation_id)} />
                <span><span className="mono muted">{m.mitigation_id}</span> {m.name}</span>
              </label>
            ))}
          </div>
        </section>
        <section className="panel">
          <div className="panel-head"><h2>Next steps</h2><span className="small muted">Written with the explanation</span></div>
          <div className="panel-body">
            {inc.explanation?.next_steps?.length
              ? <ol className="steps">{inc.explanation.next_steps.map((s, i) => <li key={i}>{s}</li>)}</ol>
              : <p className="muted">{inc.explanation?.status === 'generating' ? 'Being written…' : 'None suggested.'}</p>}
          </div>
        </section>
      </div>
      <div style={{ flex: '2 1 360px', minWidth: 0, display: 'flex', flexDirection: 'column', gap: 24 }}>
        <section className="panel">
          <div className="panel-head"><h2>Related incidents</h2><span className="small muted">Same source or shared targets</span></div>
          <div className="panel-body" style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
            {inc.related_incident_ids.length === 0 && <p className="muted">None.</p>}
            {inc.related_incident_ids.map((r) => <Link key={r} to={`/incidents/${r}`} className="tag mono">{r}</Link>)}
          </div>
        </section>
        <section className="panel">
          <div className="panel-head"><h2>Activity</h2></div>
          <div className="panel-body" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <form className="status" style={{ gap: 8 }} onSubmit={(e) => { e.preventDefault(); if (note.trim()) { update({ note: note.trim() }); setNote(''); } }}>
              <label htmlFor="note" className="sr-only">Add a note</label>
              <input id="note" className="ctl" style={{ flex: 1 }} placeholder="Add a note" value={note} onChange={(e) => setNote(e.target.value)} />
              <button className="btn" disabled={saving || !note.trim()}>Add</button>
            </form>
            {(inc.activity || []).length === 0 && <p className="small muted">No activity yet.</p>}
            {describeActivity(inc).reverse().map((a, i) => (
              <div key={i} className="activity">
                <span className="mono small muted">{dateTime(a.at)}</span>
                {a.lines.map((l, j) => <span key={j}>{l}</span>)}
                {a.note && <span className="muted">Note: {a.note}</span>}
              </div>
            ))}
            {(inc.activity || []).length > 0 && <p className="small muted">Times are when the analyst acted, not replay time.</p>}
          </div>
        </section>
      </div>
    </div>
  );
}

/** Turns the activity log into what actually changed in each entry.
    The API stores the full status on every entry, so compare each one with the state before it. */
function describeActivity(inc) {
  const names = Object.fromEntries(inc.mitigations.map((m) => [m.mitigation_id, m.name]));
  const label = (id) => `${id}${names[id] ? ` ${names[id]}` : ''}`;
  let status = 'new';
  let technique = null;
  let applied = [];
  return (inc.activity || []).map((a) => {
    const lines = [];
    if (a.status && a.status !== status) lines.push(`Status changed to ${STATUS_LABEL[a.status] || a.status}`);
    if (a.technique_override !== undefined && a.technique_override !== technique) {
      lines.push(a.technique_override ? `Technique set to ${a.technique_override}` : `Technique reset to the model's ${inc.technique_id}`);
      technique = a.technique_override;
    }
    if (Array.isArray(a.mitigations_applied)) {
      const added = a.mitigations_applied.filter((m) => !applied.includes(m));
      const removed = applied.filter((m) => !a.mitigations_applied.includes(m));
      added.forEach((m) => lines.push(`Applied ${label(m)}`));
      removed.forEach((m) => lines.push(`Unticked ${label(m)}`));
      applied = a.mitigations_applied;
    }
    status = a.status || status;
    if (!lines.length && !a.note) lines.push('Updated');
    return { at: a.at, lines: lines.map((l) => `${a.actor ? `${a.actor}: ` : ''}${l}`), note: a.note };
  });
}

/* ---------------- Research ---------------- */

function Research({ inc }) {
  return (
    <section className="panel">
      <div className="panel-head"><h2>How each model judged this incident</h2></div>
      <div className="panel-body" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
        <p className="note note-warn">The models share the same graph encoder, so agreement between them is not independent evidence.</p>
        <div className="table-scroll">
          <div style={{ minWidth: 640 }}>
            <div className="model-cols thead"><span>Model</span><span>Verdict</span><span>Attack probability</span><span>Top technique</span><span>Confidence</span><span>Groundedness</span></div>
            {inc.models.map((m) => (
              <div key={m.model} className="model-cols trow">
                <span className="mono">{m.model}</span>
                <span>{m.label === 'attack' ? <span style={{ color: 'var(--sev-high)', fontWeight: 600 }}>Attack</span> : 'Normal'}</span>
                <span className="mono">{prob(m.attack_probability)}</span>
                <span className="mono">{m.technique_id ?? '—'}</span>
                <span className="mono">{prob(m.confidence)}</span>
                <span className="mono">{prob(m.groundedness)}</span>
              </div>
            ))}
          </div>
        </div>
        {inc.models.length < 5 && <p className="small muted">Only {plural(inc.models.length, 'model')} reported. The other models appear here once the evaluation notebooks export model_outputs.jsonl to the backend.</p>}
      </div>
    </section>
  );
}
