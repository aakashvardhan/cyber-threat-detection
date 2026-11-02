import { useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { api } from '../api/client.js';
import { ReplayStrip } from '../components/ReplayBar.jsx';

// Everything the RAG pipeline can cite, by ATT&CK technique (GET /knowledge-base, /knowledge-base/{id}).

const SOURCES = [
  { key: 'procedure', label: 'Procedures', what: 'ATT&CK procedure examples: how named groups and campaigns used the technique' },
  { key: 'cti', label: 'CTI', what: 'Threat-intelligence report chunks linked to the technique' },
  { key: 'cve', label: 'CVE', what: 'Vulnerability records linked to the technique' },
];
const SOURCE_TOTAL_LABEL = { mitre: 'ATT&CK techniques', procedure: 'Procedure examples', cti: 'CTI chunks', cve: 'CVE records' };

function Detail({ id, onClose }) {
  const [page, setPage] = useState(null);
  const [error, setError] = useState(null);
  const [tab, setTab] = useState(null);
  useEffect(() => {
    setPage(null); setError(null);
    api.knowledgeTechnique(id).then((p) => {
      setPage(p);
      setTab(SOURCES.find((s) => p.counts[s.key] > 0)?.key ?? 'procedure');
    }).catch((e) => setError(e.message));
  }, [id]);

  if (error) return <section className="panel kb-detail empty">{error}</section>;
  if (!page) return <section className="panel kb-detail empty">Loading {id}…</section>;
  const items = page.items[tab] ?? [];
  return (
    <section className="panel kb-detail" aria-label={`${page.technique_id} ${page.name}`}>
      <div className="panel-head">
        <div>
          <span className="mono muted">{page.technique_id}</span>
          <h2 style={{ marginTop: 2 }}>{page.name}</h2>
        </div>
        <button className="btn btn-sm btn-ghost" onClick={onClose} aria-label="Close details">Close</button>
      </div>
      <div className="panel-body" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
        <div className="chips" style={{ marginTop: 0 }}>
          {page.tactics.map((t) => <span key={t} className="tag">{t}</span>)}
          {page.url && <a className="small" href={page.url} target="_blank" rel="noreferrer">Open on MITRE ATT&CK ↗</a>}
        </div>
        <p className="kb-desc">{page.description}</p>
        {page.mitigations.length > 0 && (
          <div>
            <h3 className="mini-head">Mitigations</h3>
            <ul className="kb-list">{page.mitigations.map((m) => <li key={m.mitigation_id}><span className="mono muted">{m.mitigation_id}</span> {m.name}</li>)}</ul>
          </div>
        )}
        {page.subtechniques.length > 0 && (
          <div>
            <h3 className="mini-head">Sub-techniques</h3>
            <ul className="kb-list">{page.subtechniques.map((s) => <li key={s.technique_id}><span className="mono muted">{s.technique_id}</span> {s.name}</li>)}</ul>
          </div>
        )}
        <div>
          <div role="tablist" className="tabs">
            {SOURCES.map((s) => (
              <button key={s.key} role="tab" className="tab" aria-selected={tab === s.key} title={s.what} onClick={() => setTab(s.key)}>
                {s.label}<span className="count">{page.counts[s.key].toLocaleString('en-US')}</span>
              </button>
            ))}
          </div>
          {items.length === 0 ? (
            <p className="small muted" style={{ marginTop: 12 }}>Nothing from this source is linked to {page.technique_id}; retrieval falls back to other techniques of the same tactic.</p>
          ) : (
            <ul className="kb-items">
              {items.map((it) => (
                <li key={it.id}>
                  <div className="kb-item-head">
                    <strong>{it.title}</strong>
                    {it.url ? <a className="mono small" href={it.url} target="_blank" rel="noreferrer">{it.ref}</a> : <span className="mono small muted">{it.ref}</span>}
                  </div>
                  <p>{it.text}</p>
                </li>
              ))}
              {page.counts[tab] > items.length && <li className="small muted">Showing {items.length} of {page.counts[tab].toLocaleString('en-US')}.</li>}
            </ul>
          )}
        </div>
      </div>
    </section>
  );
}

export default function KnowledgeBase() {
  const [kb, setKb] = useState(null);
  const [error, setError] = useState(null);
  const [params, setParams] = useSearchParams();
  const [query, setQuery] = useState('');
  const [tactic, setTactic] = useState('');
  const [detectorOnly, setDetectorOnly] = useState(false);
  const selected = params.get('t');

  useEffect(() => { api.knowledgeBase().then(setKb).catch((e) => setError(e.message)); }, []);

  const tactics = useMemo(() => [...new Set((kb?.techniques ?? []).flatMap((t) => t.tactics))].sort(), [kb]);
  const shown = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (kb?.techniques ?? []).filter((t) => (!q || t.technique_id.toLowerCase().includes(q) || t.name.toLowerCase().includes(q))
      && (!tactic || t.tactics.includes(tactic)) && (!detectorOnly || t.detector_class));
  }, [kb, query, tactic, detectorOnly]);
  const select = (id) => setParams(id ? { t: id } : {}, { replace: true });

  return (
    <>
      <ReplayStrip />
      <div className="page">
        <header className="page-head">
          <div>
            <h1>Knowledge base</h1>
            <p>Everything the RAG pipeline can cite, by MITRE ATT&CK technique{kb ? ` · retrieval: ${kb.retrieval}` : ''}.</p>
          </div>
        </header>
        {error && <section className="panel empty">{error}</section>}
        {kb && (
          <>
            <section className="panel">
              <div className="kpis">
                {kb.sources.map((s) => (
                  <div key={s.source} className="kpi">
                    <span className="kpi-label">{SOURCE_TOTAL_LABEL[s.source] ?? s.source}</span>
                    <span className="kpi-value" style={{ fontSize: 24 }}>{s.items.toLocaleString('en-US')}</span>
                    <span className="kpi-sub muted">{s.source === 'mitre' ? 'techniques and sub-techniques' : `linked to ${s.techniques_linked} techniques`}</span>
                  </div>
                ))}
              </div>
            </section>
            <div className="kb-layout">
              <section className="panel kb-list-panel">
                <div className="filters">
                  <input className="ctl" type="search" placeholder="Search ID or name" aria-label="Search techniques"
                    value={query} onChange={(e) => setQuery(e.target.value)} />
                  <select className="ctl" aria-label="Tactic" value={tactic} onChange={(e) => setTactic(e.target.value)}>
                    <option value="">All tactics</option>
                    {tactics.map((t) => <option key={t} value={t}>{t}</option>)}
                  </select>
                  <label className="small" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <input type="checkbox" checked={detectorOnly} onChange={(e) => setDetectorOnly(e.target.checked)} />
                    Only techniques the model predicts
                  </label>
                  <span className="small muted" style={{ marginLeft: 'auto' }}>{shown.length} of {kb.techniques.length}</span>
                </div>
                <div className="table-scroll">
                  <table className="eval-table kb-table">
                    <thead>
                      <tr><th scope="col">Technique</th><th scope="col">Tactic</th>
                        {SOURCES.map((s) => <th key={s.key} scope="col" className="num" title={s.what}>{s.label}</th>)}
                        <th scope="col" className="num">Mitigations</th></tr>
                    </thead>
                    <tbody>
                      {shown.map((t) => (
                        <tr key={t.technique_id} className={selected === t.technique_id ? 'is-selected' : ''}
                          tabIndex={0} onClick={() => select(t.technique_id)}
                          onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); select(t.technique_id); } }}>
                          <th scope="row">
                            <span className="mono muted">{t.technique_id}</span> {t.name}
                            {t.detector_class && <span className="tag kb-model-tag" title="The detection models can predict this technique">model</span>}
                          </th>
                          <td className="small">{t.tactics.join(', ')}</td>
                          {SOURCES.map((s) => <td key={s.key} className={`num mono${t[s.key] ? '' : ' muted'}`}>{t[s.key] ? t[s.key].toLocaleString('en-US') : '0'}</td>)}
                          <td className={`num mono${t.mitigations ? '' : ' muted'}`}>{t.mitigations}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>
              {selected && <Detail id={selected} onClose={() => select(null)} />}
            </div>
          </>
        )}
      </div>
    </>
  );
}
