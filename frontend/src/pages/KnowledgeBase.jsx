import { useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { api } from '../api/client.js';
import { ReplayStrip } from '../components/ReplayBar.jsx';

// Everything the RAG pipeline can cite, by ATT&CK technique (GET /knowledge-base, /knowledge-base/{id}).
// The list starts with the techniques the live model predicts; "technique level" = procedure + CTI chunks
// linked to the technique itself; with none, retrieval falls back to other techniques of the same tactic.

const SOURCES = [
  { key: 'procedure', card: 'procedure', label: 'Procedures', title: 'ATT&CK procedures', unit: 'procedure chunks', what: 'Real examples of each technique' },
  { key: 'cti', card: 'cti', label: 'CTI-HAL', title: 'CTI-HAL', unit: 'report chunks', what: 'Threat reports linked to techniques' },
  { key: 'cve', card: 'cve', label: 'CVE', title: 'CVE', unit: 'entries', what: 'Only searched for exploit techniques' },
];
const LEVEL = { procedure: 'Technique level', cti: 'Technique level', cve: 'Vulnerability' };

const techniqueLevel = (t) => (t.procedure || 0) + (t.cti || 0);
const fmt = (n) => (n ?? 0).toLocaleString('en-US');

function firstSentences(text, n = 2) {
  const parts = (text || '').match(/[^.!?]+[.!?]+/g) || [text || ''];
  return parts.slice(0, n).join('').trim();
}

function SourceCards({ kb }) {
  const by = Object.fromEntries(kb.sources.map((s) => [s.source, s]));
  const links = kb.techniques.reduce((sum, t) => sum + t.mitigations, 0);
  const cards = [
    { key: 'mitre', title: 'MITRE ATT&CK', n: by.mitre?.items, unit: `techniques and sub-techniques, ${fmt(links)} technique–mitigation links`, what: 'Definitions and mitigations' },
    ...SOURCES.map((s) => ({ key: s.key, title: s.title, n: by[s.card]?.items, unit: `${s.unit}, linked to ${fmt(by[s.card]?.techniques_linked)} techniques`, what: s.what })),
  ];
  return (
    <div className="kb-cards">
      {cards.map((c) => (
        <section key={c.key} className="panel kb-card">
          <span className={`kb-card-title src-${c.key}`}>{c.title}</span>
          <strong className="kb-card-n">{fmt(c.n)}</strong>
          <span className="small muted">{c.unit}</span>
          <span className="kb-card-what">{c.what}</span>
        </section>
      ))}
    </div>
  );
}

function TechniqueList({ kb, selected, onSelect }) {
  const [query, setQuery] = useState('');
  const [all, setAll] = useState(false);
  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return kb.techniques
      .filter((t) => (all || t.detector_class) && (!q || t.technique_id.toLowerCase().includes(q) || t.name.toLowerCase().includes(q)))
      .sort((a, b) => techniqueLevel(b) - techniqueLevel(a) || a.technique_id.localeCompare(b.technique_id));
  }, [kb, query, all]);
  const max = Math.max(1, ...rows.map(techniqueLevel));
  const predicted = kb.techniques.filter((t) => t.detector_class).length;

  return (
    <section className="panel kb-list-panel">
      <div className="panel-head" style={{ flexDirection: 'column', alignItems: 'stretch' }}>
        <h2>{all ? 'All ATT&CK techniques' : 'Techniques the model predicts'}</h2>
        <span className="small muted">Number = technique-level chunks (procedures + CTI). Amber = no technique-level evidence, so retrieval falls back to the tactic. Select one to browse its sources.</span>
      </div>
      <div className="panel-body" style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        <input className="ctl" type="search" placeholder="Filter by ID or name" aria-label="Search techniques"
          value={query} onChange={(e) => setQuery(e.target.value)} />
        <label className="small" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <input type="checkbox" checked={all} onChange={(e) => setAll(e.target.checked)} />
          Show all ATT&CK techniques ({kb.techniques.length}) instead of the {predicted} the model predicts
        </label>
        <ul className="kb-tech-list">
          {rows.map((t) => {
            const n = techniqueLevel(t);
            const fallback = n === 0;
            return (
              <li key={t.technique_id}>
                <button type="button" className={`kb-tech${selected === t.technique_id ? ' is-selected' : ''}`}
                  aria-pressed={selected === t.technique_id} onClick={() => onSelect(t.technique_id)}>
                  <span className="kb-tech-name"><span className="mono muted">{t.technique_id}</span> {t.name}</span>
                  <span className="kb-tech-count">
                    <strong className="mono">{fmt(n)}</strong>
                    <span className={`small ${fallback ? 'kb-fallback' : 'muted'}`}>{fallback ? 'Tactic fallback' : 'Technique level'}</span>
                  </span>
                  <span className="kb-bar"><span style={{ width: `${fallback ? 4 : Math.max(3, (n / max) * 100)}%`, background: fallback ? 'var(--sev-medium)' : 'var(--accent)' }} /></span>
                </button>
              </li>
            );
          })}
          {rows.length === 0 && <li className="small muted">No technique matches.</li>}
        </ul>
        <div className="kb-legend small muted">
          <span><i style={{ background: 'var(--accent)' }} />Technique-level chunks</span>
          <span><i style={{ background: 'var(--sev-medium)' }} />Tactic fallback only</span>
        </div>
      </div>
    </section>
  );
}

function Detail({ id }) {
  const [page, setPage] = useState(null);
  const [error, setError] = useState(null);
  const [tab, setTab] = useState('mitre');
  useEffect(() => {
    setPage(null); setError(null);
    api.knowledgeTechnique(id).then((p) => {
      setPage(p);
      setTab(SOURCES.find((s) => p.counts[s.key] > 0)?.key ?? 'mitre');
    }).catch((e) => setError(e.message));
  }, [id]);

  if (error) return <section className="panel kb-detail empty">{error}</section>;
  if (!page) return <section className="panel kb-detail empty">Loading {id}…</section>;
  const tabs = [{ key: 'mitre', label: 'MITRE', n: 1 + page.mitigations.length }, ...SOURCES.map((s) => ({ key: s.key, label: s.label, n: page.counts[s.key] }))];
  const items = page.items[tab] ?? [];
  const source = SOURCES.find((s) => s.key === tab);

  return (
    <section className="panel kb-detail" aria-label={`${page.technique_id} ${page.name}`}>
      <div className="panel-body" style={{ paddingTop: 18, display: 'flex', flexDirection: 'column', gap: 12 }}>
        <span className="mono muted small">{page.technique_id} · {page.tactics.join(', ')}</span>
        <h2 style={{ margin: 0 }}>{page.name}</h2>
        <p className="muted" style={{ margin: 0 }}>{firstSentences(page.description)}</p>
        {page.url && <a className="btn btn-sm" style={{ alignSelf: 'flex-start' }} href={page.url} target="_blank" rel="noreferrer">Open on MITRE ATT&CK ↗</a>}
        <div role="tablist" className="tabs">
          {tabs.map((t) => (
            <button key={t.key} role="tab" className="tab" aria-selected={tab === t.key} onClick={() => setTab(t.key)}>
              {t.label}<span className="count">{fmt(t.n)}</span>
            </button>
          ))}
        </div>

        {tab === 'mitre' ? (
          <div className="kb-items" style={{ marginTop: 0 }}>
            <div className="kb-item">
              <div className="kb-item-head"><span className="mono small muted">{page.technique_id}</span><span className="tag">Definition</span></div>
              <strong>{page.name}</strong>
              <p>{page.description}</p>
              {page.platforms.length > 0 && <p className="small">Platforms: {page.platforms.join(', ')}</p>}
            </div>
            {page.mitigations.length > 0 && (
              <div className="kb-item">
                <div className="kb-item-head"><strong>Mitigations</strong><span className="tag">Response tab</span></div>
                <ul className="kb-list">{page.mitigations.map((m) => <li key={m.mitigation_id}><span className="mono muted">{m.mitigation_id}</span> {m.name}</li>)}</ul>
              </div>
            )}
            {page.subtechniques.length > 0 && (
              <div className="kb-item">
                <strong>Sub-techniques</strong>
                <ul className="kb-list">{page.subtechniques.map((s) => <li key={s.technique_id}><span className="mono muted">{s.technique_id}</span> {s.name}</li>)}</ul>
              </div>
            )}
          </div>
        ) : items.length === 0 ? (
          <p className="small muted">
            {tab === 'cve' ? 'CVE records are only searched for exploit techniques (T1190, T1210, T1203, T1211, T1212, T1068).'
              : `No ${source.label} chunks are linked to ${page.technique_id}; retrieval uses other techniques of the same tactic.`}
          </p>
        ) : (
          <div className="kb-items" style={{ marginTop: 0 }}>
            {items.map((it) => (
              <div key={it.id} className="kb-item">
                <div className="kb-item-head">
                  {it.url ? <a className="mono small" href={it.url} target="_blank" rel="noreferrer">{it.ref}</a> : <span className="mono small muted">{it.ref}</span>}
                  <span className="tag">{LEVEL[tab]}</span>
                </div>
                <strong>{it.title}</strong>
                <p>{it.text}</p>
              </div>
            ))}
          </div>
        )}
        {tab !== 'mitre' && page.counts[tab] > items.length && (
          <p className="small muted" style={{ margin: 0 }}>Showing {items.length} of {fmt(page.counts[tab])} entries.</p>
        )}
      </div>
    </section>
  );
}

export default function KnowledgeBase() {
  const [kb, setKb] = useState(null);
  const [error, setError] = useState(null);
  const [params, setParams] = useSearchParams();
  useEffect(() => { api.knowledgeBase().then(setKb).catch((e) => setError(e.message)); }, []);

  const firstPredicted = useMemo(() => (kb?.techniques ?? []).filter((t) => t.detector_class)
    .sort((a, b) => techniqueLevel(b) - techniqueLevel(a))[0]?.technique_id, [kb]);
  const selected = params.get('t') || firstPredicted;
  const select = (id) => setParams({ t: id }, { replace: true });

  return (
    <>
      <ReplayStrip />
      <div className="page">
        <header className="page-head">
          <div>
            <h1>Knowledge base</h1>
            <p>Everything the RAG pipeline can cite when it explains an incident{kb ? ` · retrieval: ${kb.retrieval}` : ''}.</p>
          </div>
        </header>
        {error && <section className="panel empty">{error}</section>}
        {kb && (
          <>
            <SourceCards kb={kb} />
            <div className="kb-layout">
              <TechniqueList kb={kb} selected={selected} onSelect={select} />
              {selected && <Detail id={selected} />}
            </div>
          </>
        )}
      </div>
    </>
  );
}
