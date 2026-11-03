import { Fragment, useEffect, useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { ReplayStrip } from '../components/ReplayBar.jsx';
import { ErrorNote, SeverityChip, StatusDot } from '../components/badges.jsx';
import { WarnTriangle } from '../components/icons.jsx';
import { api } from '../api/client.js';
import { useReplay } from '../state/ReplayContext.jsx';
import { hhmm, num, plural, prob, service, shortSpan } from '../utils/format.js';
import { byPriority, hasSeverity, isUrgent, STATUSES, STATUS_LABEL, techniqueOf } from '../utils/incidents.js';

const PAGE_SIZE = 25;
const EMPTY_FILTERS = { severity: 'all', technique: 'all', tactic: 'all', minProb: 0.5, lowOnly: false };

export default function Incidents() {
  const { incidents, seenIds, markAllSeen, refresh, error, clearError } = useReplay();
  const [params, setParams] = useSearchParams();
  const [tab, setTab] = useState('new');
  const [filters, setFilters] = useState(EMPTY_FILTERS);
  const [open, setOpen] = useState(null);
  const [selected, setSelected] = useState(() => new Set());
  const [page, setPage] = useState(0);
  const [actionError, setActionError] = useState(null);
  const [saving, setSaving] = useState(false);
  const ip = params.get('ip') || '';

  // New incidents wait behind the banner so the list never jumps while someone is reading.
  const fresh = incidents.filter((i) => !seenIds.has(i.incident_id));
  const shown = incidents.filter((i) => seenIds.has(i.incident_id));
  const freshUrgent = fresh.filter(isUrgent).length;
  const rated = hasSeverity(incidents);

  const counts = useMemo(() => {
    const c = Object.fromEntries(STATUSES.map((s) => [s, 0]));
    for (const i of shown) c[i.status] += 1;
    return c;
  }, [shown]);

  const options = useMemo(() => ({
    techniques: [...new Map(shown.map((i) => [techniqueOf(i), i.technique_name])).entries()].sort(),
    tactics: [...new Set(shown.map((i) => i.tactic).filter(Boolean))].sort(),
  }), [shown]);

  const rows = useMemo(() => shown
    .filter((i) => i.status === tab)
    .filter((i) => filters.severity === 'all' || (i.severity || 'none') === filters.severity)
    .filter((i) => filters.technique === 'all' || techniqueOf(i) === filters.technique)
    .filter((i) => filters.tactic === 'all' || i.tactic === filters.tactic)
    .filter((i) => i.max_attack_probability >= filters.minProb)
    .filter((i) => !filters.lowOnly || i.low_confidence)
    .filter((i) => !ip || i.source_ip.includes(ip) || i.edges_preview.some((e) => e.destination_ip.includes(ip)))
    .sort(byPriority), [shown, tab, filters, ip]);

  useEffect(() => { setPage(0); setSelected(new Set()); }, [tab, filters, ip]);

  const pageRows = rows.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE);
  const setF = (k, v) => setFilters((f) => ({ ...f, [k]: v }));
  const toggleSel = (id) => setSelected((s) => { const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n; });
  const allOnPage = pageRows.length > 0 && pageRows.every((r) => selected.has(r.incident_id));

  async function bulk(status) {
    setSaving(true);
    setActionError(null);
    try {
      for (const id of selected) await api.updateIncident(id, { status });
      setSelected(new Set());
      await refresh();
    } catch (e) {
      setActionError(e.message);
    } finally {
      setSaving(false);
    }
  }

  function exportCsv() {
    const head = ['incident_id', 'severity', 'max_attack_probability', 'technique_id', 'technique_name', 'tactic', 'source_ip', 'target_count', 'edge_count', 'first_seen', 'last_seen', 'status', 'low_confidence'];
    const lines = [head.join(',')].concat(rows.map((r) => head.map((k) => JSON.stringify(k === 'technique_id' ? techniqueOf(r) : r[k] ?? '')).join(',')));
    const url = URL.createObjectURL(new Blob([lines.join('\n')], { type: 'text/csv' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = `incidents-${tab}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <>
      <ReplayStrip />
      <div className="page" style={{ gap: 18 }}>
        <header className="page-head">
          <div>
            <h1>Incidents</h1>
            <p>Edges the model flags as attacks are grouped into incidents: same source and technique, less than 30 minutes apart.</p>
          </div>
          <button className="btn" onClick={exportCsv} disabled={!rows.length}>Export CSV</button>
        </header>

        <ErrorNote message={error} onRetry={() => { clearError(); refresh().catch(() => {}); }} />

        {fresh.length > 0 && (
          <div role="status" className={`banner ${freshUrgent ? 'banner-high' : 'banner-medium'}`}>
            <span className="status" style={{ gap: 10 }}>
              <WarnTriangle size={20} fill={freshUrgent ? 'var(--sev-high)' : 'var(--sev-medium)'} />
              <span>
                <strong>{plural(fresh.length, 'new incident')} {fresh.length === 1 ? 'needs' : 'need'} review</strong>
                {freshUrgent > 0 && `, including ${num(freshUrgent)} ${rated ? 'high severity' : 'likely attacks'}`}.
              </span>
            </span>
            <button className="btn btn-sm" onClick={markAllSeen}
              style={{ fontWeight: 600, color: 'var(--on-accent)', background: freshUrgent ? 'var(--sev-high)' : 'var(--sev-medium)', borderColor: 'transparent' }}>
              Show updates
            </button>
          </div>
        )}

        <div role="tablist" aria-label="Status" className="tabs">
          {STATUSES.map((s) => (
            <button key={s} role="tab" aria-selected={tab === s} className="tab" onClick={() => setTab(s)}>
              {STATUS_LABEL[s]}<span className="count">{num(counts[s])}</span>
            </button>
          ))}
        </div>

        <section aria-label="Filters" className="filters">
          <label className="fld">Severity
            <select className="ctl" value={filters.severity} onChange={(e) => setF('severity', e.target.value)}>
              <option value="all">All</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="none">Unrated</option>
            </select>
          </label>
          <label className="fld">Technique
            <select className="ctl" value={filters.technique} onChange={(e) => setF('technique', e.target.value)}>
              <option value="all">All techniques</option>
              {options.techniques.map(([id, name]) => <option key={id} value={id}>{id} {name}</option>)}
            </select>
          </label>
          <label className="fld">Tactic
            <select className="ctl" value={filters.tactic} onChange={(e) => setF('tactic', e.target.value)}>
              <option value="all">All tactics</option>
              {options.tactics.map((t) => <option key={t}>{t}</option>)}
            </select>
          </label>
          <label className="fld">Min. attack probability
            <span className="status" style={{ minHeight: 40, gap: 8 }}>
              <input type="range" min="0" max="1" step="0.05" value={filters.minProb} onChange={(e) => setF('minProb', Number(e.target.value))} style={{ width: 120 }} />
              <span className="mono" style={{ color: 'var(--text)' }}>{filters.minProb.toFixed(2)}</span>
            </span>
          </label>
          <label className="fld">Source or target IP
            <input className="ctl mono" type="search" placeholder="143.88." value={ip} style={{ width: 160 }}
              onChange={(e) => setParams(e.target.value ? { ip: e.target.value } : {}, { replace: true })} />
          </label>
          <label className="status" style={{ minHeight: 40, gap: 8, cursor: 'pointer' }}>
            <input type="checkbox" checked={filters.lowOnly} onChange={(e) => setF('lowOnly', e.target.checked)} />Low confidence only
          </label>
          <button className="btn btn-ghost" style={{ marginLeft: 'auto' }} onClick={() => { setFilters(EMPTY_FILTERS); setParams({}, { replace: true }); }}>Clear filters</button>
        </section>

        <ErrorNote message={actionError} />

        <section className="panel" style={{ overflow: 'hidden' }}>
          <div className="bulk-bar">
            <label className="status" style={{ gap: 8, cursor: 'pointer' }}>
              <input type="checkbox" checked={allOnPage} disabled={!pageRows.length}
                onChange={() => setSelected(allOnPage ? new Set() : new Set(pageRows.map((r) => r.incident_id)))} />Select all
            </label>
            <button className="btn btn-sm" disabled={!selected.size || saving} onClick={() => bulk('confirmed')}>Confirm selected</button>
            <button className="btn btn-sm" disabled={!selected.size || saving} onClick={() => bulk('dismissed')}>Dismiss selected</button>
            <span className="small muted" style={{ marginLeft: 'auto' }}>Sorted by {rated ? 'severity, then ' : ''}attack probability</span>
          </div>
          <div className="table-scroll">
            <div style={{ minWidth: 1080 }}>
              <div className="inc-cols thead"><span /><span>Severity</span><span>Incident</span><span>Technique</span><span>Source</span><span>Targets</span><span>Edges</span><span>Active (UTC)</span><span>Status</span></div>
              {pageRows.length === 0 && <p className="empty">No incidents match. {tab === 'new' ? 'Try clearing the filters.' : ''}</p>}
              {pageRows.map((r) => {
                const isOpenRow = open === r.incident_id;
                return (
                  <Fragment key={r.incident_id}>
                    <div className="inc-cols trow" style={isUrgent(r) ? { background: 'rgba(255,64,64,.06)' } : undefined}>
                      <span className="status" style={{ gap: 6 }}>
                        <input type="checkbox" aria-label={`Select ${r.incident_id}`} checked={selected.has(r.incident_id)} onChange={() => toggleSel(r.incident_id)} />
                        <button className="expand" aria-expanded={isOpenRow} aria-label={`Show edges in ${r.incident_id}`} onClick={() => setOpen(isOpenRow ? null : r.incident_id)}>{isOpenRow ? '−' : '+'}</button>
                      </span>
                      <span className="cell-stack" style={{ gap: 3, alignItems: 'flex-start' }}>
                        <SeverityChip severity={r.severity} />
                        <span className="mono small muted">p {prob(r.max_attack_probability)}</span>
                      </span>
                      <Link to={`/incidents/${r.incident_id}`} className="mono" style={{ fontWeight: 500 }}>{r.incident_id}</Link>
                      <span className="cell-stack">
                        <span style={{ fontWeight: 500 }}>{r.technique_name}</span>
                        <span className="small muted">
                          {techniqueOf(r)} · {r.tactic}
                          {r.technique_override && <span style={{ marginLeft: 8 }}>(analyst set)</span>}
                          {r.low_confidence && <span className="warn-text" style={{ marginLeft: 8 }}>Low confidence</span>}
                        </span>
                      </span>
                      <span className="mono">{r.source_ip}</span>
                      <span>{plural(r.target_count, 'host')}</span>
                      <span>{num(r.edge_count)}</span>
                      <span className="mono small muted">{shortSpan(r.first_seen, r.last_seen)}</span>
                      <StatusDot status={r.status} />
                    </div>
                    {isOpenRow && (
                      <div className="preview">
                        <span className="small muted">Latest edges in this incident</span>
                        {r.edges_preview.map((e) => (
                          <div key={e.event_id} className="mono preview-row">
                            <span className="muted">{hhmm(e.window_start)}</span><span>{e.destination_ip}</span><span className="muted">{service(e)}</span><span>p {prob(e.attack_probability)}</span>
                          </div>
                        ))}
                        <Link to={`/incidents/${r.incident_id}`} style={{ fontSize: 13 }}>Open {r.incident_id}</Link>
                      </div>
                    )}
                  </Fragment>
                );
              })}
            </div>
          </div>
          <div className="pager">
            <span>{rows.length ? `Showing ${num(page * PAGE_SIZE + 1)}–${num(Math.min(rows.length, (page + 1) * PAGE_SIZE))} of ${plural(rows.length, `${STATUS_LABEL[tab].toLowerCase()} incident`)}` : ''}</span>
            <div style={{ display: 'flex', gap: 8 }}>
              <button className="btn btn-sm" disabled={page === 0} onClick={() => setPage(page - 1)}>Previous</button>
              <button className="btn btn-sm" disabled={(page + 1) * PAGE_SIZE >= rows.length} onClick={() => setPage(page + 1)}>Next</button>
            </div>
          </div>
        </section>
      </div>
    </>
  );
}
