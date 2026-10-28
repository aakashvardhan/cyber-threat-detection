import { useMemo, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import ReplayBar from '../components/ReplayBar.jsx';
import { ErrorNote, SeverityChip } from '../components/badges.jsx';
import { SearchIcon, WarnTriangle } from '../components/icons.jsx';
import { useReplay } from '../state/ReplayContext.jsx';
import { hhmm, num, pct, plural, sameDay, shortDate } from '../utils/format.js';
import { byPriority, hasSeverity, isOpen, isUrgent, URGENT_PROBABILITY, techniqueOf } from '../utils/incidents.js';

const RECENT_MS = 6 * 3600 * 1000; // the Traffic panel shows the 6 hours before the replay clock

export default function Overview() {
  const { data, incidents, error, refresh, clearError } = useReplay();
  const navigate = useNavigate();
  const [ip, setIp] = useState('');

  const stats = useMemo(() => {
    const windows = data?.windows ?? [];
    let events = 0;
    let attack = 0;
    for (const w of windows) { events += w.events; attack += w.attack_edges; }
    const open = incidents.filter(isOpen);
    const awaiting = incidents.filter((i) => i.status === 'new');
    const urgent = open.filter(isUrgent);
    const byTech = new Map();
    for (const inc of open) {
      const id = techniqueOf(inc);
      const cur = byTech.get(id) || { id, name: inc.technique_name, n: 0 };
      cur.n += 1;
      byTech.set(id, cur);
    }
    const tech = [...byTech.values()].sort((a, b) => b.n - a.n).slice(0, 5);
    return {
      events, attack, normal: events - attack, open, awaiting, urgent, tech,
      needsReview: [...awaiting].sort(byPriority).slice(0, 6),
      recent: (() => {
        // Only windows in the 6 hours before the clock. After a jump, older windows from other days are left out.
        const now = data?.replay?.window_start ? new Date(data.replay.window_start).getTime() : 0;
        return windows.filter((w) => { const t = new Date(w.window_start).getTime(); return t <= now && t > now - RECENT_MS; });
      })(),
      rated: hasSeverity(incidents),
    };
  }, [data, incidents]);

  const onSearch = (e) => {
    e.preventDefault();
    navigate(`/incidents?ip=${encodeURIComponent(ip.trim())}`);
  };

  return (
    <>
      <ReplayBar />
      <div className="page">
        <header className="page-head">
          <div>
            <h1>Overview</h1>
            <p>What the replay has found so far. Updates after every window.</p>
          </div>
          <form onSubmit={onSearch} className="search">
            <label htmlFor="ip-search" className="sr-only">Search by IP</label>
            <SearchIcon />
            <input id="ip-search" type="search" className="ctl mono" placeholder="Search by IP" value={ip} onChange={(e) => setIp(e.target.value)} />
          </form>
        </header>

        <ErrorNote message={error} onRetry={() => { clearError(); refresh().catch(() => {}); }} />

        <section className="panel kpis" aria-label="Key numbers">
          <Link to="/incidents" className="kpi">
            <span className="kpi-label">Awaiting review</span>
            <span className="kpi-value">{num(stats.awaiting.length)}</span>
            <span className="kpi-sub" style={{ color: 'var(--accent)' }}>Incidents not yet triaged</span>
          </Link>
          <div className="kpi">
            <span className="kpi-label">{stats.rated ? 'High severity, unresolved' : `Likely attacks (p ≥ ${URGENT_PROBABILITY.toFixed(2)}), unresolved`}</span>
            <span className="kpi-value" style={{ color: 'var(--sev-high)' }}>
              {stats.urgent.length > 0 && <WarnTriangle size={26} />}
              {num(stats.urgent.length)}
            </span>
            <span className="kpi-sub" style={{ color: stats.urgent.length ? 'var(--sev-high)' : 'var(--muted)', fontWeight: 500 }}>
              {stats.urgent.length ? 'Review these first' : 'Nothing urgent right now'}
            </span>
          </div>
          <div className="kpi">
            <span className="kpi-label"><span className="dot" style={{ background: 'var(--sev-high)' }} />Flagged as attack</span>
            <span className="kpi-value">{num(stats.attack)}</span>
            <span className="kpi-sub muted">{stats.events ? pct(stats.attack / stats.events) : '—'} of edges, in {plural(incidents.length, 'incident')}</span>
          </div>
          <div className="kpi">
            <span className="kpi-label"><span className="dot" style={{ background: 'var(--normal)' }} />Normal traffic</span>
            <span className="kpi-value">{num(stats.normal)}</span>
            <span className="kpi-sub muted">{stats.events ? pct(stats.normal / stats.events) : '—'} of {num(stats.events)} edges analyzed</span>
          </div>
        </section>

        <div className="row-wrap">
          <section className="panel" style={{ flex: '3 1 560px', minWidth: 0, paddingBottom: 6 }}>
            <div className="panel-head"><h2>Needs review</h2><Link to="/incidents">All incidents</Link></div>
            {stats.needsReview.length === 0 ? (
              <p className="empty">{data?.replay?.window_index ? 'No incidents waiting for review.' : 'Press Play to start detecting.'}</p>
            ) : (
              <div className="table-scroll">
                <div style={{ minWidth: 640 }}>
                  <div className="ov-cols thead"><span>Severity</span><span>Incident</span><span>Source</span><span>Targets</span><span>Last seen</span></div>
                  {stats.needsReview.map((r) => (
                    <Link key={r.incident_id} to={`/incidents/${r.incident_id}`} className="ov-cols trow">
                      <span><SeverityChip severity={r.severity} /></span>
                      <span className="cell-stack">
                        <span style={{ fontWeight: 500 }}>{r.technique_name}</span>
                        <span className="small muted">{r.incident_id} · {r.tactic}</span>
                      </span>
                      <span className="mono">{r.source_ip}</span>
                      <span>{plural(r.target_count, 'host')}</span>
                      <span className="mono muted">{sameDay(r.last_seen, data?.replay?.window_start) ? hhmm(r.last_seen) : `${shortDate(r.last_seen)} ${hhmm(r.last_seen)}`}</span>
                    </Link>
                  ))}
                </div>
              </div>
            )}
          </section>

          <div style={{ flex: '2 1 380px', minWidth: 0, display: 'flex', flexDirection: 'column', gap: 24 }}>
            <TrafficPanel windows={stats.recent} />
            <section className="panel">
              <div className="panel-head"><h2>Unresolved incidents by technique</h2></div>
              <div className="panel-body tech-list">
                {stats.tech.length === 0 && <p className="muted">None yet.</p>}
                {stats.tech.map((t) => (
                  <div key={t.id} className="tech-row">
                    <span className="mono muted">{t.id}</span>
                    <span>{t.name}</span>
                    <span className="bar-track"><span className="bar-fill" style={{ width: `${(t.n / stats.tech[0].n) * 100}%`, background: 'var(--accent)' }} /></span>
                    <span className="mono" style={{ textAlign: 'right' }}>{num(t.n)}</span>
                  </div>
                ))}
              </div>
            </section>
          </div>
        </div>
      </div>
    </>
  );
}

function TrafficPanel({ windows }) {
  const maxN = Math.max(1, ...windows.map((w) => w.events - w.attack_edges));
  const maxA = Math.max(1, ...windows.map((w) => w.attack_edges));
  const avgN = windows.length ? Math.round(windows.reduce((s, w) => s + w.events - w.attack_edges, 0) / windows.length) : 0;
  const ticks = windows.length ? [...new Set([0, Math.floor(windows.length / 3), Math.floor((2 * windows.length) / 3), windows.length - 1])] : [];

  return (
    <section className="panel">
      <div className="panel-head"><h2>Traffic</h2><span className="small muted">Last 6 hours, per 5-minute window</span></div>
      <div className="panel-body" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        {windows.length === 0 ? <p className="muted">No windows replayed yet.</p> : (
          <>
            <div className="lane">
              <span className="lane-head small"><span className="muted">Normal</span><span className="mono small muted">about {num(avgN)} edges per window</span></span>
              <div className="bars" style={{ height: 56 }} role="img" aria-label={`Normal edges per window, about ${avgN}`}>
                {windows.map((w) => <span key={w.window_start} style={{ height: `${((w.events - w.attack_edges) / maxN) * 100}%`, background: 'var(--normal)' }} />)}
              </div>
            </div>
            <div className="lane">
              <span className="lane-head small"><span style={{ color: 'var(--sev-high)' }}>Flagged as attack</span><span className="mono small muted">peak {num(maxA)} edges per window</span></span>
              <div className="bars" style={{ height: 84 }} role="img" aria-label={`Flagged edges per window, peak ${maxA}`}>
                {windows.map((w) => <span key={w.window_start} style={{ height: `${(w.attack_edges / maxA) * 100}%`, background: 'var(--sev-high)' }} />)}
              </div>
            </div>
            <div className="mono small muted" style={{ display: 'flex', justifyContent: 'space-between' }}>
              {ticks.map((i) => <span key={i}>{hhmm(windows[i].window_start)}</span>)}
            </div>
            <p className="small muted">Each row has its own scale, because normal traffic is much larger than flagged traffic.</p>
          </>
        )}
      </div>
    </section>
  );
}
