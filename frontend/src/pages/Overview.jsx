import { useMemo, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import ReplayBar from '../components/ReplayBar.jsx';
import { ErrorNote, SeverityChip } from '../components/badges.jsx';
import { SearchIcon, WarnTriangle } from '../components/icons.jsx';
import { useReplay } from '../state/ReplayContext.jsx';
import { dateTime, hhmm, num, pct, plural, sameDay, shortDate } from '../utils/format.js';
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
            <span className="kpi-label">{stats.rated ? 'High severity, unresolved' : `High-confidence incidents (p ≥ ${URGENT_PROBABILITY.toFixed(2)})`}</span>
            <span className="kpi-value" style={{ color: 'var(--sev-high)' }}>
              {stats.urgent.length > 0 && <WarnTriangle size={26} />}
              {num(stats.urgent.length)}
            </span>
            {stats.rated ? (
              <span className="kpi-sub" style={{ color: stats.urgent.length ? 'var(--sev-high)' : 'var(--muted)', fontWeight: 500 }}>
                {stats.urgent.length ? 'Review these first' : 'Nothing urgent right now'}
              </span>
            ) : (
              <span className="kpi-sub muted">Unresolved; no severity rating yet, so ranked by attack probability</span>
            )}
          </div>
          <div className="kpi">
            <span className="kpi-label"><span className="dot" style={{ background: 'var(--sev-medium)' }} />Flagged as attack</span>
            <span className="kpi-value" style={{ color: 'var(--sev-medium)' }}>{num(stats.attack)}</span>
            <span className="kpi-sub muted">
              {stats.events ? pct(stats.attack / stats.events) : '—'} of edges, in {plural(incidents.length, 'incident')}
              {data?.threshold != null && ` · model threshold ${Number(data.threshold).toFixed(2)}`}
            </span>
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
            <TrafficPanel windows={stats.recent} clock={data?.replay?.window_start} />
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

const SLOT_MS = 5 * 60 * 1000;

/** Flagged bar: red bottom part for high-confidence edges, yellow for the rest (older backends: all yellow). */
function flaggedFill(w) {
  if (w.high_confidence_edges == null || !w.attack_edges) return 'var(--sev-medium)';
  const red = Math.round((w.high_confidence_edges / w.attack_edges) * 100);
  return `linear-gradient(to top, var(--sev-high) 0 ${red}%, var(--sev-medium) ${red}% 100%)`;
}
const SLOTS = RECENT_MS / SLOT_MS;   // 72 five-minute slots in 6 hours

function TrafficPanel({ windows, clock }) {
  const [hover, setHover] = useState(null);
  const t = useMemo(() => {
    if (!clock || !windows.length) return null;
    const end = new Date(clock).getTime();
    const byTime = new Map(windows.map((w) => [new Date(w.window_start).getTime(), w]));
    const slots = Array.from({ length: SLOTS }, (_, i) => {
      const time = end - (SLOTS - 1 - i) * SLOT_MS;
      return { time, w: byTime.get(time) };
    });
    // runs: consecutive slots with data, or a gap without data, so gaps can be drawn as one block
    const runs = [];
    for (const slot of slots) {
      const kind = slot.w ? 'bar' : 'gap';
      if (kind === 'gap' && runs.length && runs[runs.length - 1].kind === 'gap') runs[runs.length - 1].slots.push(slot);
      else runs.push({ kind, slots: [slot] });
    }
    const present = slots.filter((x) => x.w);
    const crossesDay = new Date(slots[0].time).getUTCDate() !== new Date(end).getUTCDate();
    return {
      slots, runs, crossesDay,
      maxN: Math.max(1, ...present.map((x) => x.w.events - x.w.attack_edges)),
      maxA: Math.max(1, ...present.map((x) => x.w.attack_edges)),
      avgN: Math.round(present.reduce((sum, x) => sum + x.w.events - x.w.attack_edges, 0) / Math.max(present.length, 1)),
      missing: slots.length - present.length,
    };
  }, [windows, clock]);

  const label = (time) => {
    const iso = new Date(time).toISOString();
    return t.crossesDay ? `${shortDate(iso)} ${hhmm(iso)}` : hhmm(iso);
  };
  const lane = (value, max, color, height) => (
    <div className="bars" style={{ height }}>
      {t.runs.map((run) => (run.kind === 'gap'
        ? <span key={run.slots[0].time} className="gap" style={{ flex: run.slots.length }} title={`No data ${label(run.slots[0].time)}–${label(run.slots[run.slots.length - 1].time + SLOT_MS)}`}>
            {run.slots.length >= 8 && height > 60 && <em>no data</em>}
          </span>
        : run.slots.map((x) => (
          <span key={x.time} className="bar" style={{ flex: 1, height: `${(value(x.w) / max) * 100}%`, background: typeof color === 'function' ? color(x.w) : color, opacity: hover && hover.time !== x.time ? 0.55 : 1 }}
            onMouseEnter={() => setHover(x)} onMouseLeave={() => setHover(null)} />
        ))))}
    </div>
  );

  return (
    <section className="panel">
      <div className="panel-head"><h2>Traffic</h2><span className="small muted">Last 6 hours, per 5-minute window</span></div>
      <div className="panel-body" style={{ display: 'flex', flexDirection: 'column', gap: 12, position: 'relative' }}>
        {!t ? <p className="muted">No windows replayed yet.</p> : (
          <>
            <div className="lane">
              <span className="lane-head small"><span className="muted">Normal</span>{t.avgN > 0 && <span className="mono small muted">about {num(t.avgN)} edges per window</span>}</span>
              {t.slots.some((x) => x.w && x.w.events > x.w.attack_edges)
                ? lane((w) => w.events - w.attack_edges, t.maxN, 'var(--normal)', 56)
                : <p className="small muted" style={{ margin: 0, padding: '10px 0', borderBottom: '1px solid var(--border)' }}>No normal traffic in these windows: every edge was flagged.</p>}
            </div>
            <div className="lane">
              <span className="lane-head small">
                <span className="lane-key">
                  <span style={{ color: 'var(--sev-medium)' }}><i className="key" style={{ background: 'var(--sev-medium)' }} />Flagged as attack</span>
                  <span style={{ color: 'var(--sev-high)' }}><i className="key" style={{ background: 'var(--sev-high)' }} />of which p ≥ {URGENT_PROBABILITY.toFixed(2)}</span>
                </span>
                <span className="mono small muted">peak {num(t.maxA)} edges per window</span>
              </span>
              {lane((w) => w.attack_edges, t.maxA, flaggedFill, 84)}
            </div>
            <div className="mono small muted" style={{ display: 'flex', justifyContent: 'space-between' }}>
              {[0, 24, 48, SLOTS - 1].map((i) => <span key={i}>{label(t.slots[i].time)}</span>)}
            </div>
            <div className="traffic-readout small" aria-live="polite">
              {hover
                ? <><span className="mono">{dateTime(new Date(hover.time).toISOString())}</span> · Normal <strong>{num(hover.w.events - hover.w.attack_edges)}</strong> · Flagged <strong style={{ color: 'var(--sev-medium)' }}>{num(hover.w.attack_edges)}</strong> edges{hover.w.high_confidence_edges != null && hover.w.attack_edges > 0 && <>, <strong style={{ color: 'var(--sev-high)' }}>{num(hover.w.high_confidence_edges)}</strong> with p ≥ {URGENT_PROBABILITY.toFixed(2)}</>}</>
                : <span className="muted">Hover a bar to see that window.</span>}
            </div>
            <p className="small muted">
              Each row has its own scale, because normal traffic is much larger than flagged traffic.
              The red part of a flagged bar is the edges the model is at least {Math.round(URGENT_PROBABILITY * 100)}% sure of, the same level as High-confidence incidents.
              {t.missing > 0 && ' Shaded gaps are 5-minute windows with no recorded traffic in the test split, or not replayed yet.'}
            </p>
          </>
        )}
      </div>
    </section>
  );
}
