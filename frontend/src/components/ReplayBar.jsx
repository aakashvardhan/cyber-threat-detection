import { useMemo } from 'react';
import { SPEEDS, useReplay } from '../state/ReplayContext.jsx';
import { dateTime, hhmm, num, shortDate } from '../utils/format.js';
import { PauseIcon, PlayIcon } from './icons.jsx';

const WINDOW_MS = 5 * 60 * 1000;
const BINS = 120;

/** Start and end of the test period. The test split has gaps, so use the bounds the backend reports;
 *  older backends without them: estimate from the replay position (assumes no gaps). */
function usePeriod(data) {
  return useMemo(() => {
    const r = data?.replay;
    if (r?.first_window_start && r?.last_window_start) {
      const start = new Date(r.first_window_start).getTime();
      return { start, end: new Date(r.last_window_start).getTime() + WINDOW_MS, count: r.window_count };
    }
    if (!r?.window_start || !r.window_index) return null;
    const start = new Date(r.window_start).getTime() - (r.window_index - 1) * WINDOW_MS;
    return { start, end: start + r.window_count * WINDOW_MS, count: r.window_count };
  }, [data]);
}

function stateText(playing, finished, hasData) {
  if (!hasData) return 'Not started';
  if (finished) return 'Finished, restart to replay again';
  return playing ? 'Playing, detecting live' : 'Paused';
}

/** Full replay controls with the whole-period traffic strip (Overview). */
export default function ReplayBar() {
  const replay = useReplay();
  const { data, playing, finished, speedMs } = replay;
  const period = usePeriod(data);
  const pos = data?.replay;

  const rails = useMemo(() => {
    if (!period) return null;
    const normal = new Array(BINS).fill(0);
    const attack = new Array(BINS).fill(0);
    const done = new Array(BINS).fill(false);
    const span = period.end - period.start;
    for (const w of data.windows) {
      const t = new Date(w.window_start).getTime() - period.start;
      const bin = Math.min(BINS - 1, Math.max(0, Math.floor((t * BINS) / span)));
      normal[bin] += w.events - w.attack_edges;
      attack[bin] += w.attack_edges;
      done[bin] = true;
    }
    const maxN = Math.max(1, ...normal);
    const maxA = Math.max(1, ...attack);
    const head = pos?.window_start ? ((new Date(pos.window_start).getTime() + WINDOW_MS / 2 - period.start) / span) * 100 : 0;
    return { normal, attack, done, maxN, maxA, head };
  }, [data, period, pos]);

  const days = useMemo(() => {
    if (pos?.day_starts?.length) return pos.day_starts;   // first recorded window of each day
    if (!period) return [];
    const out = [];
    const first = new Date(period.start);
    first.setUTCHours(0, 0, 0, 0);
    for (let t = first.getTime(); t < period.end; t += 24 * 3600 * 1000) {
      if (t >= period.start) out.push(new Date(t).toISOString().replace('.000Z', 'Z'));
    }
    return out;
  }, [period, pos]);
  const years = useMemo(() => [...new Set(days.map((d) => d.slice(0, 4)))], [days]);

  return (
    <section className="replay" aria-label="Replay">
      <div className="replay-controls">
        <button className="btn btn-primary" onClick={replay.togglePlay} disabled={finished} aria-label={playing ? 'Pause replay' : 'Play replay'}>
          {playing ? <PauseIcon /> : <PlayIcon />}{playing ? 'Pause' : 'Play'}
        </button>
        <button className="btn" onClick={replay.step} disabled={finished}>Step one window</button>
        <label className="replay-speed">
          <span className="muted">Speed</span>
          <select className="ctl" value={speedMs} onChange={(e) => replay.setSpeedMs(Number(e.target.value))}>
            {SPEEDS.map((s) => <option key={s.ms} value={s.ms}>{s.label}</option>)}
          </select>
        </label>
        <div className="replay-clock" aria-live="polite">
          <strong>{pos?.window_start ? dateTime(pos.window_start) : 'Press Play to start the replay'}</strong>
          <span className="muted small">
            {pos?.window_index ? `Window ${num(pos.window_index)} of ${num(pos.window_count)} · ` : ''}
            {stateText(playing, finished, !!pos?.window_index)}
          </span>
        </div>
        <div className="replay-right">
          {days.length > 0 && (
            <label className="replay-speed">
              <span className="muted">Jump to</span>
              <select className="ctl" value="" onChange={(e) => e.target.value && replay.jumpTo(e.target.value)}>
                <option value="">Choose a day</option>
                {years.length > 1
                  ? years.map((y) => (   // the test split spans several years: group by year so the order is clear
                    <optgroup key={y} label={y}>
                      {days.filter((d) => d.startsWith(y)).map((d) => <option key={d} value={d}>{shortDate(d)}, {y}, {hhmm(d)}</option>)}
                    </optgroup>
                  ))
                  : days.map((d) => <option key={d} value={d}>{shortDate(d)}, {hhmm(d)}</option>)}
              </select>
            </label>
          )}
          <button className="btn btn-ghost" onClick={replay.restart}>Restart</button>
        </div>
      </div>

      {rails && (
        <>
          <div className="rails">
            <div className="rail-labels small"><span className="muted">All traffic</span><span style={{ color: 'var(--sev-high)' }}>Flagged as attack</span></div>
            <div className="rail-area" role="img" aria-label={`Traffic per period across the test split. The replay is ${Math.round(rails.head)}% through.`}>
              <div className="rail" style={{ height: 14 }}>
                {rails.normal.map((v, i) => (
                  <span key={i} style={{ height: rails.done[i] ? `${3 + (v / rails.maxN) * 11}px` : '3px', background: rails.done[i] ? 'var(--normal)' : 'var(--normal-dim)' }} />
                ))}
              </div>
              <div className="rail" style={{ height: 22 }}>
                {rails.attack.map((v, i) => (
                  <span key={i} style={{ height: rails.done[i] ? `${2 + (v / rails.maxA) * 20}px` : '2px', background: rails.done[i] ? 'var(--sev-high)' : 'rgba(255,64,64,.22)' }} />
                ))}
              </div>
              <span className="rail-head" style={{ left: `${rails.head}%` }} />
            </div>
          </div>
          <div className="rail-foot small muted">
            <span className="mono small">{shortDate(new Date(period.start).toISOString())}</span>
            <span>Each row on its own scale · dimmed = not replayed yet</span>
            <span className="mono small">{shortDate(new Date(period.end - WINDOW_MS).toISOString())}</span>
          </div>
        </>
      )}
    </section>
  );
}

/** One-line replay status for the other pages. */
export function ReplayStrip() {
  const { data, playing, finished, togglePlay } = useReplay();
  const pos = data?.replay;
  const progress = pos?.window_count ? (pos.window_index / pos.window_count) * 100 : 0;
  return (
    <section className="replay replay-strip" aria-label="Replay">
      <span className="status">
        <span className="dot" style={{ background: playing ? 'var(--ok)' : 'var(--muted)' }} />
        <strong>{playing ? 'Replay playing' : finished ? 'Replay finished' : 'Replay paused'}</strong>
      </span>
      {pos?.window_start && (
        <span className="muted">{dateTime(pos.window_start)} · window {num(pos.window_index)} of {num(pos.window_count)}</span>
      )}
      <span className="strip-track"><span style={{ width: `${progress}%` }} /></span>
      <button className="btn btn-sm" onClick={togglePlay} disabled={finished}>{playing ? 'Pause' : 'Play'}</button>
    </section>
  );
}
