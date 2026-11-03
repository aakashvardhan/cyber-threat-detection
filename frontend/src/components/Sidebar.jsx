import { useEffect, useState } from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import { api } from '../api/client.js';
import { useReplay } from '../state/ReplayContext.jsx';
import { BookIcon, ChartIcon, IncidentsIcon, Logo, OverviewIcon, ReportIcon } from './icons.jsx';

function monthYear(iso) {
  return new Date(iso).toLocaleDateString('en-US', { month: 'short', year: 'numeric', timeZone: 'UTC' });
}

// The test split is a stratified sample of 5-minute windows from several capture weeks, not a continuous period.
function replayText(r) {
  if (!r?.window_count) return 'Source: test split';
  const days = r.day_starts?.length;
  const span = r.first_window_start && r.last_window_start
    ? ` between ${monthYear(r.first_window_start)} and ${monthYear(r.last_window_start)}` : '';
  return `Source: ${r.window_count.toLocaleString('en-US')} test windows${days ? ` on ${days} sampled days` : ''}${span}`;
}

function ModelSwitcher() {
  const { data, switchModel } = useReplay();
  const navigate = useNavigate();
  const [models, setModels] = useState(null);
  const [pending, setPending] = useState(null);   // model id waiting for confirmation
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const active = data?.primary_model;

  useEffect(() => {
    api.models().then(setModels).catch(() => setModels(null));
  }, [active]);

  const live = (models?.models ?? []).filter((m) => m.live);
  const offline = (models?.models ?? []).filter((m) => !m.live);
  const choose = async () => {
    setBusy(true);
    setError(null);
    try {
      await switchModel(pending);
      setPending(null);
      navigate('/');
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  if (live.length < 2) return <strong>{active ?? '…'}</strong>;
  return (
    <>
      <label className="sr-only" htmlFor="live-model">Live model</label>
      <select id="live-model" className="ctl model-select" value={pending ?? models.active} disabled={busy}
        onChange={(e) => setPending(e.target.value === models.active ? null : e.target.value)}>
        {live.map((m) => (
          <option key={m.id} value={m.id} disabled={!m.available} title={m.note ?? undefined}>
            {m.name}{m.available ? '' : ' (not installed)'}
          </option>
        ))}
        {offline.length > 0 && (
          <optgroup label="Offline only (Research tab)">
            {offline.map((m) => <option key={m.id} value={m.id} disabled>{m.name}</option>)}
          </optgroup>
        )}
      </select>
      {pending && (
        <div className="model-confirm">
          <span>Switching resets detection and starts over with {live.find((m) => m.id === pending)?.name}.</span>
          <div style={{ display: 'flex', gap: 6 }}>
            <button className="btn btn-primary btn-sm" disabled={busy} onClick={choose}>{busy ? 'Switching…' : 'Switch'}</button>
            <button className="btn btn-sm" disabled={busy} onClick={() => setPending(null)}>Cancel</button>
          </div>
        </div>
      )}
      {error && <span className="model-error">{error}</span>}
    </>
  );
}

export default function Sidebar() {
  const { data, incidents } = useReplay();
  const awaiting = incidents.filter((i) => i.status === 'new').length;

  return (
    <nav className="nav" aria-label="Main">
      <div className="brand"><Logo />Threat Console</div>
      <NavLink to="/" end><OverviewIcon />Overview</NavLink>
      <NavLink to="/incidents">
        <IncidentsIcon />Incidents
        {awaiting > 0 && <span className="badge" aria-label={`${awaiting} awaiting review`}>{awaiting}</span>}
      </NavLink>
      <NavLink to="/reports"><ReportIcon />Reports</NavLink>
      <div className="nav-group">Research</div>
      <NavLink to="/evaluation"><ChartIcon />Evaluation</NavLink>
      <NavLink to="/knowledge-base"><BookIcon />Knowledge base</NavLink>
      <div className="model-box">
        <span>Live model</span>
        <ModelSwitcher />
        <span title="The test split is a stratified sample of 5-minute windows from several capture weeks, so the days are not continuous.">
          {replayText(data?.replay)}
        </span>
      </div>
    </nav>
  );
}
