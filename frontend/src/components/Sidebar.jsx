import { NavLink } from 'react-router-dom';
import { useReplay } from '../state/ReplayContext.jsx';
import { BookIcon, ChartIcon, IncidentsIcon, Logo, OverviewIcon, ReportIcon } from './icons.jsx';

function monthYear(iso) {
  return new Date(iso).toLocaleDateString('en-US', { month: 'short', year: 'numeric', timeZone: 'UTC' });
}

function replayText(r) {
  if (!r?.window_count) return 'Replaying the test split';
  const span = r.first_window_start && r.last_window_start
    ? `, ${monthYear(r.first_window_start)} to ${monthYear(r.last_window_start)}` : '';
  return `Replaying ${r.window_count.toLocaleString('en-US')} test windows${span}`;
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
        <span>Primary model</span>
        <strong>{data?.primary_model ?? '…'}</strong>
        <span>{replayText(data?.replay)}</span>
      </div>
    </nav>
  );
}
