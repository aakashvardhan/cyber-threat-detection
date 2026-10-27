import { NavLink } from 'react-router-dom';
import { useReplay } from '../state/ReplayContext.jsx';
import { BookIcon, ChartIcon, IncidentsIcon, Logo, OverviewIcon, ReportIcon } from './icons.jsx';

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
        <span>Replaying the UWF-ZeekData24 test split</span>
      </div>
    </nav>
  );
}
