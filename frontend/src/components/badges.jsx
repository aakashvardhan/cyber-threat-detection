import { WarnTriangle } from './icons.jsx';
import { STATUS_COLOR, STATUS_LABEL } from '../utils/incidents.js';

const SEV_LABEL = { high: 'High', medium: 'Medium', low: 'Low' };

/** Severity is always written as a word; high adds a warning icon.
    When the primary model gives no severity, show a neutral "Unrated" chip. */
export function SeverityChip({ severity }) {
  if (!severity) {
    return <span className="sev sev-none" title="The primary model gives no severity; ranked by attack probability">Unrated</span>;
  }
  return (
    <span className={`sev sev-${severity}`}>
      {severity === 'high' && <WarnTriangle fill="var(--on-accent)" on="var(--sev-high)" />}
      {SEV_LABEL[severity]}
    </span>
  );
}

export function StatusDot({ status }) {
  return (
    <span className="status">
      <span className="dot" style={{ background: STATUS_COLOR[status] }} />
      {STATUS_LABEL[status] || status}
    </span>
  );
}

export function ErrorNote({ message, onRetry }) {
  if (!message) return null;
  return (
    <div className="note note-error" role="alert">
      {message}{' '}
      {onRetry && <button className="btn btn-sm btn-ghost" onClick={onRetry} style={{ marginLeft: 8 }}>Retry</button>}
    </div>
  );
}
