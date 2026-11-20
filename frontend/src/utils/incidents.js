// Incident rules shared by the pages, so they all rank and label the same way.

export const STATUSES = ['new', 'confirmed', 'investigating', 'contained', 'closed', 'dismissed'];
export const STATUS_LABEL = {
  new: 'New', confirmed: 'Confirmed', investigating: 'Investigating',
  contained: 'Contained', closed: 'Closed', dismissed: 'Dismissed',
};
export const STATUS_COLOR = {
  new: 'var(--accent)', confirmed: 'var(--sev-high)', investigating: 'var(--sev-medium)',
  contained: 'var(--ok)', closed: 'var(--ok)', dismissed: 'var(--muted)',
};
/** Next step in the workflow for each status, shown as the primary action. */
export const NEXT_ACTION = {
  new: { to: 'confirmed', label: 'Confirm attack' },
  confirmed: { to: 'investigating', label: 'Start investigating' },
  investigating: { to: 'contained', label: 'Mark contained' },
  contained: { to: 'closed', label: 'Close incident' },
};
export const WORKFLOW = ['new', 'confirmed', 'investigating', 'contained', 'closed'];
/** Where Reopen takes an incident that was finished or dismissed. */
export const REOPEN_TO = { closed: 'investigating', dismissed: 'new' };

const SEV_RANK = { high: 3, medium: 2, low: 1 };

/** Probability at or above which an unrated incident counts as urgent.
    Used only when the primary model gives no severity (API: severity is null). */
export const URGENT_PROBABILITY = 0.8;

export const isOpen = (inc) => !['contained', 'closed', 'dismissed'].includes(inc.status);

export function isUrgent(inc) {
  if (inc.severity) return inc.severity === 'high';
  return inc.max_attack_probability >= URGENT_PROBABILITY;
}

/** Severity first, then attack probability (the API contract's rule when severity is null). */
export function byPriority(a, b) {
  const s = (SEV_RANK[b.severity] || 0) - (SEV_RANK[a.severity] || 0);
  if (s) return s;
  return b.max_attack_probability - a.max_attack_probability;
}

export const hasSeverity = (incidents) => incidents.some((i) => i.severity);

/** Technique shown to people: the analyst's override wins over the model. */
export const techniqueOf = (inc) => inc.technique_override || inc.technique_id;
