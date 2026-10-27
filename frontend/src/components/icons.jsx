// Inline SVG icons from the design, so no icon library is needed.

const stroke = { fill: 'none', stroke: 'currentColor', strokeWidth: 1.7, 'aria-hidden': true };

export const Logo = ({ size = 28 }) => (
  <svg width={size} height={size} viewBox="0 0 28 28" aria-hidden="true">
    <path d="M14 2 25 6.5v7.2c0 6.6-4.6 11-11 12.3C7.6 24.7 3 20.3 3 13.7V6.5L14 2Z" fill="var(--surface)" stroke="var(--accent)" strokeWidth="1.6" />
    <circle cx="9" cy="16" r="1.8" fill="var(--accent)" />
    <circle cx="19" cy="11" r="1.8" fill="var(--accent)" />
    <circle cx="17" cy="19" r="1.8" fill="var(--sev-high)" />
    <path d="M9 16 19 11M9 16l8 3M19 11l-2 8" stroke="var(--accent)" strokeWidth="1.1" />
  </svg>
);

export const OverviewIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" {...stroke}>
    <rect x="3" y="3" width="7" height="9" rx="1.5" /><rect x="14" y="3" width="7" height="5" rx="1.5" />
    <rect x="14" y="12" width="7" height="9" rx="1.5" /><rect x="3" y="16" width="7" height="5" rx="1.5" />
  </svg>
);
export const IncidentsIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" {...stroke}><path d="M12 3 2.5 20h19L12 3Z" /><path d="M12 10v4M12 17.5v.5" /></svg>
);
export const ReportIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" {...stroke}><path d="M6 3h9l4 4v14H6z" /><path d="M14 3v5h5M9 13h7M9 17h7" /></svg>
);
export const ChartIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" {...stroke}><path d="M4 20V10M10 20V4M16 20v-7M22 20H2" /></svg>
);
export const BookIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" {...stroke}>
    <path d="M4 5a2 2 0 0 1 2-2h13v16H6a2 2 0 0 0-2 2V5Z" /><path d="M4 19a2 2 0 0 1 2-2h13" />
  </svg>
);
export const SearchIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--muted)" strokeWidth="2" aria-hidden="true">
    <circle cx="11" cy="11" r="7" /><path d="m20 20-3.5-3.5" />
  </svg>
);
export const PlayIcon = () => (<svg width="14" height="14" viewBox="0 0 24 24" aria-hidden="true"><path d="M7 4v16l13-8z" fill="currentColor" /></svg>);
export const PauseIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" aria-hidden="true"><rect x="5" y="4" width="5" height="16" rx="1" fill="currentColor" /><rect x="14" y="4" width="5" height="16" rx="1" fill="currentColor" /></svg>
);

/** Solid warning triangle. `on` colors the mark inside. */
export const WarnTriangle = ({ size = 12, fill = 'var(--sev-high)', on = 'var(--on-accent)' }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" aria-hidden="true" style={{ flex: 'none' }}>
    <path d="M12 2.5 1.5 21h21L12 2.5Z" fill={fill} />
    <path d="M12 9.5v5" stroke={on} strokeWidth="2.6" strokeLinecap="round" />
    <circle cx="12" cy="18" r="1.5" fill={on} />
  </svg>
);
