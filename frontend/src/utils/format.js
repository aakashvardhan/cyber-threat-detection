// Display helpers. All times from the API are UTC ISO strings and are shown in UTC.

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const pad = (n) => String(n).padStart(2, '0');

export function hhmm(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`;
}

export function shortDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return `${MONTHS[d.getUTCMonth()]} ${d.getUTCDate()}`;
}

export function dateTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return `${MONTHS[d.getUTCMonth()]} ${d.getUTCDate()}, ${d.getUTCFullYear()}, ${hhmm(iso)} UTC`;
}

/** "May 30, 15:50–16:25 UTC", or with both dates when the span crosses midnight. */
export function timeSpan(first, last) {
  if (!first) return '—';
  if (!last || first === last) return `${shortDate(first)}, ${hhmm(first)} UTC`;
  if (shortDate(first) === shortDate(last)) return `${shortDate(first)}, ${hhmm(first)}–${hhmm(last)} UTC`;
  return `${shortDate(first)} ${hhmm(first)} – ${shortDate(last)} ${hhmm(last)} UTC`;
}

/** Compact span for table cells: "15:50–16:25" or "May 23 04:40 – May 29 23:10". */
export function shortSpan(first, last) {
  if (!first) return '—';
  if (shortDate(first) === shortDate(last || first)) return `${hhmm(first)}–${hhmm(last || first)}`;
  return `${shortDate(first)} ${hhmm(first)} – ${shortDate(last)} ${hhmm(last)}`;
}

export const num = (n) => (n == null ? '—' : Number(n).toLocaleString('en-US'));
export const prob = (p) => (p == null ? '—' : Number(p).toFixed(2));
export const pct = (x, digits = 1) => (x == null ? '—' : `${(x * 100).toFixed(digits)}%`);

export function bytes(b) {
  if (b == null) return '—';
  if (b < 1024) return `${Math.round(b)} B`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
  return `${(b / 1024 / 1024).toFixed(1)} MB`;
}

export const plural = (n, word, many = `${word}s`) => `${num(n)} ${n === 1 ? word : many}`;

export function service(edge) {
  const svc = edge.service || edge.traffic_features?.dominant_zeek_service;
  const port = edge.port ?? edge.traffic_features?.dominant_destination_port;
  if (!svc && port == null) return '—';
  return [svc, port].filter((x) => x != null && x !== '').join('/');
}

export const sameDay = (a, b) => !!a && !!b && shortDate(a) === shortDate(b);
