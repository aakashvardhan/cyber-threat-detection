// Thin client for the analyst console API (docs/api/openapi.yaml, v0.4.3).
// Base URL and key come from .env.local (see .env.example).

const BASE_URL = (import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000').replace(/\/$/, '');
const API_KEY = import.meta.env.VITE_API_KEY || '';

export class ApiError extends Error {
  constructor(status, message, body) {
    super(message);
    this.status = status;
    this.body = body;
  }
}

async function request(method, path, body) {
  let res;
  try {
    res = await fetch(BASE_URL + path, {
      method,
      headers: {
        'X-API-Key': API_KEY,
        ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new ApiError(0, `Can't reach the server at ${BASE_URL}. Is the backend running?`);
  }
  const text = await res.text();
  const data = text ? safeJson(text) : null;
  if (!res.ok) {
    const detail = data?.detail;
    const message =
      res.status === 401 ? 'The API key was rejected. Check VITE_API_KEY in .env.local.'
      : typeof detail === 'string' ? detail
      : data?.message || `Request failed (${res.status})`;
    throw new ApiError(res.status, message, data);
  }
  return data;
}

function safeJson(text) {
  try { return JSON.parse(text); } catch { return null; }
}

export const api = {
  /** Process the next window, or a given one. `reset` starts the replay over. */
  detect: ({ windowStart, reset } = {}) =>
    request('POST', '/detect', {
      ...(windowStart ? { window_start: windowStart } : {}),
      ...(reset ? { reset: true } : {}),
    }),
  /** Replay position, per-window stats and all incident summaries. */
  listIncidents: () => request('GET', '/incidents'),
  /** Full incident; the first call starts the explanation (status "generating"). */
  getIncident: (id, { refresh = false } = {}) =>
    request('GET', `/incidents/${encodeURIComponent(id)}${refresh ? '?refresh_explanation=true' : ''}`),
  /** The 5-minute window graph around the incident's source (default: its latest window). */
  incidentGraph: (id, windowStart) =>
    request('GET', `/incidents/${encodeURIComponent(id)}/graph${windowStart ? `?window_start=${encodeURIComponent(windowStart)}` : ''}`),
  /** Status, technique override, note, mitigations applied. */
  updateIncident: (id, update) => request('PATCH', `/incidents/${encodeURIComponent(id)}`, update),
  metrics: () => request('GET', '/metrics'),
  health: () => request('GET', '/health'),
};

export const apiBaseUrl = BASE_URL;
