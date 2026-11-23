// Thin client for the analyst console API (docs/api/openapi.yaml, v0.7.1).
// Development: base URL and key come from .env.local (see .env.example).
// Docker / AWS: the bundle is built with VITE_API_BASE_URL=/api and no key; nginx adds the key server-side.

const BASE_URL = (import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000').replace(/\/$/, '');
const API_KEY = import.meta.env.VITE_API_KEY || '';

export class ApiError extends Error {
  constructor(status, message, body) {
    super(message);
    this.status = status;
    this.body = body;
  }
}

function newKey() {
  return globalThis.crypto?.randomUUID?.() || `${Date.now()}-${Math.random().toString(36).slice(2)}`;
}

async function request(method, path, body, extraHeaders = {}) {
  let res;
  try {
    res = await fetch(BASE_URL + path, {
      method,
      headers: {
        ...(API_KEY ? { 'X-API-Key': API_KEY } : {}),
        ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
        ...extraHeaders,
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
      res.status === 401 ? (API_KEY ? 'The API key was rejected. Check VITE_API_KEY in .env.local.'
        : 'The API key was rejected. Check API_KEY in the server\'s .env.')
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
  /** Why the model flagged the incident's top edge (GNNExplainer); poll while status is "computing". */
  modelExplanation: (id) => request('GET', `/incidents/${encodeURIComponent(id)}/model-explanation`),
  /** The 5-minute window graph around the incident's source (default: its latest window). */
  incidentGraph: (id, windowStart) =>
    request('GET', `/incidents/${encodeURIComponent(id)}/graph${windowStart ? `?window_start=${encodeURIComponent(windowStart)}` : ''}`),
  /** Status, technique override, note, mitigations applied. */
  /** One key per edit: if the request is retried, the backend records the edit once. */
  updateIncident: (id, update) =>
    request('PATCH', `/incidents/${encodeURIComponent(id)}`, update, { 'Idempotency-Key': newKey() }),
  /** The incident's follow-up conversation. */
  incidentChat: (id) => request('GET', `/incidents/${encodeURIComponent(id)}/chat`),
  /** Ask a follow-up question; returns the whole conversation with the answer at the end (a few seconds). */
  askIncidentChat: (id, message) => request('POST', `/incidents/${encodeURIComponent(id)}/chat`, { message }),
  clearIncidentChat: (id) => request('DELETE', `/incidents/${encodeURIComponent(id)}/chat`),
  metrics: () => request('GET', '/metrics'),
  /** Live models (GraphSAGE, HGT) and offline ones (LLMs). */
  models: () => request('GET', '/models'),
  /** Switch the live model; the backend restarts the replay. */
  setModel: (id) => request('POST', '/models/active', { model: id }),
  /** Every ATT&CK technique with the chunks the RAG pipeline can cite. */
  knowledgeBase: () => request('GET', '/knowledge-base'),
  knowledgeTechnique: (id, limit = 20) => request('GET', `/knowledge-base/${encodeURIComponent(id)}?limit=${limit}`),
  health: () => request('GET', '/health'),
};

export const apiBaseUrl = BASE_URL;
