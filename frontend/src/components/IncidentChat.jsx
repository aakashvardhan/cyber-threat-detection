import { useEffect, useRef, useState } from 'react';
import { api } from '../api/client.js';
import { ErrorNote } from './badges.jsx';

const SOURCE_LABEL = { mitre: 'MITRE', graph: 'Knowledge graph', procedure: 'Procedure', cti: 'CTI-HAL', cve: 'CVE' };
const SUGGESTIONS = [
  'Which groups use this technique, and what do they do next?',
  'Could this be a different technique?',
  'How should I mitigate and detect this?',
  'Has this source done anything before?',
];

/** "Ask about this incident": follow-up questions answered from fresh GraphRAG retrieval, with citations.
    The conversation is kept by the backend (and saved with the incident). */
export default function IncidentChat({ incidentId }) {
  const [thread, setThread] = useState(null);
  const [draft, setDraft] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const endRef = useRef(null);

  useEffect(() => {
    let live = true;
    api.incidentChat(incidentId).then((t) => live && setThread(t)).catch((e) => live && setError(e.message));
    return () => { live = false; };
  }, [incidentId]);

  useEffect(() => { endRef.current?.scrollIntoView?.({ block: 'nearest' }); }, [thread?.messages?.length, busy]);

  const ask = async (text) => {
    const message = text.trim();
    if (!message || busy) return;
    setBusy(true);
    setError(null);
    setThread((t) => t && { ...t, messages: [...t.messages, { role: 'user', text: message, at: new Date().toISOString(), pending: true }] });
    setDraft('');
    try {
      setThread(await api.askIncidentChat(incidentId, message));
    } catch (e) {
      setError(e.message);
      setDraft(message);
      setThread((t) => t && { ...t, messages: t.messages.filter((m) => !m.pending) });
    } finally {
      setBusy(false);
    }
  };

  const clear = async () => {
    try { setThread(await api.clearIncidentChat(incidentId)); } catch (e) { setError(e.message); }
  };

  const messages = thread?.messages || [];
  return (
    <section className="panel" aria-label="Ask about this incident">
      <div className="panel-head">
        <h2>Ask about this incident</h2>
        {messages.length > 0 && <button className="btn btn-sm btn-ghost" onClick={clear} disabled={busy}>Clear</button>}
      </div>
      <div className="panel-body chat">
        {thread && !thread.llm_enabled && (
          <div className="note note-warn">No LLM is configured on the backend: answers list the most related evidence.</div>
        )}
        {messages.length === 0 && (
          <div className="chat-empty">
            <p className="small muted">Answers come from a new search of the ATT&amp;CK knowledge graph for your question, and cite their sources.</p>
            <div className="chat-suggestions">
              {SUGGESTIONS.map((s) => <button key={s} className="btn btn-sm" onClick={() => ask(s)} disabled={busy || !thread}>{s}</button>)}
            </div>
          </div>
        )}
        <ol className="chat-log">
          {messages.map((m, i) => (m.role === 'user'
            ? <li key={i} className="chat-msg chat-user">{m.text}</li>
            : <li key={i} className="chat-msg chat-assistant"><Answer m={m} /></li>))}
          {busy && <li className="chat-msg chat-assistant"><div className="generating"><span className="pulse" />Searching the knowledge graph and writing an answer…</div></li>}
        </ol>
        <div ref={endRef} />
        <ErrorNote message={error} />
        <form className="chat-form" onSubmit={(e) => { e.preventDefault(); ask(draft); }}>
          <input className="ctl" style={{ flex: 1 }} value={draft} onChange={(e) => setDraft(e.target.value)} maxLength={1000}
            placeholder="Ask a follow-up question" aria-label="Question" disabled={busy || !thread} />
          <button className="btn btn-primary" type="submit" disabled={busy || !draft.trim() || !thread}>Ask</button>
        </form>
      </div>
    </section>
  );
}

function Answer({ m }) {
  const evidence = m.evidence || [];
  const no = Object.fromEntries(evidence.map((e, i) => [e.evidence_id, i + 1]));
  return (
    <>
      {/* an LLM answer reads as one paragraph; an evidence-only answer is a list, one source per line */}
      {(m.mode === 'evidence' ? (m.sentences || []).map((s) => [s]) : [m.sentences || [{ text: m.text, citations: [] }]]).map((group, g) => (
        <p key={g}>
          {group.map((s, i) => (
            <span key={i}>
              {s.text}
              {s.citations?.length > 0 && <span className="mono cite"> {s.citations.map((c) => `[${no[c] ?? c}]`).join(' ')}</span>}{' '}
            </span>
          ))}
        </p>
      ))}
      {m.message && <p className="small warn-text">{m.message}</p>}
      {evidence.length > 0 && (
        <details className="chat-sources">
          <summary className="small muted">
            {evidence.length} source{evidence.length === 1 ? '' : 's'}
            {m.query && <> · searched <span className="mono">{m.query}</span></>}
            {m.rerank && <> · reranked by {m.rerank.model.split('/').pop()}</>}
            {m.mode === 'llm' && m.model && <> · {m.model}</>}
          </summary>
          {evidence.map((e) => (
            <article key={e.evidence_id} className="evidence is-active">
              <div className="evidence-meta small">
                <span className="mono" style={{ color: 'var(--accent)' }}>[{no[e.evidence_id]}]</span>
                <span className="tag">{SOURCE_LABEL[e.source] || e.source}</span>
              </div>
              <strong>{e.url ? <a href={e.url} target="_blank" rel="noreferrer">{e.title}</a> : e.title}</strong>
              <p className="small muted clamp">{e.text}</p>
            </article>
          ))}
        </details>
      )}
    </>
  );
}
