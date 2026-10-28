import { num } from '../utils/format.js';

const SOURCE_LABEL = { mitre: 'MITRE', procedure: 'Procedures', cti: 'CTI-HAL', cve: 'CVE' };

/** "How the evidence was found": retrieval trace drawn as a funnel,
    from candidates searched per source, to sources kept, to cited sentences. */
export default function EvidenceFunnel({ trace, explanation, evidenceCount }) {
  if (!trace) return null;
  const sources = trace.sources || [];
  const maxSearched = Math.max(1, ...sources.map((s) => s.searched ?? s.returned ?? 0));
  const sentences = explanation?.sentences || [];
  const cited = sentences.filter((s) => s.citations?.length).length;
  const generating = explanation?.status === 'generating';
  // e.g. "1 MITRE + 5 Procedures", so the total adds up visibly
  const kept = sources.filter((s) => s.returned > 0).map((s) => `${s.returned} ${SOURCE_LABEL[s.source] || s.source}`).join(' + ');

  return (
    <div role="group" aria-label="How the evidence was found" style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      <div className="funnel-query small"><span className="funnel-title">1. Query</span> <span className="mono">{trace.query}</span></div>
      <div className="funnel">
      <div className="funnel-step funnel-wide">
        <span className="funnel-title">2. Search by technique</span>
        <div className="funnel-sources">
          {sources.map((s) => (
            <div key={s.source} className={`funnel-src ${s.skipped ? 'is-skipped' : ''}`}>
              <span className="small">{SOURCE_LABEL[s.source] || s.source}</span>
              <span className="funnel-bar" aria-hidden="true">
                <span style={{ width: `${((s.searched ?? s.returned) / maxSearched) * 100}%`, background: 'var(--normal)' }} />
                <span style={{ width: `${(s.returned / maxSearched) * 100}%`, background: 'var(--accent)', minWidth: s.returned ? 3 : 0 }} />
              </span>
              <span className="mono small funnel-num">
                {s.skipped ? 'not used' : s.searched != null ? `${num(s.returned)} of ${num(s.searched)}` : `${num(s.returned)} match`}
              </span>
            </div>
          ))}
        </div>
        <span className="small muted">Grey = candidates scored · blue = kept</span>
      </div>
      <Arrow />
      <div className="funnel-step">
        <span className="funnel-title">3. Rank</span>
        <span className="funnel-big">{num(evidenceCount)}</span>
        <span className="small muted">sources kept: {kept || 'none'}</span>
        <span className="small muted">Technique page plus the best {trace.top_k ?? '—'} others{trace.min_score != null ? `, score ≥ ${trace.min_score}` : ''}</span>
        <span className={`small ${trace.fallback_to_tactic ? 'warn-text' : 'muted'}`}>
          {trace.fallback_to_tactic ? 'Fell back to tactic-level evidence' : 'Technique-level match, no fallback'}
        </span>
      </div>
      <Arrow />
      <div className="funnel-step">
        <span className="funnel-title">4. Generate</span>
        {generating ? <span className="muted">Writing…</span> : (
          <>
            <span>{explanation?.mode === 'llm' ? explanation.model || 'LLM' : 'Evidence only, no LLM'}</span>
            {explanation?.latency_ms != null && explanation.mode === 'llm' && <span className="small muted">{(explanation.latency_ms / 1000).toFixed(1)} s</span>}
          </>
        )}
      </div>
      <Arrow />
      <div className="funnel-step">
        <span className="funnel-title">5. Check</span>
        {generating ? <span className="muted">Waiting</span> : (
          <>
            <span className="funnel-big">{cited}<span className="muted" style={{ fontSize: 15 }}> of {sentences.length}</span></span>
            <span className="small muted">sentences cite evidence</span>
            {explanation?.groundedness != null && <span className="small">Groundedness <span className="mono">{explanation.groundedness.toFixed(2)}</span></span>}
          </>
        )}
      </div>
      </div>
    </div>
  );
}

const Arrow = () => (
  <svg className="funnel-arrow" width="18" height="18" viewBox="0 0 24 24" aria-hidden="true">
    <path d="M5 12h13M13 6l6 6-6 6" fill="none" stroke="var(--muted)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);
