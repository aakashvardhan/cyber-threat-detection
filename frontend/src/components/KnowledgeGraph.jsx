import { useState } from 'react';
import { num } from '../utils/format.js';

// The ATT&CK subgraph GraphRAG retrieved for an incident (retrieval_trace.graph), drawn in lanes:
//   documented users | the predicted technique (tactic above, community below) | what users do next
//   with mitigations and detection data underneath. Nodes cited by the selected sentence light up.

const C = { seed: '#FF4040', user: '#F5B14C', next: '#4CB3E6', alternative: '#F5B14C', history: '#FF8080',
  mitigation: '#3FB68B', data: '#9AA9BC', community: '#A08CE0', tactic: '#9AA9BC', context: '#5F7A96',
  text: '#E6EDF3', muted: '#9AA9BC', panel: '#1B2838', border: '#2A3B50' };
const ROLE_LABEL = { seed: 'Predicted technique', user: 'Documented user', next: 'Often used by the same actors',
  alternative: 'Behaviour check alternative', history: 'Earlier activity from this source', mitigation: 'Mitigation',
  data: 'Detection data', community: 'Technique community', tactic: 'Tactic', context: 'Context' };
const W = 1000, H = 470;
const short = (s, n = 24) => (s.length > n ? s.slice(0, n - 1) + '…' : s);

function layout(nodes) {
  const by = (role) => nodes.filter((n) => n.role === role);
  const pos = {};
  const column = (list, x, top, bottom) => list.forEach((n, i) => {
    pos[n.id] = { x, y: list.length === 1 ? (top + bottom) / 2 : top + (i * (bottom - top)) / (list.length - 1) };
  });
  const seed = by('seed')[0];
  if (seed) pos[seed.id] = { x: W / 2, y: 190 };
  column(by('tactic'), W / 2, 60, 60);
  column(by('community'), W / 2, 300, 300);
  column([...by('user')], 150, 50, 330);
  column([...by('next'), ...by('alternative'), ...by('history')], W - 150, 70, 310);
  const bottom = [...by('mitigation'), ...by('data')];
  bottom.forEach((n, i) => { pos[n.id] = { x: 150 + (i + 0.5) * ((W - 300) / Math.max(bottom.length, 1)), y: 420 }; });
  return pos;
}

function Shape({ n, p, lit, selected }) {
  const color = C[n.role] || C.context;
  const big = n.role === 'seed';
  const w = big ? 190 : 150, h = big ? 46 : 34;
  const stroke = selected ? C.text : lit ? color : C.border;
  const dash = n.role === 'alternative' ? '5 4' : undefined;
  const glow = lit ? { filter: `drop-shadow(0 0 6px ${color})` } : undefined;
  const actor = n.type === 'Group' || n.type === 'Software' || n.type === 'Campaign';
  return (
    <g style={glow}>
      {actor ? (
        <rect x={p.x - w / 2} y={p.y - h / 2} width={w} height={h} rx={h / 2} fill={C.panel} stroke={stroke} strokeWidth={lit || selected ? 2 : 1} />
      ) : (
        <rect x={p.x - w / 2} y={p.y - h / 2} width={w} height={h} rx={6} fill={big ? '#3A1E24' : C.panel} stroke={big ? color : stroke}
          strokeWidth={big || lit || selected ? 2 : 1} strokeDasharray={dash} />
      )}
      <rect x={p.x - w / 2} y={p.y - h / 2 + 6} width={3} height={h - 12} rx={1.5} fill={color} />
      <text x={p.x - w / 2 + 12} y={p.y - (big ? 4 : 2)} fill={C.text} fontSize={big ? 13 : 11.5} fontWeight={big ? 600 : 500}>{short(n.name, big ? 26 : 21)}</text>
      <text x={p.x - w / 2 + 12} y={p.y + (big ? 13 : 11)} fill={C.muted} fontSize={10} fontFamily="ui-monospace, Menlo, Consolas, monospace">
        {n.id.startsWith('COM-') ? 'community' : n.id}{actor ? ` · ${n.type.toLowerCase()}` : ''}
      </text>
    </g>
  );
}

export default function KnowledgeGraph({ trace, active, evidenceNo }) {
  const g = trace?.graph;
  const [picked, setPicked] = useState(null);
  if (!g?.nodes?.length) return null;
  const pos = layout(g.nodes);
  const nodes = g.nodes.filter((n) => pos[n.id]);
  const byId = Object.fromEntries(nodes.map((n) => [n.id, n]));
  const seed = nodes.find((n) => n.role === 'seed');
  const lit = (n) => n.evidence_ids?.some((e) => active?.has(e));
  // draw only the links that explain the picture: actors to the technique and to what they do next, defences, context
  const edges = g.edges.filter((e) => byId[e.source] && byId[e.target]);
  const pick = picked && byId[picked];
  const users = nodes.filter((n) => n.role === 'user').length;

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Knowledge graph <span className="muted" style={{ fontWeight: 400 }}>· GraphRAG</span></h2>
        <span className="small muted">
          MITRE ATT&amp;CK graph in {g.store === 'neo4j' ? 'Neo4j' : 'memory'} · {num(g.actors)} actors use {seed?.id} · showing {users} most related
        </span>
      </div>
      <div className="panel-body kg">
        <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`Knowledge graph around ${seed?.id}: ${nodes.length} nodes`} className="kg-svg">
          <text x={150} y={22} fill={C.muted} fontSize={11} textAnchor="middle">DOCUMENTED USERS</text>
          <text x={W / 2} y={22} fill={C.muted} fontSize={11} textAnchor="middle">PREDICTED TECHNIQUE</text>
          <text x={W - 150} y={22} fill={C.muted} fontSize={11} textAnchor="middle">WHAT THESE ACTORS ALSO DO</text>
          <text x={W / 2} y={378} fill={C.muted} fontSize={11} textAnchor="middle">MITIGATE AND DETECT</text>
          {edges.map((e, i) => {
            const a = pos[e.source], b = pos[e.target];
            const toNext = byId[e.target].role === 'next' || byId[e.target].role === 'alternative';
            const fromUser = byId[e.source].role === 'user';
            const on = picked && (e.source === picked || e.target === picked);
            const faint = fromUser && toNext;
            return (
              <line key={i} x1={a.x} y1={a.y} x2={b.x} y2={b.y}
                stroke={on ? C.text : faint ? C.border : '#41566F'} strokeOpacity={on ? 0.9 : faint ? 0.6 : 0.8}
                strokeWidth={on ? 1.6 : 1} strokeDasharray={e.relation === 'IN_COMMUNITY' || e.relation === 'IN_TACTIC' ? '3 3' : undefined}>
                <title>{`${byId[e.source].name} ${e.relation.replace(/_/g, ' ').toLowerCase()} ${byId[e.target].name}`}</title>
              </line>
            );
          })}
          {nodes.map((n) => (
            <g key={n.id} onClick={() => setPicked(picked === n.id ? null : n.id)} style={{ cursor: 'pointer' }}
              role="button" tabIndex={0} aria-label={`${n.name}, ${ROLE_LABEL[n.role] || n.role}`}
              onKeyDown={(ev) => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); setPicked(picked === n.id ? null : n.id); } }}>
              <Shape n={n} p={pos[n.id]} lit={lit(n)} selected={picked === n.id} />
            </g>
          ))}
        </svg>
        <div className="kg-side">
          {pick ? (
            <div className="kg-card">
              <span className="small" style={{ color: C[pick.role] }}>{ROLE_LABEL[pick.role] || pick.role}</span>
              <strong>{pick.url ? <a href={pick.url} target="_blank" rel="noreferrer">{pick.name}</a> : pick.name}</strong>
              <span className="mono small muted">{pick.id} · {pick.type}</span>
              {pick.evidence_ids?.length > 0 && (
                <span className="small">Cited in evidence {pick.evidence_ids.map((e) => `[${evidenceNo[e] ?? e}]`).join(' ')}</span>
              )}
              <span className="small muted">PageRank from the predicted technique <span className="mono">{pick.score.toFixed(4)}</span></span>
            </div>
          ) : (
            <p className="small muted" style={{ margin: 0 }}>
              Select a node for details. Nodes cited by the selected sentence light up. Users are documented
              tradecraft from ATT&amp;CK, not attribution of this incident.
            </p>
          )}
          <ul className="kg-legend small">
            {['seed', 'user', 'next', 'alternative', 'history', 'mitigation', 'data', 'community'].filter((r) => r !== 'alternative' && r !== 'history' || nodes.some((n) => n.role === r)).map((r) => (
              <li key={r}><span style={{ background: C[r] }} />{ROLE_LABEL[r]}</li>
            ))}
          </ul>
          <p className="small muted" style={{ margin: 0 }}>
            {g.method}. Searched {num(g.subgraph.nodes)} nodes and {num(g.subgraph.edges)} relations{g.seeds.length > 1 ? ` from ${g.seeds.join(', ')}` : ''}.
          </p>
        </div>
      </div>
    </section>
  );
}
