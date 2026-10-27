import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react';
import { api } from '../api/client.js';

// The browser drives the replay: one POST /detect per tick, then GET /incidents.
// State lives here so the replay keeps running while the analyst moves between pages.

export const SPEEDS = [
  { ms: 5000, label: '1 window / 5 s' },
  { ms: 2000, label: '1 window / 2 s' },
  { ms: 1000, label: '1 window / 1 s' },
  { ms: 250, label: '4 windows / 1 s' },
];

const ReplayContext = createContext(null);

export function ReplayProvider({ children }) {
  const [data, setData] = useState(null); // GET /incidents response
  const [playing, setPlaying] = useState(false);
  const [speedMs, setSpeedMs] = useState(SPEEDS[0].ms);
  const [error, setError] = useState(null);
  const [finished, setFinished] = useState(false);
  const [seenIds, setSeenIds] = useState(null); // incidents the analyst has already been shown
  const busy = useRef(false);

  const refresh = useCallback(async () => {
    const next = await api.listIncidents();
    setData(next);
    setSeenIds((prev) => prev ?? new Set(next.incidents.map((i) => i.incident_id)));
    return next;
  }, []);

  const run = useCallback(async (args) => {
    if (busy.current) return;
    busy.current = true;
    try {
      await api.detect(args);
      setFinished(false);
      await refresh();
      setError(null);
    } catch (e) {
      if (e.status === 409) {
        setFinished(true);
        setPlaying(false);
      } else {
        setError(e.message);
        setPlaying(false);
      }
    } finally {
      busy.current = false;
    }
  }, [refresh]);

  // Load the current position once; the backend keeps state between page loads.
  useEffect(() => {
    refresh().catch((e) => setError(e.message));
  }, [refresh]);

  // Replay loop: wait for each window to finish before scheduling the next.
  useEffect(() => {
    if (!playing) return undefined;
    let cancelled = false;
    let timer;
    const loop = async () => {
      await run();
      if (!cancelled) timer = setTimeout(loop, speedMs);
    };
    timer = setTimeout(loop, 0);
    return () => { cancelled = true; clearTimeout(timer); };
  }, [playing, speedMs, run]);

  const value = useMemo(() => ({
    data,
    incidents: data?.incidents ?? [],
    playing,
    speedMs,
    error,
    finished,
    seenIds: seenIds ?? new Set(),
    togglePlay: () => setPlaying((p) => !p),
    pause: () => setPlaying(false),
    setSpeedMs,
    step: () => { setPlaying(false); return run(); },
    jumpTo: (windowStart) => { setPlaying(false); return run({ windowStart }); },
    restart: async () => {
      setPlaying(false);
      await run({ reset: true });
      setSeenIds(null);
    },
    markAllSeen: () => setSeenIds(new Set((data?.incidents ?? []).map((i) => i.incident_id))),
    refresh,
    clearError: () => setError(null),
  }), [data, playing, speedMs, error, finished, seenIds, run, refresh]);

  return <ReplayContext.Provider value={value}>{children}</ReplayContext.Provider>;
}

export function useReplay() {
  const ctx = useContext(ReplayContext);
  if (!ctx) throw new Error('useReplay must be used inside <ReplayProvider>');
  return ctx;
}
