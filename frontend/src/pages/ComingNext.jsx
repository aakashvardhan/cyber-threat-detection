import { ReplayStrip } from '../components/ReplayBar.jsx';

/** Fallback page for unknown routes. */
export default function ComingNext({ title, what }) {
  return (
    <>
      <ReplayStrip />
      <div className="page">
        <header className="page-head"><div><h1>{title}</h1><p>{what}</p></div></header>
      </div>
    </>
  );
}
