import { ReplayStrip } from '../components/ReplayBar.jsx';

/** Placeholder for pages planned for the next round (Reports, Evaluation, Knowledge base). */
export default function ComingNext({ title, what }) {
  return (
    <>
      <ReplayStrip />
      <div className="page">
        <header className="page-head"><div><h1>{title}</h1><p>{what}</p></div></header>
        <section className="panel empty">This page is in the design (prototype v1.1) and comes in the next round of the build.</section>
      </div>
    </>
  );
}
