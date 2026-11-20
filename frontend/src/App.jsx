import { Route, Routes } from 'react-router-dom';
import Evaluation from './pages/Evaluation.jsx';
import KnowledgeBase from './pages/KnowledgeBase.jsx';
import Sidebar from './components/Sidebar.jsx';
import ComingNext from './pages/ComingNext.jsx';
import IncidentDetail from './pages/IncidentDetail.jsx';
import Incidents from './pages/Incidents.jsx';
import Overview from './pages/Overview.jsx';

export default function App() {
  return (
    <div className="app">
      <Sidebar />
      <main className="main">
        <Routes>
          <Route path="/" element={<Overview />} />
          <Route path="/incidents" element={<Incidents />} />
          <Route path="/incidents/:id" element={<IncidentDetail />} />
          <Route path="/reports" element={<ComingNext title="Reports" what="Printable investigation reports built from incident data." />} />
          <Route path="/evaluation" element={<Evaluation />} />
          <Route path="/knowledge-base" element={<KnowledgeBase />} />
          <Route path="*" element={<ComingNext title="Page not found" what="Use the menu to go back." />} />
        </Routes>
      </main>
    </div>
  );
}
