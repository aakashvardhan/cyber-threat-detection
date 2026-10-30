import { Route, Routes } from 'react-router-dom';
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
          <Route path="/evaluation" element={<ComingNext title="Evaluation" what="Model comparison on the test split (GET /metrics)." />} />
          <Route path="/knowledge-base" element={<ComingNext title="Knowledge base" what="Everything the RAG pipeline can cite, by technique." />} />
          <Route path="*" element={<ComingNext title="Page not found" what="Use the menu to go back." />} />
        </Routes>
      </main>
    </div>
  );
}
