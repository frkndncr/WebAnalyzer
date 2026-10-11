import React, { useEffect, useState } from 'react';
import Sidebar from './components/Sidebar';
import Overview from './pages/Overview';
import NewScan from './pages/NewScan';
import Results from './pages/Results';
import { apiRequest } from './api/client';
import { usePolling } from './hooks/useApi';

const TITLES = {
  overview: ['Overview', 'Security posture across all scans'],
  scan: ['New Scan', 'Configure and launch reconnaissance'],
  results: ['Results', 'Per-module findings and report export'],
};

export default function App() {
  const [page, setPage] = useState('overview');
  const [domain, setDomain] = useState('');
  const [health, setHealth] = useState(null);

  usePolling(async (signal) => {
    try {
      const h = await apiRequest('/api/system-health', { signal });
      if (!signal.aborted) setHealth(h);
    } catch {
      if (!signal.aborted) setHealth({ api_status: 'offline' });
    }
  }, 15000);

  // Clear health poll dependency note: usePolling handles mount + interval.
  useEffect(() => { document.title = `WebAnalyzer · ${TITLES[page][0]}`; }, [page]);

  const openDomain = (d) => { setDomain(d); setPage('results'); };
  const [title, sub] = TITLES[page];

  return (
    <div className="app">
      <Sidebar active={page} onNav={setPage} health={health} />
      <main className="main">
        <div className="topbar">
          <div>
            <h1>{title}</h1>
            <div className="sub">{page === 'results' && domain ? domain : sub}</div>
          </div>
        </div>
        <div className="content">
          {page === 'overview' && <Overview onOpenDomain={openDomain} />}
          {page === 'scan' && <NewScan onLaunched={openDomain} />}
          {page === 'results' && <Results key={domain} domain={domain} />}
        </div>
      </main>
    </div>
  );
}
