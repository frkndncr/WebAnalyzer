import React, { useEffect, useState } from 'react';
import Sidebar from './components/Sidebar';
import Footer from './components/Footer';
import CookieConsent from './components/CookieConsent';
import Overview from './pages/Overview';
import NewScan from './pages/NewScan';
import Results from './pages/Results';
import ThreatIntel from './pages/ThreatIntel';
import NetworkMap from './pages/NetworkMap';
import AttackPath from './pages/AttackPath';
import Legal from './pages/Legal';
import { apiRequest } from './api/client';
import { usePolling } from './hooks/useApi';

const TITLES = {
  overview: ['Overview', 'Security posture across all scans'],
  scan: ['New Scan', 'Configure and launch reconnaissance'],
  results: ['Results', 'Per-module findings and report export'],
  threat: ['Threat Intelligence', 'MITRE mapping, IOCs and risk scoring'],
  network: ['Network Map', 'Subdomains, technologies and look-alikes'],
  attack: ['Attack Path', 'Exploit chains and graph analysis'],
  legal: ['Legal & Privacy', 'Policies, KVKK notice and terms'],
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

  useEffect(() => { document.title = `WebAnalyzer · ${TITLES[page][0]}`; }, [page]);

  const openDomain = (d) => { setDomain(d); setPage('results'); };
  const [title, sub] = TITLES[page];
  const contextDomain = ['results', 'threat', 'network', 'attack'].includes(page) && domain;

  return (
    <div className="app">
      <Sidebar active={page} onNav={setPage} health={health} />
      <main className="main">
        <div className="topbar">
          <div>
            <h1>{title}</h1>
            <div className="sub">{contextDomain || sub}</div>
          </div>
        </div>
        <div className="content">
          {page === 'overview' && <Overview onOpenDomain={openDomain} />}
          {page === 'scan' && <NewScan onLaunched={openDomain} />}
          {page === 'results' && <Results key={domain} domain={domain} />}
          {page === 'threat' && <ThreatIntel key={domain} domain={domain} setDomain={setDomain} />}
          {page === 'network' && <NetworkMap key={domain} domain={domain} setDomain={setDomain} />}
          {page === 'attack' && <AttackPath key={domain} domain={domain} setDomain={setDomain} />}
          {page === 'legal' && <Legal />}
          <Footer onNav={setPage} />
        </div>
      </main>
      <CookieConsent onNav={setPage} />
    </div>
  );
}
