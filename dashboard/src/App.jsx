import React, { useEffect, useState } from 'react';
import Sidebar from './components/Sidebar';
import Footer from './components/Footer';
import CookieConsent from './components/CookieConsent';
import DbBanner from './components/DbBanner';
import { HealthContext } from './context/health';
import { CatalogueContext } from './context/catalogue';
import { buildCatalogue, DEFAULT_CATALOGUE } from './lib/catalogue';
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

/** Parse "#/results/example.com" into { page, domain }. Unknown pages fall back to overview. */
function readHash() {
  const m = window.location.hash.match(/^#\/([a-z]+)(?:\/(.+))?$/);
  const page = m && TITLES[m[1]] ? m[1] : 'overview';
  let domain = '';
  try { domain = m && m[2] ? decodeURIComponent(m[2]) : ''; } catch { domain = ''; }
  return { page, domain };
}

export default function App() {
  const [{ page, domain }, setRoute] = useState(readHash);
  const [health, setHealth] = useState(null);
  const [catalogue, setCatalogue] = useState(DEFAULT_CATALOGUE);

  const setPage = (p) => setRoute((r) => ({ ...r, page: p }));
  const setDomain = (d) => setRoute((r) => ({ ...r, domain: d }));

  // Browser back/forward and pasted links update the route.
  useEffect(() => {
    const onHash = () => setRoute(readHash());
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);

  // Keep the URL in sync so the current view can be refreshed or shared.
  useEffect(() => {
    const wantsDomain = ['results', 'threat', 'network', 'attack'].includes(page) && domain;
    const hash = `#/${page}${wantsDomain ? `/${encodeURIComponent(domain)}` : ''}`;
    if (window.location.hash !== hash) window.history.replaceState(null, '', hash);
  }, [page, domain]);

  // The live module list: modules added on the backend show up without a frontend change.
  useEffect(() => {
    const controller = new AbortController();
    apiRequest('/api/modules', { signal: controller.signal })
      .then((payload) => setCatalogue(buildCatalogue(payload)))
      .catch(() => { /* keep the bundled snapshot */ });
    return () => controller.abort();
  }, []);

  usePolling(async (signal) => {
    try {
      const h = await apiRequest('/api/system-health', { signal });
      if (!signal.aborted) setHealth(h);
    } catch {
      if (!signal.aborted) setHealth({ api_status: 'offline' });
    }
  }, 15000);

  useEffect(() => { document.title = `WebAnalyzer · ${TITLES[page][0]}`; }, [page]);

  const openDomain = (d) => setRoute({ page: 'results', domain: d });
  const [title, sub] = TITLES[page];
  const contextDomain = ['results', 'threat', 'network', 'attack'].includes(page) && domain;

  return (
    <HealthContext.Provider value={health}>
    <CatalogueContext.Provider value={catalogue}>
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
          <DbBanner />
          {page === 'overview' && <Overview onOpenDomain={openDomain} onNewScan={() => setPage('scan')} />}
          {page === 'scan' && <NewScan onLaunched={openDomain} />}
          {page === 'results' && <Results key={domain} domain={domain} setDomain={setDomain} />}
          {page === 'threat' && <ThreatIntel key={domain} domain={domain} setDomain={setDomain} />}
          {page === 'network' && <NetworkMap key={domain} domain={domain} setDomain={setDomain} />}
          {page === 'attack' && <AttackPath key={domain} domain={domain} setDomain={setDomain} />}
          {page === 'legal' && <Legal />}
          <Footer onNav={setPage} />
        </div>
      </main>
      <CookieConsent onNav={setPage} />
    </div>
    </CatalogueContext.Provider>
    </HealthContext.Provider>
  );
}
