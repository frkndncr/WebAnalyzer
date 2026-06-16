import React, { useState, useEffect, useRef } from 'react';
import DocumentationModal from './DocumentationModal';
import InteractiveJson from './InteractiveJson';
import { getApiUrl } from '../config';

const SECTIONS = [
  { id: 'overview', title: 'Overview', icon: '📋', layer: 'ALL', description: 'Module information, 5-layer architecture', docFile: '01-genel-bakis.md' },
  { id: 'data_classes', title: 'Data Classes', icon: '🏗️', layer: 'CORE', description: '6 data class structures, hash deduplication', docFile: '02-veri-siniflari.md' },
  { id: 'pattern_registry', title: 'Pattern Registry', icon: '📖', layer: 'CORE', description: '40+ secret patterns, 14 JS categories', docFile: '03-pattern-registry.md' },
  { id: 'crawl_engine', title: 'Crawl Engine', icon: '🕷️', layer: 'L1', description: 'Concurrent crawl engine, sitemap, robots.txt', docFile: '04-crawl-engine.md' },
  { id: 'secret_scanner', title: 'Secret Scanner', icon: '🔐', layer: 'L1+L3', description: 'Secret information scan, entropy, risk scoring', docFile: '05-secret-scanner.md' },
  { id: 'js_analysis', title: 'JS Analysis & Taint', icon: '⚡', layer: 'L1+L3', description: 'JS security analysis, taint-flow tracking', docFile: '06-js-analysis.md' },
  { id: 'ssrf_detection', title: 'SSRF Detection', icon: '🎯', layer: 'L1+L2', description: 'SSRF passive/active detection', docFile: '07-ssrf-detection.md' },
  { id: 'active_testing', title: 'Active Testing', icon: '⚔️', layer: 'L2', description: 'Fuzzing, auth bypass, CORS, Nuclei', docFile: '08-active-testing.md' },
  { id: 'headless_browser', title: 'Headless Browser', icon: '🌐', layer: 'L4', description: 'Playwright runtime analysis', docFile: '09-headless-browser.md' },
  { id: 'exploit_chains', title: 'Exploit Chains', icon: '⛓️', layer: 'L5', description: 'Exploit chain building', docFile: '10-exploit-chains.md' },
  { id: 'waf_detection', title: 'WAF Detection', icon: '🛡️', layer: 'L5', description: 'WAF detection and adaptive strategy', docFile: '11-waf-detection.md' },
  { id: 'utilities', title: 'Utilities & Helpers', icon: '🔧', layer: 'ALL', description: 'Helper functions, CLI', docFile: '12-utilities-and-helpers.md' },
  { id: 'main_flow', title: 'Main Flow (run())', icon: '🚀', layer: 'ALL', description: 'Full scan pipeline', docFile: '13-ana-akis.md' },
];

const LAYER_COLORS = { 'L1': '#58a6ff', 'L2': '#d29922', 'L3': '#3fb950', 'L4': '#bc8cff', 'L5': '#f85149', 'CORE': '#8b949e', 'ALL': '#e6edf3', 'L1+L3': '#3fb950', 'L1+L2': '#d29922' };

const AdvancedScannerPanel = ({ domain: propDomain }) => {
  const [domain, setDomain] = useState(propDomain || '');
  const [statuses, setStatuses] = useState({});
  const [results, setResults] = useState({});
  const [docModal, setDocModal] = useState({ open: false, file: null });
  const [expandedResult, setExpandedResult] = useState(null);
  const [runAllActive, setRunAllActive] = useState(false);
  const [runAllProgress, setRunAllProgress] = useState(0);
  const pollRefs = useRef({});

  // Cleanup polls on unmount
  useEffect(() => {
    return () => {
      Object.values(pollRefs.current).forEach(id => clearInterval(id));
    };
  }, []);

  const pollStatus = (sectionId) => {
    const poll = setInterval(async () => {
      try {
        const resp = await fetch(getApiUrl(`/api/scan/section/status?domain=${encodeURIComponent(domain)}&section=${sectionId}`));
        if (resp.ok) {
          const data = await resp.json();
          if (data.status === 'completed') {
            setStatuses(prev => ({ ...prev, [sectionId]: 'completed' }));
            setResults(prev => ({ ...prev, [sectionId]: data.result }));
            clearInterval(poll);
            delete pollRefs.current[sectionId];
          } else if (data.status === 'error') {
            setStatuses(prev => ({ ...prev, [sectionId]: 'error' }));
            setResults(prev => ({ ...prev, [sectionId]: { error: data.error } }));
            clearInterval(poll);
            delete pollRefs.current[sectionId];
          }
        }
      } catch { /* ignore */ }
    }, 2000);
    pollRefs.current[sectionId] = poll;
  };

  const runSection = async (sectionId) => {
    if (!domain) { alert('Domain field is required!'); return; }
    setStatuses(prev => ({ ...prev, [sectionId]: 'running' }));
    setResults(prev => { const n = { ...prev }; delete n[sectionId]; return n; });
    try {
      const resp = await fetch(getApiUrl('/api/scan/section'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain, section: sectionId }),
      });
      if (resp.ok) {
        pollStatus(sectionId);
      } else {
        setStatuses(prev => ({ ...prev, [sectionId]: 'error' }));
        setResults(prev => ({ ...prev, [sectionId]: { error: 'API did not respond' } }));
      }
    } catch {
      setStatuses(prev => ({ ...prev, [sectionId]: 'error' }));
      setResults(prev => ({ ...prev, [sectionId]: { error: 'Failed to connect to API' } }));
    }
  };

  const runAll = async () => {
    if (!domain) { alert('Domain field is required!'); return; }
    setRunAllActive(true);
    setRunAllProgress(0);
    for (let i = 0; i < SECTIONS.length; i++) {
      await runSection(SECTIONS[i].id);
      // Wait for it to finish before moving on
      await new Promise(resolve => {
        const check = setInterval(() => {
          setStatuses(prev => {
            const s = prev[SECTIONS[i].id];
            if (s === 'completed' || s === 'error') {
              clearInterval(check);
              resolve();
            }
            return prev;
          });
        }, 1000);
      });
      setRunAllProgress(Math.round(((i + 1) / SECTIONS.length) * 100));
    }
    setRunAllActive(false);
  };

  const statusBadge = (id) => {
    const s = statuses[id];
    if (s === 'running') return <span className="acs-status-badge acs-status-running">⏳ Running</span>;
    if (s === 'completed') return <span className="acs-status-badge acs-status-completed">✅ Completed</span>;
    if (s === 'error') return <span className="acs-status-badge acs-status-error">❌ Error</span>;
    return <span className="acs-status-badge acs-status-idle">⏸ Ready</span>;
  };

  return (
    <div className="animate-fade-in" style={{ maxWidth: '1100px', margin: '0 auto' }}>
      <DocumentationModal isOpen={docModal.open} docFile={docModal.file} onClose={() => setDocModal({ open: false, file: null })} />

      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginBottom: '1.5rem' }}>
        <div>
          <h2 style={{ fontSize: '2rem', marginBottom: '0.3rem', display: 'flex', alignItems: 'center', gap: '12px' }}>
            <span className="text-gradient">Advanced Content Scanner</span>
            <span style={{ fontSize: '0.8rem', padding: '3px 10px', borderRadius: '4px', background: 'rgba(188, 140, 255, 0.15)', color: 'var(--accent-purple)' }}>v4.0</span>
          </h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.88rem' }}>5-Layer Security Analysis Module — 13 Components</p>
        </div>
        <div className="glass-panel" style={{ padding: '0.8rem 1.2rem', display: 'flex', gap: '1.5rem', fontSize: '0.82rem' }}>
          <div><span style={{ color: 'var(--text-secondary)' }}>Components: </span><strong>13</strong></div>
          <div><span style={{ color: 'var(--text-secondary)' }}>Patterns: </span><strong>40+</strong></div>
          <div><span style={{ color: 'var(--text-secondary)' }}>Lines: </span><strong>2545</strong></div>
        </div>
      </div>

      {/* Domain + Run All */}
      <div className="glass-panel" style={{ padding: '1.2rem', marginBottom: '1.5rem', display: 'flex', gap: '1rem', alignItems: 'center' }}>
        <div style={{ flex: 1 }}>
          <input type="text" className="input-glass" placeholder="example.com"
            value={domain} onChange={e => setDomain(e.target.value)} style={{ fontSize: '1rem' }} />
        </div>
        <button className="btn-primary" onClick={runAll} disabled={runAllActive || !domain}
          style={{ whiteSpace: 'nowrap', display: 'flex', alignItems: 'center', gap: '8px' }}>
          {runAllActive ? (<><div className="status-indicator pending" style={{ margin: 0 }}></div> {runAllProgress}%</>) : (<>🚀 Run All</>)}
        </button>
      </div>

      {runAllActive && (
        <div className="progress-container" style={{ marginBottom: '1.5rem' }}>
          <div className="progress-bar-fill" style={{ width: `${runAllProgress}%` }}></div>
        </div>
      )}

      {/* Section Cards — Clean & Minimal */}
      <div className="acs-cards-grid">
        {SECTIONS.map((sec) => (
          <div key={sec.id} className="acs-card">
            <div className="acs-card-header" style={{ cursor: 'default' }}>
              {/* Left: Icon + Info */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flex: 1 }}>
                <span style={{ fontSize: '1.4rem' }}>{sec.icon}</span>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span style={{ fontWeight: 600, fontSize: '0.95rem' }}>{sec.title}</span>
                    <span className="acs-layer-tag" style={{ color: LAYER_COLORS[sec.layer] }}>{sec.layer}</span>
                  </div>
                  <p style={{ color: 'var(--text-secondary)', fontSize: '0.78rem', margin: '2px 0 0' }}>{sec.description}</p>
                </div>
              </div>

              {/* Right: status + buttons */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                {statusBadge(sec.id)}
                <button className="btn-primary" style={{ padding: '0.35rem 0.8rem', fontSize: '0.75rem' }}
                  onClick={() => runSection(sec.id)} disabled={statuses[sec.id] === 'running'}>
                  {statuses[sec.id] === 'running' ? '⏳' : '▶'} Run
                </button>
                <button className="btn-outline" style={{ padding: '0.35rem 0.8rem', fontSize: '0.75rem' }}
                  onClick={() => setDocModal({ open: true, file: sec.docFile })}>
                  📖 Docs
                </button>
              </div>
            </div>

            {/* Result area — only shown when there are results */}
            {results[sec.id] && (
              <div className="acs-card-result">
                <div className="acs-card-result-header" onClick={() => setExpandedResult(expandedResult === sec.id ? null : sec.id)}>
                  <span style={{ fontSize: '0.82rem', color: 'var(--accent-green)', fontWeight: 600 }}>
                    {results[sec.id].error ? '❌ Error' : '📊 Results'}
                  </span>
                  <span style={{ color: 'var(--text-secondary)', fontSize: '0.8rem', transform: expandedResult === sec.id ? 'rotate(180deg)' : 'none', transition: '0.2s' }}>▼</span>
                </div>
                {expandedResult === sec.id && (
                  <div className="acs-card-result-body">
                    {results[sec.id].error ? (
                      <div style={{ color: 'var(--accent-red)', fontSize: '0.85rem', padding: '0.5rem' }}>{results[sec.id].error}</div>
                    ) : (
                      <div className="json-view" style={{ maxHeight: '300px', overflow: 'auto' }}>
                        <InteractiveJson data={results[sec.id]} initExpanded={true} />
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};

export default AdvancedScannerPanel;
