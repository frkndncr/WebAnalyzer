import React, { useState, useEffect } from 'react';
import EducationModal from './EducationModal';
import { getApiUrl } from '../config';
import { apiGet } from '../api/client';
import { SeverityBar, ModuleErrorBoundary, ModuleResultRenderer } from './results/moduleRenderers';
import { categorizeModule } from './results/helpers';

const ResultsPanel = ({ domain, setCurrentDomain }) => {
  const [activeDomain, setActiveDomain] = useState(domain || 'example.com');
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [modalState, setModalState] = useState({ isOpen: false, moduleName: '' });
  const [activeFilter, setActiveFilter] = useState('all');
  const [recentScans, setRecentScans] = useState([]);

  // Sync prop changes to activeDomain state
  useEffect(() => {
    if (domain && domain !== activeDomain) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setActiveDomain(domain);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [domain]);

  // Fetch recent scans once on mount
  useEffect(() => {
    const fetchRecent = async () => {
      try {
        const json = await apiGet('/api/recent-scans');
        setRecentScans(json);
        // If activeDomain is default un-scanned example.com and we have past scans, auto-select the latest one
        if (activeDomain === 'example.com' && json.length > 0) {
          const latestDomain = json[0].domain;
          setActiveDomain(latestDomain);
          if (setCurrentDomain) {
            setCurrentDomain(latestDomain);
          }
        }
      } catch (err) {
        console.error('Error fetching recent scans', err);
      }
    };
    fetchRecent();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    let interval;
    const fetchResults = async (showLoading = false) => {
      if (showLoading) {
        setLoading(true);
      }
      try {
        const json = await apiGet(`/api/status/${activeDomain}`);
        setData(json);
        setError(null);
        setLoading(false);
        if (json.current_module === 'Finished') {
          clearInterval(interval);
        }
      } catch (err) {
        setLoading(false);
        setData(null);
        if (err?.status === 404) {
          setError(`No scan results found for ${activeDomain}. Run a scan to get started.`);
        } else if (err?.status) {
          setError('Waiting for backend acknowledgment...');
        } else {
          setError('Cannot connect to API server.');
        }
        clearInterval(interval);
      }
    };

    fetchResults(true);
    interval = setInterval(() => fetchResults(false), 2000);
    return () => clearInterval(interval);
  }, [activeDomain]);

  const handleDomainChange = (e) => {
    const val = e.target.value;
    if (val) {
      setActiveDomain(val);
      if (setCurrentDomain) {
        setCurrentDomain(val);
      }
    }
  };

  const openEducationModal = (moduleName) => {
    setModalState({ isOpen: true, moduleName });
  };

  const exportJSON = () => {
    if (!data || !data.results) return;
    const blob = new Blob([JSON.stringify(data.results, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${activeDomain}-results.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const exportReport = () => {
    if (!activeDomain) return;
    const url = getApiUrl(`/api/report/${encodeURIComponent(activeDomain)}`);
    window.open(url, '_blank');
  };



  const progressPercent = data && data.total ? Math.round((data.completed / data.total) * 100) : 0;
  const isFinished = data && data.current_module === 'Finished';

  const filterTabs = [
    { id: 'all', label: 'All', icon: '📋' },
    { id: 'vulnerabilities', label: 'Vulnerabilities', icon: '🔴' },
    { id: 'information', label: 'Information', icon: '🔵' },
    { id: 'errors', label: 'Errors', icon: '⚠️' },
  ];

  const filteredEntries = data && data.results
    ? Object.entries(data.results).filter(([moduleName, moduleData]) => {
        // Exclude Attack Path Planner since it has its own dedicated tab
        if (moduleName === 'Attack Path Planner') return false;

        if (activeFilter === 'all') return true;
        if (activeFilter === 'errors') return moduleData && moduleData.error;
        
        if (['critical', 'high', 'medium', 'low', 'info'].includes(activeFilter)) {
          const vulns = Array.isArray(moduleData)
            ? moduleData
            : Array.isArray(moduleData?.vulnerabilities)
              ? moduleData.vulnerabilities
              : Array.isArray(moduleData?.vulnerable_subdomains)
                ? moduleData.vulnerable_subdomains
                : [];
          return vulns.some(v => v && typeof v === 'object' && (v.severity || v.confidence || 'medium').toLowerCase() === activeFilter);
        }

        const cats = categorizeModule(moduleName, moduleData);
        return cats.includes(activeFilter);
      })
    : [];

  return (
    <div className="animate-fade-in" style={{ maxWidth: '1000px', margin: '0 auto' }}>
      <EducationModal 
        isOpen={modalState.isOpen} 
        moduleName={modalState.moduleName} 
        onClose={() => setModalState({ isOpen: false, moduleName: '' })} 
      />

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginBottom: '1rem', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ fontSize: '2rem', marginBottom: '0.5rem' }}>Analysis Results</h2>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <span style={{ color: 'var(--text-secondary)' }}>Target: </span>
            {recentScans.length > 0 ? (
              <select
                value={activeDomain}
                onChange={handleDomainChange}
                className="input-glass"
                style={{
                  padding: '6px 12px',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '0.9rem',
                  color: 'var(--accent-blue)',
                  border: '1px solid var(--panel-border)',
                  borderRadius: '6px',
                  background: 'rgba(0,0,0,0.5)',
                  cursor: 'pointer',
                  minWidth: '200px'
                }}
              >
                {recentScans.map(s => (
                  <option key={s.domain} value={s.domain} style={{ background: '#0b0f19', color: '#fff' }}>
                    {s.domain} {s.grade ? `[${s.grade}]` : ''}
                  </option>
                ))}
                {!recentScans.some(s => s.domain === activeDomain) && (
                  <option value={activeDomain} style={{ background: '#0b0f19', color: '#fff' }}>{activeDomain}</option>
                )}
              </select>
            ) : (
              <strong style={{ color: 'var(--text-primary)' }}>{activeDomain}</strong>
            )}
          </div>
        </div>
        
        <div style={{ display: 'flex', gap: '0.8rem', alignItems: 'center' }}>
          {data && isFinished && (
            <div style={{ display: 'flex', gap: '0.6rem', alignItems: 'center' }}>
              <button
                className="btn-primary"
                onClick={exportReport}
                style={{
                  padding: '0.5rem 1rem',
                  fontSize: '0.8rem',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  background: 'linear-gradient(135deg, #0284c7, #0369a1)',
                  borderColor: '#38bdf8',
                }}
              >
                <span>🛡️</span> Executive Report (PDF)
              </button>
              <button
                className="btn-outline"
                onClick={exportJSON}
                style={{ padding: '0.5rem 1rem', fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '6px' }}
              >
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                  <polyline points="7 10 12 15 17 10"/>
                  <line x1="12" y1="15" x2="12" y2="3"/>
                </svg>
                Export JSON
              </button>
            </div>
          )}
          {data && (
            <div className="glass-panel" style={{ padding: '1rem', display: 'flex', gap: '2rem' }}>
              <div>
                <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Scope Modules</div>
                <div style={{ fontSize: '1.5rem', fontWeight: 'bold' }}>{data.total || '-'}</div>
              </div>
              <div>
                <div style={{ fontSize: '0.8rem', color: 'var(--accent-green)', textTransform: 'uppercase' }}>Executed</div>
                <div style={{ fontSize: '1.5rem', fontWeight: 'bold' }}>{data.completed || '0'}</div>
              </div>
            </div>
          )}
        </div>
      </div>

      {data && data.results && <SeverityBar results={data.results} activeFilter={activeFilter} onSelectSeverity={setActiveFilter} />}

      {data && !isFinished && (
        <div className="glass-panel" style={{ padding: '1.5rem', marginBottom: '2.5rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem', fontSize: '0.9rem' }}>
            <span style={{ color: 'var(--text-secondary)' }}>
              Status: <strong style={{ color: 'var(--accent-blue)' }}>{data.current_module}</strong>
            </span>
            <span>{progressPercent}%</span>
          </div>
          <div className="progress-container">
            <div className="progress-bar-fill" style={{ width: `${progressPercent}%` }}></div>
          </div>
        </div>
      )}

      {loading && !data && (
        <div className="glass-panel" style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-secondary)' }}>
          <div className="status-indicator pending" style={{ width: '20px', height: '20px', margin: '0 auto 1rem auto' }}></div>
          <p>Initializing Scan Pipeline for {activeDomain}...</p>
        </div>
      )}

      {error && !data && !loading && (
        <div className="glass-panel" style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-secondary)', borderStyle: 'dashed' }}>
          <p>{error}</p>
        </div>
      )}

      {data && data.results && (
        <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1.5rem', borderBottom: '1px solid var(--panel-border)', paddingBottom: '0.5rem' }}>
          {filterTabs.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveFilter(tab.id)}
              style={{
                padding: '0.5rem 1rem',
                background: activeFilter === tab.id ? 'rgba(0, 242, 254, 0.1)' : 'transparent',
                border: activeFilter === tab.id ? '1px solid var(--accent-blue)' : '1px solid transparent',
                borderRadius: '6px 6px 0 0',
                color: activeFilter === tab.id ? 'var(--accent-blue)' : 'var(--text-secondary)',
                cursor: 'pointer',
                fontSize: '0.85rem',
                fontFamily: 'var(--font-sans)',
                transition: 'all 0.2s ease',
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
              }}
            >
              <span>{tab.icon}</span>
              {tab.label}
            </button>
          ))}
        </div>
      )}

      {filteredEntries.map(([moduleName, moduleData]) => (
        <div key={moduleName} style={{ marginBottom: '3rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingBottom: '0.5rem', borderBottom: '1px solid var(--panel-border)', marginBottom: '1.5rem' }}>
            <h3 style={{ fontSize: '1.2rem', display: 'flex', alignItems: 'center', gap: '10px', margin: 0 }}>
              {moduleName}
            </h3>
            <button 
              className="btn-outline" 
              style={{ padding: '0.3rem 0.8rem', fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '6px' }}
              onClick={() => openEducationModal(moduleName)}
              title="Learn how this module generated these results"
            >
              🎓 Learn More
            </button>
          </div>
          
          <div className="glass-panel" style={{ padding: '1.5rem', borderRadius: '12px' }}>
            <ModuleErrorBoundary moduleName={moduleName}>
              <ModuleResultRenderer moduleName={moduleName} moduleData={moduleData} activeFilter={activeFilter} />
            </ModuleErrorBoundary>
          </div>
        </div>
      ))}
    </div>
  );
};

export default ResultsPanel;
