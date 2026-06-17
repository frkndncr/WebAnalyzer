import React, { useState, useEffect } from 'react';
import EducationModal from './EducationModal';
import InteractiveJson from './InteractiveJson';
import { getApiUrl } from '../config';

// Specialized Markdown/Highlight parser for making vulnerabilities bold
const HighlightVuln = ({ text }) => {
  if (typeof text !== 'string') return <span>{JSON.stringify(text)}</span>;

  const vulnKeywords = [
    'vulnerability', 'vulnerabilities', 'xss', 'sqli', 'ssrf', 'csrf', 
    'cve-', 'critical', 'high', 'exposure', 'exposed', 'disclosure',
    'leak', 'crlf', 'rce', 'ssti', 'misconfiguration', 'missing'
  ];

  const regex = new RegExp(`(${vulnKeywords.join('|')})`, 'gi');
  
  const parts = text.split(regex);
  return (
    <span>
      {parts.map((part, i) => {
        if (regex.test(part)) {
          return <span key={i} className="vuln-highlight">{part}</span>;
        }
        return <span key={i}>{part}</span>;
      })}
    </span>
  );
};

/* ── CVSS-style Score Badge ── */
const CVSSBadge = ({ severity }) => {
  const sev = (severity || 'medium').toLowerCase();
  const scoreMap = { critical: 9.5, high: 7.5, medium: 5.0, low: 2.5, info: 0.5 };
  const colorMap = {
    critical: 'var(--accent-red)',
    high: 'var(--accent-orange)',
    medium: 'var(--accent-blue)',
    low: 'var(--text-secondary)',
    info: 'var(--accent-green)',
  };
  const score = scoreMap[sev] || 5.0;
  const color = colorMap[sev] || 'var(--accent-blue)';

  return (
    <div style={{
      display: 'flex',
      alignItems: 'center',
      gap: '6px',
    }}>
      <div style={{
        width: '40px',
        height: '40px',
        borderRadius: '50%',
        border: `2px solid ${color}`,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        fontFamily: 'var(--font-mono)',
        fontSize: '0.85rem',
        fontWeight: 700,
        color: color,
        background: `${color}15`,
        flexShrink: 0,
      }}>
        {score.toFixed(1)}
      </div>
      <span className={`severity-${sev}`} style={{
        textTransform: 'uppercase',
        fontSize: '0.7rem',
        padding: '0.15rem 0.45rem',
        background: 'var(--panel-bg)',
        borderRadius: '4px',
        fontFamily: 'var(--font-cyber)',
        letterSpacing: '0.5px',
      }}>
        {severity || 'Medium'}
      </span>
    </div>
  );
};

const VulnerabilityCard = ({ finding }) => {
  const severityClass = finding.severity?.toLowerCase() || 'medium';
  const [copied, setCopied] = useState(false);

  const copyToClipboard = () => {
    const text = JSON.stringify(finding, null, 2);
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }).catch(() => {});
  };

  return (
    <div className="glass-panel" style={{
      padding: '1.5rem',
      marginBottom: '1rem',
      borderLeft: `4px solid var(--accent-${severityClass === 'critical' || severityClass === 'high' ? 'red' : severityClass === 'medium' ? 'blue' : 'orange'})`,
      transition: 'all 0.2s ease',
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flex: 1 }}>
          <CVSSBadge severity={finding.severity || finding.confidence} />
          <h3 style={{ margin: 0, fontSize: '1.05rem', flex: 1 }}>
            <HighlightVuln text={finding.type || finding.title || 'Vulnerability Finding'} />
          </h3>
        </div>
        <button
          onClick={copyToClipboard}
          style={{
            background: copied ? 'rgba(57, 255, 20, 0.15)' : 'rgba(255,255,255,0.05)',
            border: copied ? '1px solid var(--accent-green)' : '1px solid var(--panel-border)',
            color: copied ? 'var(--accent-green)' : 'var(--text-secondary)',
            padding: '0.3rem 0.6rem',
            borderRadius: '4px',
            cursor: 'pointer',
            fontSize: '0.75rem',
            fontFamily: 'var(--font-mono)',
            transition: 'all 0.2s ease',
            flexShrink: 0,
          }}
          title="Copy finding to clipboard"
        >
          {copied ? '✓ Copied' : '📋 Copy'}
        </button>
      </div>
      
      {finding.description && (
        <p style={{ color: 'var(--text-secondary)', marginBottom: '0.8rem', fontSize: '0.95rem' }}>
          <HighlightVuln text={finding.description} />
        </p>
      )}
      
      {finding.recommendation && (
        <div style={{ padding: '0.8rem', background: 'rgba(63, 185, 80, 0.1)', borderRadius: '6px', border: '1px solid rgba(63, 185, 80, 0.2)' }}>
          <strong style={{ color: 'var(--accent-green)', display: 'block', fontSize: '0.8rem', marginBottom: '0.3rem', textTransform: 'uppercase' }}>Recommendation</strong>
          <span style={{ fontSize: '0.9rem', color: '#e6edf3' }}>{finding.recommendation}</span>
        </div>
      )}

      {Object.keys(finding).filter(k => !['type', 'title', 'severity', 'description', 'recommendation', 'confidence'].includes(k)).length > 0 && (
        <details style={{ marginTop: '1rem' }}>
          <summary style={{ cursor: 'pointer', color: 'var(--accent-blue)', fontSize: '0.85rem' }}>View Technical Details</summary>
          <div className="json-view" style={{ marginTop: '0.5rem' }}>
            <InteractiveJson data={Object.fromEntries(Object.entries(finding).filter(([k]) => !['type', 'title', 'severity', 'description', 'recommendation', 'confidence'].includes(k)))} />
          </div>
        </details>
      )}
    </div>
  );
};

/* ── Severity Breakdown Bar ── */
const SeverityBar = ({ results }) => {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

  if (results) {
    Object.values(results).forEach(moduleData => {
      const vulns = Array.isArray(moduleData)
        ? moduleData
        : Array.isArray(moduleData?.vulnerabilities)
          ? moduleData.vulnerabilities
          : Array.isArray(moduleData?.vulnerable_subdomains)
            ? moduleData.vulnerable_subdomains
            : [];
      vulns.forEach(v => {
        if (typeof v === 'object' && v) {
          const sev = (v.severity || v.confidence || 'medium').toLowerCase();
          if (sev in counts) counts[sev]++;
          else counts['info']++;
        }
      });
    });
  }

  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  if (total === 0) return null;

  const segments = [
    { key: 'critical', color: 'var(--accent-red)', label: 'Critical' },
    { key: 'high', color: 'var(--accent-orange)', label: 'High' },
    { key: 'medium', color: 'var(--accent-blue)', label: 'Medium' },
    { key: 'low', color: 'var(--text-secondary)', label: 'Low' },
    { key: 'info', color: 'var(--accent-green)', label: 'Info' },
  ];

  return (
    <div className="glass-panel" style={{ padding: '1rem 1.5rem', marginBottom: '1.5rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.6rem' }}>
        <span style={{ fontSize: '0.8rem', fontFamily: 'var(--font-cyber)', textTransform: 'uppercase', letterSpacing: '1px', color: 'var(--text-secondary)' }}>
          Severity Breakdown
        </span>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', color: 'var(--text-primary)' }}>
          {total} finding{total !== 1 ? 's' : ''}
        </span>
      </div>
      <div style={{ display: 'flex', height: '8px', borderRadius: '4px', overflow: 'hidden', marginBottom: '0.6rem' }}>
        {segments.map(seg => {
          const pct = total > 0 ? (counts[seg.key] / total) * 100 : 0;
          return pct > 0 ? (
            <div key={seg.key} style={{ width: `${pct}%`, background: seg.color, transition: 'width 0.5s ease' }} />
          ) : null;
        })}
      </div>
      <div style={{ display: 'flex', gap: '1.2rem', flexWrap: 'wrap' }}>
        {segments.map(seg => counts[seg.key] > 0 && (
          <div key={seg.key} style={{ display: 'flex', alignItems: 'center', gap: '5px', fontSize: '0.75rem' }}>
            <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: seg.color }} />
            <span style={{ color: 'var(--text-secondary)' }}>{seg.label}</span>
            <span style={{ fontFamily: 'var(--font-mono)', color: seg.color }}>{counts[seg.key]}</span>
          </div>
        ))}
      </div>
    </div>
  );
};

/* ── Category Helpers ── */
const categorizeModule = (moduleName, moduleData) => {
  const categories = [];
  if (moduleData && typeof moduleData === 'object') {
    if (moduleData.error) {
      categories.push('errors');
    }
    if (moduleData.vulnerabilities || moduleData.vulnerable_subdomains || moduleData.security_issues ||
      (Array.isArray(moduleData) && moduleData.some(v => v && v.severity))) {
      categories.push('vulnerabilities');
    }
  }
  if (categories.length === 0) categories.push('information');
  return categories;
};

const ResultsPanel = ({ domain }) => {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [modalState, setModalState] = useState({ isOpen: false, moduleName: '' });
  const [activeFilter, setActiveFilter] = useState('all');

  useEffect(() => {
    let interval;
    const fetchResults = async () => {
      try {
        const res = await fetch(getApiUrl(`/api/status/${domain}`));
        if (res.ok) {
          const json = await res.json();
          setData(json);
          setError(null);
          
          if (json.current_module === 'Finished') {
            setLoading(false);
            clearInterval(interval);
          } else {
            setLoading(false);
          }
        } else {
          setError('Waiting for backend acknowledgment...');
        }
      } catch (err) {
        setError('Cannot connect to API server.');
      }
    };

    fetchResults();
    interval = setInterval(fetchResults, 2000);
    return () => clearInterval(interval);
  }, [domain]);

  const openEducationModal = (moduleName) => {
    setModalState({ isOpen: true, moduleName });
  };

  const exportJSON = () => {
    if (!data || !data.results) return;
    const blob = new Blob([JSON.stringify(data.results, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${domain}-results.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  if (loading && !data) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', flexDirection: 'column', gap: '1rem' }}>
        <div className="status-indicator pending" style={{ width: '20px', height: '20px' }}></div>
        <p style={{ color: 'var(--text-secondary)' }}>Initializing Scan Pipeline for {domain}...</p>
      </div>
    );
  }

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
        if (activeFilter === 'all') return true;
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

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginBottom: '1rem' }}>
        <div>
          <h2 style={{ fontSize: '2rem', marginBottom: '0.5rem' }}>Analysis Results</h2>
          <p style={{ color: 'var(--text-secondary)' }}>Target: <strong style={{ color: 'var(--text-primary)' }}>{domain}</strong></p>
        </div>
        
        <div style={{ display: 'flex', gap: '0.8rem', alignItems: 'center' }}>
          {data && isFinished && (
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

      {/* ── Severity Breakdown ── */}
      {data && data.results && <SeverityBar results={data.results} />}

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

      {error && !data && (
        <div className="glass-panel" style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-secondary)', borderStyle: 'dashed' }}>
          <p>{error}</p>
        </div>
      )}

      {/* ── Tab Navigation ── */}
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
          
          {(moduleData.vulnerable_subdomains || moduleData.vulnerabilities || moduleData.security_issues || (Array.isArray(moduleData) && moduleData.length > 0 && typeof moduleData[0] === 'object')) ? (
            <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr)', gap: '1rem' }}>
              {Array.isArray(moduleData) ? (
                moduleData.map((finding, idx) => <VulnerabilityCard key={idx} finding={finding} />)
              ) : Array.isArray(moduleData.vulnerable_subdomains) ? (
                moduleData.vulnerable_subdomains.map((sub, idx) => <VulnerabilityCard key={idx} finding={sub} />)
              ) : Array.isArray(moduleData.vulnerabilities) ? (
                moduleData.vulnerabilities.map((v, idx) => <VulnerabilityCard key={idx} finding={v} />)
              ) : Object.keys(moduleData).includes('error') ? (
                <div style={{ color: 'var(--accent-red)' }}>{moduleData.error}</div>
              ) : (
                <div className="glass-panel json-view">
                  <InteractiveJson data={moduleData} initExpanded={true} />
                </div>
              )}
            </div>
          ) : (
            <div className="glass-panel json-view">
              <InteractiveJson data={moduleData} initExpanded={true} />
            </div>
          )}
        </div>
      ))}
    </div>
  );
};

export default ResultsPanel;
