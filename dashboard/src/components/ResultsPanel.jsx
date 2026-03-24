import React, { useState, useEffect } from 'react';
import EducationModal from './EducationModal';
import InteractiveJson from './InteractiveJson';

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

const VulnerabilityCard = ({ finding }) => {
  const severityClass = finding.severity?.toLowerCase() || 'medium';
  
  return (
    <div className="glass-panel" style={{ padding: '1.5rem', marginBottom: '1rem', borderLeft: `4px solid var(--accent-${severityClass === 'critical' || severityClass === 'high' ? 'red' : 'orange'})` }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
        <h3 style={{ margin: 0, fontSize: '1.1rem' }}>
          <HighlightVuln text={finding.type || finding.title || 'Vulnerability Finding'} />
        </h3>
        <span className={`severity-${severityClass}`} style={{ textTransform: 'uppercase', fontSize: '0.8rem', padding: '0.2rem 0.5rem', background: 'var(--panel-bg)', borderRadius: '4px' }}>
          {finding.severity || finding.confidence || 'Medium'}
        </span>
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

const ResultsPanel = ({ domain }) => {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [modalState, setModalState] = useState({ isOpen: false, moduleName: '' });

  useEffect(() => {
    let interval;
    const fetchResults = async () => {
      try {
        const res = await fetch(`http://localhost:8000/api/status/${domain}`);
        if (res.ok) {
          const json = await res.json();
          setData(json);
          setError(null);
          
          if (json.current_module === 'Finished') {
            setLoading(false);
            clearInterval(interval);
          } else {
            setLoading(false); // We have status, so not completely loading
          }
        } else {
          setError('Waiting for backend acknowledgment...');
        }
      } catch (err) {
        setError('Cannot connect to API server.');
      }
    };

    fetchResults();
    interval = setInterval(fetchResults, 2000); // Poll faster for the progress bar
    return () => clearInterval(interval);
  }, [domain]);

  const openEducationModal = (moduleName) => {
    setModalState({ isOpen: true, moduleName });
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

      {data && data.results && Object.entries(data.results).map(([moduleName, moduleData]) => (
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
