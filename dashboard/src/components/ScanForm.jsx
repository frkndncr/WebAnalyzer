import React, { useState } from 'react';

const MODULES = [
  "Domain Information", "DNS Records", "SEO Analysis", 
  "Web Technologies", "Security Analysis", "Advanced Content Scan",
  "Contact Spy", "Subdomain Discovery", "Subdomain Takeover",
  "CloudFlare Bypass", "Nmap Zero Day Scan", "GEO Analysis"
];

const ScanForm = ({ setCurrentDomain, setActiveTab }) => {
  const [domain, setDomain] = useState('');
  const [selectedModules, setSelectedModules] = useState(
    MODULES.reduce((acc, mod) => ({ ...acc, [mod]: true }), {})
  );
  const [loading, setLoading] = useState(false);

  const toggleModule = (mod) => {
    setSelectedModules(prev => ({ ...prev, [mod]: !prev[mod] }));
  };

  const handleSelectAll = (select) => {
    setSelectedModules(MODULES.reduce((acc, mod) => ({ ...acc, [mod]: select }), {}));
  };

  const startScan = async (e) => {
    e.preventDefault();
    if (!domain) return;
    
    setLoading(true);
    const modulesToRun = Object.keys(selectedModules).filter(m => selectedModules[m]);
    
    try {
      const resp = await fetch('http://localhost:8000/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain, modules: modulesToRun })
      });
      
      if (resp.ok) {
        setCurrentDomain(domain);
        setActiveTab('results');
      } else {
        alert('Failed to start scan.');
      }
    } catch (err) {
      alert('Error connecting to API. Is FastAPI running on port 8000?');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="glass-panel" style={{ padding: '2rem', maxWidth: '800px', margin: '0 auto' }}>
      <h2 style={{ marginBottom: '1.5rem', display: 'flex', alignItems: 'center', gap: '10px' }}>
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon>
        </svg>
        Target Acquisition
      </h2>
      
      <form onSubmit={startScan}>
        <div style={{ marginBottom: '2rem' }}>
          <label style={{ display: 'block', marginBottom: '0.5rem', color: 'var(--text-secondary)' }}>Target Domain (e.g. example.com)</label>
          <input 
            type="text" 
            className="input-glass" 
            placeholder="example.com"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            required
            style={{ fontSize: '1.2rem', padding: '1rem' }}
          />
        </div>

        <div style={{ marginBottom: '2rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <label style={{ color: 'var(--text-secondary)' }}>Analysis Modules</label>
            <div style={{ display: 'flex', gap: '10px' }}>
              <button type="button" className="btn-outline" onClick={() => handleSelectAll(true)} style={{ padding: '0.2rem 0.5rem', fontSize: '0.8rem' }}>Select All</button>
              <button type="button" className="btn-outline" onClick={() => handleSelectAll(false)} style={{ padding: '0.2rem 0.5rem', fontSize: '0.8rem' }}>Deselect All</button>
            </div>
          </div>
          
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: '1rem' }}>
            {MODULES.map(mod => (
              <label key={mod} className="custom-checkbox">
                <input 
                  type="checkbox" 
                  checked={selectedModules[mod]}
                  onChange={() => toggleModule(mod)}
                />
                <span style={{ fontSize: '0.9rem' }}>{mod}</span>
              </label>
            ))}
          </div>
        </div>

        <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '2rem' }}>
          <button type="submit" className="btn-primary" disabled={loading} style={{ width: '200px', display: 'flex', justifyContent: 'center', alignItems: 'center', gap: '8px' }}>
            {loading ? (
              <>
                <div className="status-indicator pending" style={{ margin: 0 }}></div>
                Initializing...
              </>
            ) : (
              <>
                Launch Scan
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M5 12h14M12 5l7 7-7 7"/>
                </svg>
              </>
            )}
          </button>
        </div>
      </form>
    </div>
  );
};

export default ScanForm;
