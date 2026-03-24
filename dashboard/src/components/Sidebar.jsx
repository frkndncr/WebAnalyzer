import React from 'react';

const Sidebar = ({ activeTab, setActiveTab }) => {
  return (
    <div className="sidebar">
      <div style={{ padding: '2rem 1.5rem', borderBottom: '1px solid var(--panel-border)' }}>
        <h2 className="text-gradient" style={{ margin: 0, fontSize: '1.5rem', display: 'flex', alignItems: 'center', gap: '10px' }}>
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/>
          </svg>
          WebAnalyzer
        </h2>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.8rem', marginTop: '0.5rem' }}>
          Vulnerability & Recon Suite
        </p>
      </div>
      
      <div style={{ padding: '1.5rem 1rem', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
        <button 
          className={`btn-outline ${activeTab === 'new_scan' ? 'active' : ''}`}
          style={{ textAlign: 'left', display: 'flex', alignItems: 'center', gap: '10px', padding: '1rem' }}
          onClick={() => setActiveTab('new_scan')}
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="11" cy="11" r="8"></circle>
            <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
          </svg>
          New Scan
        </button>
        
        <button 
          className={`btn-outline ${activeTab === 'results' ? 'active' : ''}`}
          style={{ textAlign: 'left', display: 'flex', alignItems: 'center', gap: '10px', padding: '1rem' }}
          onClick={() => setActiveTab('results')}
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
            <polyline points="14 2 14 8 20 8"></polyline>
            <line x1="16" y1="13" x2="8" y2="13"></line>
            <line x1="16" y1="17" x2="8" y2="17"></line>
            <polyline points="10 9 9 9 8 9"></polyline>
          </svg>
          Scan Results
        </button>
        
        <button 
          className={`btn-outline ${activeTab === 'advanced_scanner' ? 'active' : ''}`}
          style={{ textAlign: 'left', display: 'flex', alignItems: 'center', gap: '10px', padding: '1rem' }}
          onClick={() => setActiveTab('advanced_scanner')}
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/>
          </svg>
          Advanced Scanner
        </button>
      </div>

      <div style={{ marginTop: 'auto', padding: '1.5rem', borderTop: '1px solid var(--panel-border)', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
          <div className="status-indicator active"></div>
          API Gateway Online
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <div className="status-indicator active"></div>
          Engine Ready
        </div>
      </div>
    </div>
  );
};

export default Sidebar;
