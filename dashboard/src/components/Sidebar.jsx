import React from 'react';

const Sidebar = ({ activeTab, setActiveTab }) => {
  return (
    <div className="sidebar">
      <div style={{ padding: '2rem 1.5rem', borderBottom: '1px solid var(--panel-border)' }}>
        <h2 className="text-gradient cyber-glitch" style={{ margin: 0, fontSize: '1.4rem', display: 'flex', alignItems: 'center', gap: '10px', fontFamily: 'var(--font-cyber)', cursor: 'pointer' }}>
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ filter: 'drop-shadow(0 0 5px var(--accent-blue))' }}>
            <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/>
          </svg>
          WEB_ANALYZER
        </h2>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.75rem', marginTop: '0.6rem', fontFamily: 'var(--font-mono)', letterSpacing: '1px' }}>
          SEC_AUDIT_SUITE v3.3.0
        </p>
      </div>
      
      <div style={{ padding: '2rem 1rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
        <button 
          className={`btn-outline ${activeTab === 'new_scan' ? 'active' : ''}`}
          style={{ textAlign: 'left', display: 'flex', alignItems: 'center', gap: '12px', padding: '1rem', fontFamily: 'var(--font-mono)', fontSize: '0.85rem', textTransform: 'uppercase', letterSpacing: '1px' }}
          onClick={() => setActiveTab('new_scan')}
        >
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="11" cy="11" r="8"></circle>
            <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
          </svg>
          [01] NEW_SCAN
        </button>
        
        <button 
          className={`btn-outline ${activeTab === 'results' ? 'active' : ''}`}
          style={{ textAlign: 'left', display: 'flex', alignItems: 'center', gap: '12px', padding: '1rem', fontFamily: 'var(--font-mono)', fontSize: '0.85rem', textTransform: 'uppercase', letterSpacing: '1px' }}
          onClick={() => setActiveTab('results')}
        >
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
            <polyline points="14 2 14 8 20 8"></polyline>
            <line x1="16" y1="13" x2="8" y2="13"></line>
            <line x1="16" y1="17" x2="8" y2="17"></line>
            <polyline points="10 9 9 9 8 9"></polyline>
          </svg>
          [02] SCAN_RESULTS
        </button>
        
        <button 
          className={`btn-outline ${activeTab === 'advanced_scanner' ? 'active' : ''}`}
          style={{ textAlign: 'left', display: 'flex', alignItems: 'center', gap: '12px', padding: '1rem', fontFamily: 'var(--font-mono)', fontSize: '0.85rem', textTransform: 'uppercase', letterSpacing: '1px' }}
          onClick={() => setActiveTab('advanced_scanner')}
        >
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/>
          </svg>
          [03] ADVANCED_SCAN
        </button>
      </div>

      <div style={{ marginTop: 'auto', padding: '1.5rem', borderTop: '1px solid var(--panel-border)', fontSize: '0.78rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
          <div className="status-indicator active"></div>
          GATEWAY_ONLINE
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <div className="status-indicator active"></div>
          RECON_ENGINE_READY
        </div>
      </div>
    </div>
  );
};

export default Sidebar;
