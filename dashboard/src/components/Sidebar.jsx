import React, { useState, useEffect } from 'react';

const NAV_ITEMS = [
  {
    id: 'overview',
    code: '00',
    label: 'SYS_OVERVIEW',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <rect x="3" y="3" width="7" height="7" rx="1"></rect>
        <rect x="14" y="3" width="7" height="7" rx="1"></rect>
        <rect x="14" y="14" width="7" height="7" rx="1"></rect>
        <rect x="3" y="14" width="7" height="7" rx="1"></rect>
      </svg>
    ),
  },
  {
    id: 'new_scan',
    code: '01',
    label: 'NEW_SCAN',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <circle cx="11" cy="11" r="8"></circle>
        <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
        <line x1="11" y1="8" x2="11" y2="14"></line>
        <line x1="8" y1="11" x2="14" y2="11"></line>
      </svg>
    ),
  },
  {
    id: 'results',
    code: '02',
    label: 'SCAN_RESULTS',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
        <polyline points="14 2 14 8 20 8"></polyline>
        <line x1="16" y1="13" x2="8" y2="13"></line>
        <line x1="16" y1="17" x2="8" y2="17"></line>
      </svg>
    ),
  },
  {
    id: 'advanced_scanner',
    code: '03',
    label: 'DEEP_SCANNER',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/>
      </svg>
    ),
  },
  {
    id: 'threat_intel',
    code: '04',
    label: 'THREAT_INTEL',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        <path d="M12 8v4M12 16h.01"/>
      </svg>
    ),
  },
  {
    id: 'network_map',
    code: '05',
    label: 'NETWORK_MAP',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <circle cx="12" cy="5" r="3"/>
        <circle cx="5" cy="19" r="3"/>
        <circle cx="19" cy="19" r="3"/>
        <line x1="12" y1="8" x2="5" y2="16"/>
        <line x1="12" y1="8" x2="19" y2="16"/>
      </svg>
    ),
  },
  {
    id: 'settings',
    code: '06',
    label: 'SETTINGS',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <circle cx="12" cy="12" r="3"/>
        <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>
      </svg>
    ),
  },
];

const Sidebar = ({ activeTab, setActiveTab }) => {
  const [currentTime, setCurrentTime] = useState('');
  const [uptime, setUptime] = useState(0);
  const [collapsed, setCollapsed] = useState(false);

  useEffect(() => {
    const updateClock = () => {
      const now = new Date();
      setCurrentTime(now.toUTCString().slice(17, 25));
    };
    updateClock();
    const clockInterval = setInterval(updateClock, 1000);
    const uptimeInterval = setInterval(() => setUptime(prev => prev + 1), 1000);
    return () => {
      clearInterval(clockInterval);
      clearInterval(uptimeInterval);
    };
  }, []);

  const formatUptime = (seconds) => {
    const h = Math.floor(seconds / 3600).toString().padStart(2, '0');
    const m = Math.floor((seconds % 3600) / 60).toString().padStart(2, '0');
    const s = (seconds % 60).toString().padStart(2, '0');
    return `${h}:${m}:${s}`;
  };

  return (
    <div className={`sidebar ${collapsed ? 'collapsed' : ''}`}>
      {/* Logo / Brand */}
      <div style={{ padding: collapsed ? '1.5rem 0.8rem' : '1.5rem', borderBottom: '1px solid var(--panel-border)', transition: 'padding 0.3s' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', cursor: 'pointer' }} onClick={() => setCollapsed(!collapsed)}>
          <div style={{
            width: '36px', height: '36px', borderRadius: '10px',
            background: 'linear-gradient(135deg, rgba(0,242,254,0.2), rgba(218,34,255,0.2))',
            border: '1px solid rgba(0,242,254,0.3)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            boxShadow: '0 0 15px rgba(0,242,254,0.2)', flexShrink: 0
          }}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--accent-blue)" strokeWidth="2">
              <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/>
            </svg>
          </div>
          {!collapsed && (
            <div>
              <h2 className="text-gradient cyber-glitch" style={{ margin: 0, fontSize: '1.1rem', fontFamily: 'var(--font-cyber)', letterSpacing: '2px' }}>
                WEBANALYZER
              </h2>
              <p style={{ color: 'var(--text-secondary)', fontSize: '0.65rem', marginTop: '2px', fontFamily: 'var(--font-mono)', letterSpacing: '1px' }}>
                SEC_AUDIT v3.3.0
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Navigation */}
      <div style={{ padding: collapsed ? '1rem 0.5rem' : '1rem 0.8rem', display: 'flex', flexDirection: 'column', gap: '4px', flex: 1, overflowY: 'auto' }}>
        {NAV_ITEMS.map((item) => (
          <button
            key={item.id}
            className={`btn-outline ${activeTab === item.id ? 'active' : ''}`}
            style={{
              textAlign: 'left',
              display: 'flex',
              alignItems: 'center',
              gap: collapsed ? '0' : '10px',
              padding: collapsed ? '0.8rem' : '0.75rem 0.8rem',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.75rem',
              textTransform: 'uppercase',
              letterSpacing: '0.5px',
              justifyContent: collapsed ? 'center' : 'flex-start',
              width: '100%',
              border: activeTab === item.id ? '1px solid rgba(0, 242, 254, 0.3)' : '1px solid transparent',
              borderRadius: '8px',
              background: activeTab === item.id ? 'rgba(0, 242, 254, 0.08)' : 'transparent',
              transition: 'all 0.2s',
            }}
            onClick={() => setActiveTab(item.id)}
            title={collapsed ? item.label : undefined}
          >
            <span style={{ opacity: activeTab === item.id ? 1 : 0.6, flexShrink: 0, display: 'flex' }}>{item.icon}</span>
            {!collapsed && (
              <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span style={{ color: 'var(--text-secondary)', fontSize: '0.65rem' }}>[{item.code}]</span>
                {item.label}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Bottom Section */}
      <div style={{ padding: collapsed ? '0.8rem' : '1rem', borderTop: '1px solid var(--panel-border)', fontSize: '0.72rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
        {/* System Status */}
        {!collapsed && (
          <>
            {/* Live Clock */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px', padding: '6px 8px', background: 'rgba(0,242,254,0.04)', borderRadius: '6px', border: '1px solid rgba(0,242,254,0.08)' }}>
              <span style={{ fontSize: '0.65rem', color: 'var(--text-secondary)' }}>UTC</span>
              <span style={{ color: 'var(--accent-blue)', fontWeight: 700, fontSize: '0.8rem', fontFamily: 'var(--font-cyber)', letterSpacing: '1px' }}>{currentTime}</span>
            </div>

            {/* Uptime */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px', padding: '6px 8px', background: 'rgba(57,255,20,0.03)', borderRadius: '6px', border: '1px solid rgba(57,255,20,0.08)' }}>
              <span style={{ fontSize: '0.65rem', color: 'var(--text-secondary)' }}>UPTIME</span>
              <span style={{ color: 'var(--accent-green)', fontWeight: 700, fontSize: '0.75rem', fontFamily: 'var(--font-mono)' }}>{formatUptime(uptime)}</span>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
              <div className="status-indicator active"></div>
              <span style={{ fontSize: '0.68rem' }}>GATEWAY_ONLINE</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '1rem' }}>
              <div className="status-indicator active"></div>
              <span style={{ fontSize: '0.68rem' }}>RECON_ENGINE_READY</span>
            </div>

            <div style={{ borderTop: '1px dashed rgba(0, 242, 254, 0.1)', paddingTop: '0.8rem', display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <div style={{ fontSize: '0.7rem' }}>
                <span style={{ color: 'var(--text-secondary)' }}>Developed by</span>
                <a href="https://github.com/frkndncr" target="_blank" rel="noopener noreferrer" style={{ display: 'block', color: 'var(--accent-blue)', textDecoration: 'none', marginTop: '2px', fontSize: '0.72rem', transition: 'all 0.2s' }}>
                  Furkan Dinçer (@frkndncr)
                </a>
              </div>

              <a href="https://github.com/frkndncr/WebAnalyzer" target="_blank" rel="noopener noreferrer"
                className="btn-primary"
                style={{
                  display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px',
                  padding: '0.45rem', fontSize: '0.68rem', textDecoration: 'none',
                  textTransform: 'uppercase', letterSpacing: '1px', fontFamily: 'var(--font-cyber)',
                  borderRadius: '6px',
                }}>
                ⭐ STAR ON GITHUB
              </a>
            </div>
          </>
        )}

        {collapsed && (
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '8px' }}>
            <div className="status-indicator active" style={{ margin: 0 }}></div>
            <a href="https://github.com/frkndncr/WebAnalyzer" target="_blank" rel="noopener noreferrer"
              style={{ color: 'var(--accent-blue)', fontSize: '1.1rem', textDecoration: 'none' }}
              title="Star on GitHub">
              ⭐
            </a>
          </div>
        )}
      </div>
    </div>
  );
};

export default Sidebar;
