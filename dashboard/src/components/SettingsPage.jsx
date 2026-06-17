import React, { useState, useEffect, useRef } from 'react';
import { getApiUrl } from '../config';

/* ── Scan Profile Presets (configuration data, not mock) ── */
const SCAN_PROFILES = [
  {
    id: 'quick',
    name: 'Quick Scan',
    icon: '⚡',
    color: 'var(--accent-green)',
    description: 'Fast surface-level reconnaissance. Ideal for initial target assessment.',
    duration: '~2 min',
    modules: ['DNS Lookup', 'HTTP Headers', 'SSL Check', 'WHOIS'],
  },
  {
    id: 'standard',
    name: 'Standard Scan',
    icon: '🔍',
    color: 'var(--accent-blue)',
    description: 'Balanced analysis covering common attack surfaces and misconfigurations.',
    duration: '~8 min',
    modules: ['DNS Lookup', 'HTTP Headers', 'SSL Check', 'WHOIS', 'Port Scan', 'Tech Detection', 'Crawl Engine', 'Cookie Analysis'],
  },
  {
    id: 'deep',
    name: 'Deep Scan',
    icon: '🛡️',
    color: 'var(--accent-purple)',
    description: 'Comprehensive security audit with vulnerability scanning and exploit analysis.',
    duration: '~20 min',
    modules: ['DNS Lookup', 'HTTP Headers', 'SSL Check', 'WHOIS', 'Port Scan', 'Tech Detection', 'Crawl Engine', 'Cookie Analysis', 'JS Analysis', 'Secret Scanner', 'WAF Detection', 'Nuclei CVE', 'Exploit Chains', 'SSRF Detection'],
  },
  {
    id: 'stealth',
    name: 'Stealth Scan',
    icon: '👻',
    color: 'var(--accent-orange)',
    description: 'Low-noise passive reconnaissance to avoid detection by WAF/IDS systems.',
    duration: '~12 min',
    modules: ['DNS Lookup (Passive)', 'WHOIS', 'Certificate Transparency', 'Subdomain Enum', 'Tech Fingerprint', 'OSINT Recon'],
  },
];

/* ── Tech Stack Badges ── */
const TECH_STACK = [
  { name: 'Python', color: '#3776AB' },
  { name: 'FastAPI', color: '#009688' },
  { name: 'React', color: '#61DAFB' },
  { name: 'Nmap', color: '#FF6600' },
  { name: 'Nuclei', color: '#8B5CF6' },
  { name: 'Playwright', color: '#2EAD33' },
  { name: 'MongoDB', color: '#47A248' },
  { name: 'Vite', color: '#646CFF' },
];

/* ── Animated Pulse Ring SVG ── */
const PulseRing = ({ color, connected }) => {
  return (
    <svg width="18" height="18" viewBox="0 0 18 18" style={{ flexShrink: 0 }}>
      <circle cx="9" cy="9" r="5" fill={color} opacity="0.9">
        {connected && (
          <animate attributeName="r" values="5;8;5" dur="2s" repeatCount="indefinite" />
        )}
      </circle>
      {connected && (
        <circle cx="9" cy="9" r="5" fill="none" stroke={color} strokeWidth="1.5" opacity="0.4">
          <animate attributeName="r" values="5;9;5" dur="2s" repeatCount="indefinite" />
          <animate attributeName="opacity" values="0.5;0;0.5" dur="2s" repeatCount="indefinite" />
        </circle>
      )}
    </svg>
  );
};

/* ── Main SettingsPage Component ── */
const SettingsPage = () => {
  /* ─── API Connection State ─── */
  const [connectionStatus, setConnectionStatus] = useState('idle'); // idle | testing | connected | error
  const [healthData, setHealthData] = useState(null);
  const [connectionError, setConnectionError] = useState('');
  const [lastTested, setLastTested] = useState(null);

  /* ─── Scan Profiles State ─── */
  const [selectedProfile, setSelectedProfile] = useState(() => {
    return localStorage.getItem('webanalyzer_scan_profile') || 'standard';
  });
  const [expandedProfile, setExpandedProfile] = useState(null);

  /* ─── Export State ─── */
  const [recentScans, setRecentScans] = useState([]);
  const [selectedDomain, setSelectedDomain] = useState('');
  const [loadingScans, setLoadingScans] = useState(false);
  const [exportSuccess, setExportSuccess] = useState('');

  /* ─── Refs ─── */
  const apiUrlRef = useRef(null);

  /* ─── On Mount: test connection + load scans ─── */
  useEffect(() => {
    testConnection();
    fetchRecentScans();
  }, []);

  /* ─── Test Connection ─── */
  const testConnection = async () => {
    setConnectionStatus('testing');
    setConnectionError('');
    setHealthData(null);
    try {
      const res = await fetch(getApiUrl('/api/system-health'), {
        signal: AbortSignal.timeout(10000),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
      const data = await res.json();
      setHealthData(data);
      setConnectionStatus('connected');
      setLastTested(new Date());
    } catch (err) {
      setConnectionStatus('error');
      setConnectionError(err.message || 'Connection failed');
      setLastTested(new Date());
    }
  };

  /* ─── Fetch Recent Scans for Export ─── */
  const fetchRecentScans = async () => {
    setLoadingScans(true);
    try {
      const res = await fetch(getApiUrl('/api/recent-scans'));
      if (!res.ok) throw new Error('Failed to fetch scans');
      const data = await res.json();
      setRecentScans(Array.isArray(data) ? data : []);
      if (Array.isArray(data) && data.length > 0) {
        setSelectedDomain(data[0].domain || data[0].target || '');
      }
    } catch (err) {
      console.error('Failed to fetch recent scans:', err);
      setRecentScans([]);
    } finally {
      setLoadingScans(false);
    }
  };

  /* ─── Profile Selection ─── */
  const selectProfile = (profileId) => {
    setSelectedProfile(profileId);
    localStorage.setItem('webanalyzer_scan_profile', profileId);
  };

  /* ─── Export Handlers ─── */
  const handleExport = (format) => {
    if (!selectedDomain) return;
    const url = getApiUrl(`/api/export/${encodeURIComponent(selectedDomain)}/${format}`);
    window.open(url, '_blank');
    setExportSuccess(`${format.toUpperCase()} export started for ${selectedDomain}`);
    setTimeout(() => setExportSuccess(''), 4000);
  };

  /* ─── Copy API URL ─── */
  const copyApiUrl = () => {
    const url = getApiUrl('');
    navigator.clipboard.writeText(url).then(() => {
      if (apiUrlRef.current) {
        apiUrlRef.current.style.borderColor = 'var(--accent-green)';
        setTimeout(() => {
          if (apiUrlRef.current) apiUrlRef.current.style.borderColor = '';
        }, 1500);
      }
    });
  };

  /* ─── Helpers ─── */
  const apiUrl = getApiUrl('');
  const isConnected = connectionStatus === 'connected';
  const statusColor = isConnected ? 'var(--accent-green)' : connectionStatus === 'error' ? 'var(--accent-red)' : 'var(--text-secondary)';

  /* ═══════════════════════════════════════════════════════════════ */
  /* ─── RENDER ─── */
  /* ═══════════════════════════════════════════════════════════════ */
  return (
    <div className="animate-fade-in" style={{ maxWidth: '1100px', margin: '0 auto' }}>

      {/* ── Page Header ── */}
      <div style={{ marginBottom: '2rem' }}>
        <h2 style={{ fontSize: '1.8rem', marginBottom: '0.3rem', display: 'flex', alignItems: 'center', gap: '12px' }}>
          <span className="text-gradient">SYSTEM_CONFIG</span>
          <span className="badge badge-purple">SETTINGS</span>
        </h2>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', fontFamily: 'var(--font-mono)' }}>
          API configuration, scan profiles, data export &amp; system information
        </p>
      </div>

      {/* ════════════════════════════════════════════════════════════ */}
      {/* ─── 1. API CONFIGURATION ─── */}
      {/* ════════════════════════════════════════════════════════════ */}
      <div className="glass-panel" style={{ padding: '1.5rem', marginBottom: '1.5rem' }}>
        <h3 style={{ fontSize: '1rem', marginBottom: '1.2rem', display: 'flex', alignItems: 'center', gap: '8px', fontFamily: 'var(--font-cyber)' }}>
          🔌 API_CONFIGURATION
          <PulseRing color={statusColor} connected={isConnected} />
          <span style={{
            fontSize: '0.7rem',
            padding: '3px 10px',
            borderRadius: '20px',
            fontFamily: 'var(--font-mono)',
            fontWeight: 700,
            color: statusColor,
            background: isConnected ? 'rgba(57,255,20,0.1)' : connectionStatus === 'error' ? 'rgba(255,0,85,0.1)' : 'rgba(255,255,255,0.05)',
            border: `1px solid ${statusColor}30`,
          }}>
            {connectionStatus === 'testing' ? '⏳ TESTING...' : isConnected ? '✅ CONNECTED' : connectionStatus === 'error' ? '❌ DISCONNECTED' : '⏸️ IDLE'}
          </span>
        </h3>

        {/* API URL Display */}
        <div style={{ display: 'flex', gap: '0.8rem', marginBottom: '1rem', alignItems: 'stretch' }}>
          <div
            ref={apiUrlRef}
            className="input-glass"
            style={{
              flex: 1,
              display: 'flex',
              alignItems: 'center',
              padding: '0.6rem 1rem',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.85rem',
              color: 'var(--accent-blue)',
              cursor: 'pointer',
              transition: 'border-color 0.3s',
            }}
            onClick={copyApiUrl}
            title="Click to copy"
          >
            <span style={{ color: 'var(--text-secondary)', marginRight: '8px' }}>ENDPOINT:</span>
            {apiUrl}
            <span style={{ marginLeft: 'auto', fontSize: '0.7rem', color: 'var(--text-secondary)' }}>📋 click to copy</span>
          </div>
          <button
            className={connectionStatus === 'testing' ? 'btn-outline' : 'btn-primary'}
            onClick={testConnection}
            disabled={connectionStatus === 'testing'}
            style={{ whiteSpace: 'nowrap', minWidth: '160px' }}
          >
            {connectionStatus === 'testing' ? '⏳ Testing...' : '🔄 Test Connection'}
          </button>
        </div>

        {/* Connection Error */}
        {connectionStatus === 'error' && (
          <div style={{
            padding: '0.8rem 1rem',
            borderRadius: '8px',
            background: 'rgba(255,0,85,0.08)',
            border: '1px solid rgba(255,0,85,0.2)',
            color: 'var(--accent-red)',
            fontFamily: 'var(--font-mono)',
            fontSize: '0.8rem',
            marginBottom: '1rem',
          }}>
            ⚠️ Connection Error: {connectionError}
          </div>
        )}

        {/* System Health Data */}
        {healthData && (
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
            gap: '0.8rem',
            marginTop: '0.5rem',
          }}>
            {[
              { label: 'API Status', value: healthData.api_status || 'N/A', icon: '🟢', color: 'var(--accent-green)' },
              { label: 'Version', value: healthData.version || 'N/A', icon: '📦', color: 'var(--accent-blue)' },
              { label: 'Python', value: healthData.python_version || 'N/A', icon: '🐍', color: '#3776AB' },
              { label: 'Platform', value: healthData.platform || 'N/A', icon: '💻', color: 'var(--accent-purple)' },
              { label: 'Active Scans', value: healthData.active_scans ?? 'N/A', icon: '📡', color: 'var(--accent-orange)' },
            ].map((item, i) => (
              <div key={i} style={{
                padding: '0.7rem 1rem',
                borderRadius: '8px',
                background: 'rgba(255,255,255,0.02)',
                border: '1px solid rgba(255,255,255,0.06)',
                borderLeft: `3px solid ${item.color}`,
              }}>
                <div style={{ fontSize: '0.65rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', marginBottom: '4px', textTransform: 'uppercase' }}>
                  {item.icon} {item.label}
                </div>
                <div style={{
                  fontSize: '0.9rem',
                  color: item.color,
                  fontFamily: 'var(--font-mono)',
                  fontWeight: 700,
                  textShadow: `0 0 8px ${item.color}30`,
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                }}>
                  {String(item.value)}
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Last Tested */}
        {lastTested && (
          <div style={{ marginTop: '0.8rem', fontSize: '0.7rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', textAlign: 'right' }}>
            Last tested: {lastTested.toLocaleTimeString()}
          </div>
        )}
      </div>

      {/* ════════════════════════════════════════════════════════════ */}
      {/* ─── 2. SCAN PROFILES ─── */}
      {/* ════════════════════════════════════════════════════════════ */}
      <div className="glass-panel" style={{ padding: '1.5rem', marginBottom: '1.5rem' }}>
        <h3 style={{ fontSize: '1rem', marginBottom: '1.2rem', display: 'flex', alignItems: 'center', gap: '8px', fontFamily: 'var(--font-cyber)' }}>
          🎯 SCAN_PROFILES
          <span className="badge badge-blue" style={{ fontSize: '0.6rem' }}>
            Active: {SCAN_PROFILES.find(p => p.id === selectedProfile)?.name || 'Standard'}
          </span>
        </h3>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '1rem' }}>
          {SCAN_PROFILES.map((profile) => {
            const isActive = selectedProfile === profile.id;
            const isExpanded = expandedProfile === profile.id;
            return (
              <div
                key={profile.id}
                style={{
                  padding: '1.2rem',
                  borderRadius: '12px',
                  background: isActive ? `linear-gradient(135deg, ${profile.color}10, ${profile.color}05)` : 'rgba(255,255,255,0.02)',
                  border: `1.5px solid ${isActive ? profile.color : 'rgba(255,255,255,0.06)'}`,
                  cursor: 'pointer',
                  transition: 'all 0.3s ease',
                  position: 'relative',
                  overflow: 'hidden',
                }}
                onClick={() => selectProfile(profile.id)}
                onMouseEnter={() => setExpandedProfile(profile.id)}
                onMouseLeave={() => setExpandedProfile(null)}
              >
                {/* Active indicator bar */}
                {isActive && (
                  <div style={{
                    position: 'absolute',
                    top: 0,
                    left: 0,
                    right: 0,
                    height: '3px',
                    background: `linear-gradient(90deg, ${profile.color}, transparent)`,
                    boxShadow: `0 0 12px ${profile.color}60`,
                  }} />
                )}

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span style={{ fontSize: '1.4rem' }}>{profile.icon}</span>
                    <span style={{
                      fontFamily: 'var(--font-cyber)',
                      fontSize: '0.85rem',
                      color: isActive ? profile.color : 'var(--text-primary)',
                      fontWeight: 700,
                      textShadow: isActive ? `0 0 10px ${profile.color}40` : 'none',
                    }}>
                      {profile.name}
                    </span>
                  </div>
                  {isActive && (
                    <span style={{
                      fontSize: '0.6rem',
                      padding: '2px 8px',
                      borderRadius: '10px',
                      background: `${profile.color}20`,
                      color: profile.color,
                      fontFamily: 'var(--font-mono)',
                      fontWeight: 700,
                    }}>
                      ACTIVE
                    </span>
                  )}
                </div>

                <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', lineHeight: '1.4', marginBottom: '0.5rem' }}>
                  {profile.description}
                </p>

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
                    ⏱️ {profile.duration}
                  </span>
                  <span style={{ fontSize: '0.65rem', color: profile.color, fontFamily: 'var(--font-mono)' }}>
                    {profile.modules.length} modules
                  </span>
                </div>

                {/* Expanded module list */}
                {(isExpanded || isActive) && (
                  <div style={{
                    marginTop: '0.8rem',
                    paddingTop: '0.8rem',
                    borderTop: '1px solid rgba(255,255,255,0.06)',
                  }}>
                    <div style={{ fontSize: '0.65rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', marginBottom: '6px', textTransform: 'uppercase' }}>
                      Included Modules:
                    </div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                      {profile.modules.map((mod, i) => (
                        <span key={i} style={{
                          fontSize: '0.6rem',
                          padding: '2px 8px',
                          borderRadius: '6px',
                          background: `${profile.color}12`,
                          color: profile.color,
                          fontFamily: 'var(--font-mono)',
                          border: `1px solid ${profile.color}25`,
                        }}>
                          {mod}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* ════════════════════════════════════════════════════════════ */}
      {/* ─── 3. EXPORT OPTIONS (REAL DATA) ─── */}
      {/* ════════════════════════════════════════════════════════════ */}
      <div className="glass-panel" style={{ padding: '1.5rem', marginBottom: '1.5rem' }}>
        <h3 style={{ fontSize: '1rem', marginBottom: '1.2rem', display: 'flex', alignItems: 'center', gap: '8px', fontFamily: 'var(--font-cyber)' }}>
          📤 DATA_EXPORT
          {recentScans.length > 0 && (
            <span className="badge badge-green" style={{ fontSize: '0.6rem' }}>
              {recentScans.length} domain{recentScans.length !== 1 ? 's' : ''} available
            </span>
          )}
        </h3>

        {loadingScans ? (
          <div style={{
            textAlign: 'center',
            padding: '2rem',
            color: 'var(--text-secondary)',
            fontFamily: 'var(--font-mono)',
            fontSize: '0.85rem',
          }}>
            <div style={{ marginBottom: '0.5rem', fontSize: '1.5rem' }}>⏳</div>
            Loading scan results...
          </div>
        ) : recentScans.length === 0 ? (
          <div style={{
            textAlign: 'center',
            padding: '2.5rem',
            borderRadius: '12px',
            background: 'rgba(255,255,255,0.02)',
            border: '1px dashed rgba(255,255,255,0.1)',
          }}>
            <div style={{ fontSize: '2.5rem', marginBottom: '0.8rem', opacity: 0.5 }}>📭</div>
            <div style={{ color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', fontSize: '0.85rem', marginBottom: '0.5rem' }}>
              No scan results to export
            </div>
            <div style={{ color: 'var(--text-secondary)', fontSize: '0.75rem', opacity: 0.7 }}>
              Run a scan first to generate exportable data
            </div>
          </div>
        ) : (
          <>
            {/* Domain Selector */}
            <div style={{ display: 'flex', gap: '0.8rem', marginBottom: '1rem', alignItems: 'stretch', flexWrap: 'wrap' }}>
              <div style={{ flex: 1, minWidth: '250px' }}>
                <label style={{ display: 'block', fontSize: '0.7rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', marginBottom: '6px', textTransform: 'uppercase' }}>
                  Select Domain to Export
                </label>
                <select
                  className="input-glass"
                  value={selectedDomain}
                  onChange={(e) => setSelectedDomain(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '0.65rem 1rem',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '0.85rem',
                    color: 'var(--accent-blue)',
                    background: 'rgba(255,255,255,0.03)',
                    border: '1px solid rgba(255,255,255,0.1)',
                    borderRadius: '8px',
                    cursor: 'pointer',
                    appearance: 'none',
                    WebkitAppearance: 'none',
                    backgroundImage: `url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%23768390' d='M6 8L1 3h10z'/%3E%3C/svg%3E")`,
                    backgroundRepeat: 'no-repeat',
                    backgroundPosition: 'right 12px center',
                    paddingRight: '2rem',
                  }}
                >
                  {recentScans.map((scan, i) => {
                    const domain = scan.domain || scan.target || `scan-${i}`;
                    return (
                      <option key={i} value={domain} style={{ background: '#0a0e14', color: '#f0f6fc' }}>
                        {domain}
                      </option>
                    );
                  })}
                </select>
              </div>

              {/* Export Buttons */}
              <div style={{ display: 'flex', gap: '0.6rem', alignItems: 'flex-end' }}>
                <button
                  className="btn-primary"
                  onClick={() => handleExport('json')}
                  disabled={!selectedDomain}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    whiteSpace: 'nowrap',
                  }}
                >
                  <span style={{ fontSize: '1rem' }}>📄</span> Export JSON
                </button>
                <button
                  className="btn-outline"
                  onClick={() => handleExport('csv')}
                  disabled={!selectedDomain}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    whiteSpace: 'nowrap',
                  }}
                >
                  <span style={{ fontSize: '1rem' }}>📊</span> Export CSV
                </button>
              </div>
            </div>

            {/* Export Success Message */}
            {exportSuccess && (
              <div style={{
                padding: '0.6rem 1rem',
                borderRadius: '8px',
                background: 'rgba(57,255,20,0.08)',
                border: '1px solid rgba(57,255,20,0.2)',
                color: 'var(--accent-green)',
                fontFamily: 'var(--font-mono)',
                fontSize: '0.8rem',
                marginBottom: '1rem',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
              }}>
                ✅ {exportSuccess}
              </div>
            )}

            {/* Scanned Domains List */}
            <div style={{ marginTop: '0.5rem' }}>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', marginBottom: '8px', textTransform: 'uppercase' }}>
                📋 Scanned Domains
              </div>
              <div style={{
                maxHeight: '200px',
                overflowY: 'auto',
                borderRadius: '8px',
                border: '1px solid rgba(255,255,255,0.06)',
              }}>
                {recentScans.map((scan, i) => {
                  const domain = scan.domain || scan.target || `scan-${i}`;
                  const scanDate = scan.timestamp || scan.date || scan.created_at || '';
                  const isSelected = domain === selectedDomain;
                  return (
                    <div
                      key={i}
                      onClick={() => setSelectedDomain(domain)}
                      style={{
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        padding: '0.55rem 1rem',
                        cursor: 'pointer',
                        background: isSelected ? 'rgba(0,242,254,0.06)' : i % 2 === 0 ? 'rgba(255,255,255,0.015)' : 'transparent',
                        borderLeft: isSelected ? '3px solid var(--accent-blue)' : '3px solid transparent',
                        transition: 'all 0.2s',
                        borderBottom: i < recentScans.length - 1 ? '1px solid rgba(255,255,255,0.04)' : 'none',
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span style={{ fontSize: '0.75rem' }}>🌐</span>
                        <span style={{
                          fontFamily: 'var(--font-mono)',
                          fontSize: '0.8rem',
                          color: isSelected ? 'var(--accent-blue)' : 'var(--text-primary)',
                        }}>
                          {domain}
                        </span>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        {scanDate && (
                          <span style={{ fontSize: '0.65rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
                            {new Date(scanDate).toLocaleDateString()}
                          </span>
                        )}
                        {scan.security_grade && (
                          <span style={{
                            fontSize: '0.6rem',
                            padding: '1px 6px',
                            borderRadius: '4px',
                            fontFamily: 'var(--font-cyber)',
                            fontWeight: 700,
                            color: scan.security_grade?.startsWith('A') ? 'var(--accent-green)' :
                                   scan.security_grade?.startsWith('B') ? 'var(--accent-blue)' :
                                   scan.security_grade?.startsWith('C') ? 'var(--accent-orange)' : 'var(--accent-red)',
                            background: scan.security_grade?.startsWith('A') ? 'rgba(57,255,20,0.1)' :
                                        scan.security_grade?.startsWith('B') ? 'rgba(0,242,254,0.1)' :
                                        scan.security_grade?.startsWith('C') ? 'rgba(255,159,28,0.1)' : 'rgba(255,0,85,0.1)',
                          }}>
                            {scan.security_grade}
                          </span>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </>
        )}

        {/* Refresh Scans */}
        <div style={{ marginTop: '1rem', textAlign: 'right' }}>
          <button
            className="btn-outline"
            onClick={fetchRecentScans}
            style={{ fontSize: '0.75rem', padding: '0.4rem 1rem' }}
          >
            🔄 Refresh Scan List
          </button>
        </div>
      </div>

      {/* ════════════════════════════════════════════════════════════ */}
      {/* ─── 4. ABOUT ─── */}
      {/* ════════════════════════════════════════════════════════════ */}
      <div className="glass-panel" style={{ padding: '1.5rem' }}>
        <h3 style={{ fontSize: '1rem', marginBottom: '1.2rem', display: 'flex', alignItems: 'center', gap: '8px', fontFamily: 'var(--font-cyber)' }}>
          ℹ️ ABOUT
        </h3>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
          {/* Left: Info */}
          <div>
            {/* Logo / Title */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '1.2rem' }}>
              <div style={{
                width: '50px',
                height: '50px',
                borderRadius: '12px',
                background: 'linear-gradient(135deg, var(--accent-blue), var(--accent-purple))',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: '1.5rem',
                boxShadow: '0 0 20px rgba(0,242,254,0.2)',
              }}>
                🕷️
              </div>
              <div>
                <div style={{ fontFamily: 'var(--font-cyber)', fontSize: '1.1rem', fontWeight: 900 }}>
                  <span className="text-gradient">WebAnalyzer</span>
                </div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                  v3.4.0 • Advanced Web Security Scanner
                </div>
              </div>
            </div>

            {/* Details */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
              {[
                { label: 'Author', value: 'Furkan Dinçer (@frkndncr)', icon: '👤' },
                { label: 'License', value: 'MIT', icon: '📜' },
                { label: 'GitHub', value: 'github.com/frkndncr/WebAnalyzer', icon: '🔗', isLink: true },
              ].map((item, i) => (
                <div key={i} style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '10px',
                  padding: '0.45rem 0',
                  borderBottom: '1px solid rgba(255,255,255,0.04)',
                }}>
                  <span>{item.icon}</span>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', minWidth: '60px' }}>
                    {item.label}:
                  </span>
                  {item.isLink ? (
                    <a
                      href="https://github.com/frkndncr/WebAnalyzer"
                      target="_blank"
                      rel="noopener noreferrer"
                      style={{
                        fontSize: '0.8rem',
                        color: 'var(--accent-blue)',
                        textDecoration: 'none',
                        fontFamily: 'var(--font-mono)',
                        transition: 'color 0.2s',
                      }}
                      onMouseEnter={(e) => e.target.style.color = 'var(--accent-purple)'}
                      onMouseLeave={(e) => e.target.style.color = 'var(--accent-blue)'}
                    >
                      {item.value}
                    </a>
                  ) : (
                    <span style={{ fontSize: '0.8rem', color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>
                      {item.value}
                    </span>
                  )}
                </div>
              ))}
            </div>

            {/* Star on GitHub Button */}
            <div style={{ marginTop: '1.2rem', display: 'flex', gap: '0.6rem' }}>
              <a
                href="https://github.com/frkndncr/WebAnalyzer"
                target="_blank"
                rel="noopener noreferrer"
                className="btn-primary"
                style={{
                  textDecoration: 'none',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px',
                  fontSize: '0.8rem',
                }}
              >
                ⭐ Star on GitHub
              </a>
              <a
                href="https://github.com/frkndncr/WebAnalyzer/issues"
                target="_blank"
                rel="noopener noreferrer"
                className="btn-outline"
                style={{
                  textDecoration: 'none',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px',
                  fontSize: '0.8rem',
                }}
              >
                🐛 Report Issue
              </a>
            </div>
          </div>

          {/* Right: Tech Stack */}
          <div>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', marginBottom: '10px', textTransform: 'uppercase' }}>
              Tech Stack
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', marginBottom: '1.5rem' }}>
              {TECH_STACK.map((tech, i) => (
                <span key={i} style={{
                  fontSize: '0.7rem',
                  padding: '5px 12px',
                  borderRadius: '20px',
                  fontFamily: 'var(--font-mono)',
                  fontWeight: 600,
                  color: tech.color,
                  background: `${tech.color}12`,
                  border: `1px solid ${tech.color}30`,
                  transition: 'all 0.3s',
                  cursor: 'default',
                }}>
                  {tech.name}
                </span>
              ))}
            </div>

            {/* Capabilities SVG Visualization */}
            <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', marginBottom: '10px', textTransform: 'uppercase' }}>
              Core Capabilities
            </div>
            <svg width="100%" height="120" viewBox="0 0 400 120" style={{ opacity: 0.85 }}>
              {[
                { label: 'Recon', pct: 95, color: '#00f2fe' },
                { label: 'Vuln Scan', pct: 88, color: '#da22ff' },
                { label: 'Exploit', pct: 72, color: '#ff0055' },
                { label: 'OSINT', pct: 80, color: '#39ff14' },
                { label: 'Reporting', pct: 90, color: '#ff9f1c' },
              ].map((cap, i) => {
                const y = i * 24 + 4;
                const barWidth = (cap.pct / 100) * 260;
                return (
                  <g key={i}>
                    <text x="0" y={y + 14} fill="#768390" fontSize="10" fontFamily="'JetBrains Mono', monospace">{cap.label}</text>
                    <rect x="80" y={y + 2} width="260" height="14" rx="4" fill="rgba(255,255,255,0.04)" />
                    <rect x="80" y={y + 2} width={barWidth} height="14" rx="4" fill={cap.color} opacity="0.7">
                      <animate attributeName="width" from="0" to={barWidth} dur="1.2s" fill="freeze" />
                    </rect>
                    <text x={80 + barWidth + 8} y={y + 14} fill={cap.color} fontSize="10" fontFamily="'Orbitron', sans-serif" fontWeight="700">{cap.pct}%</text>
                  </g>
                );
              })}
            </svg>
          </div>
        </div>

        {/* Footer */}
        <div style={{
          marginTop: '1.5rem',
          paddingTop: '1rem',
          borderTop: '1px solid rgba(255,255,255,0.06)',
          textAlign: 'center',
        }}>
          <p style={{
            fontSize: '0.7rem',
            color: 'var(--text-secondary)',
            fontFamily: 'var(--font-mono)',
            opacity: 0.7,
          }}>
            Built with 💜 by Furkan Dinçer • MIT License • © 2024-2026
          </p>
        </div>
      </div>
    </div>
  );
};

export default SettingsPage;
