import React, { useState, useEffect } from 'react';
import { getApiUrl } from '../config';

/* ─── Scan Profile Data ──────────────────────────────────────── */
const SCAN_PROFILES = [
  {
    id: 'quick',
    name: 'Quick Scan',
    description: 'Basic reconnaissance — Domain Info, DNS, SEO analysis. Ideal for initial surface-level assessment.',
    modules: 4,
    time: '~2 min',
    icon: '⚡',
    color: '#39ff14',
  },
  {
    id: 'standard',
    name: 'Standard Scan',
    description: 'Full passive analysis — all passive modules including WHOIS, SSL, headers, and technology detection.',
    modules: 12,
    time: '~10 min',
    icon: '🔍',
    color: '#00f2fe',
  },
  {
    id: 'deep',
    name: 'Deep Scan',
    description: 'Complete active + passive scan — all modules including port scanning, vulnerability checks, and fuzzing.',
    modules: 24,
    time: '~30 min',
    icon: '🔬',
    color: '#da22ff',
  },
  {
    id: 'stealth',
    name: 'Stealth Scan',
    description: 'Low-profile reconnaissance with rate limiting, randomized timing, and minimal footprint to avoid detection.',
    modules: 18,
    time: '~45 min',
    icon: '👻',
    color: '#ff9f1c',
  },
];

const EXPORT_HISTORY = [
  { date: '2024-12-15 14:32', format: 'JSON', size: '2.4 MB', domain: 'target-corp.com' },
  { date: '2024-12-14 09:18', format: 'CSV', size: '1.1 MB', domain: 'webapp.io' },
  { date: '2024-12-13 22:45', format: 'PDF', size: '3.8 MB', domain: 'secure-bank.net' },
];

const TECH_BADGES = [
  { name: 'React', color: '#61dafb' },
  { name: 'Vite', color: '#646cff' },
  { name: 'FastAPI', color: '#009688' },
  { name: 'Python', color: '#3776ab' },
];

/* ─── Component ──────────────────────────────────────────────── */
const SettingsPage = () => {
  const [activeProfile, setActiveProfile] = useState('standard');
  const [connectionStatus, setConnectionStatus] = useState('checking');
  const [apiVersion, setApiVersion] = useState('—');
  const [exportFormat, setExportFormat] = useState('JSON');
  const [testingConnection, setTestingConnection] = useState(false);

  /* ── Test API Connection ── */
  const testConnection = async () => {
    setTestingConnection(true);
    setConnectionStatus('checking');
    try {
      const resp = await fetch(getApiUrl('/api/stats'), { signal: AbortSignal.timeout(5000) });
      if (resp.ok) {
        setConnectionStatus('connected');
        try {
          const data = await resp.json();
          setApiVersion(data.version || 'v3.3.0');
        } catch {
          setApiVersion('v3.3.0');
        }
      } else {
        setConnectionStatus('disconnected');
      }
    } catch {
      setConnectionStatus('disconnected');
    } finally {
      setTestingConnection(false);
    }
  };

  useEffect(() => {
    testConnection();
  }, []);

  const connColor = connectionStatus === 'connected' ? '#39ff14' : connectionStatus === 'disconnected' ? '#ff0055' : '#ff9f1c';
  const connLabel = connectionStatus === 'connected' ? 'CONNECTED' : connectionStatus === 'disconnected' ? 'DISCONNECTED' : 'CHECKING...';
  const connIndicatorClass = connectionStatus === 'connected' ? 'active' : connectionStatus === 'disconnected' ? 'error' : 'pending';

  const apiUrl = getApiUrl('');

  /* ─────────────── RENDER ─────────────── */
  return (
    <div className="animate-fade-in" style={{ maxWidth: '1100px', margin: '0 auto' }}>

      {/* ═══ Section A: Header ═══ */}
      <div style={{ marginBottom: '2.5rem' }}>
        <h2 style={{ fontSize: '2.2rem', marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '15px' }}>
          <span className="text-gradient">SYSTEM_CONFIGURATION</span>
        </h2>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', fontFamily: "var(--font-mono)" }}>
          Scanner Settings & Preferences
        </p>
      </div>

      {/* ═══ Section B: API Configuration ═══ */}
      <div className="glass-panel" style={{ padding: '1.5rem', marginBottom: '2rem' }}>
        <h3 style={{ fontSize: '0.85rem', fontFamily: "var(--font-cyber)", marginBottom: '1.2rem', color: 'var(--text-secondary)', letterSpacing: '2px' }}>
          🔧 API_CONFIGURATION
        </h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '1.2rem' }}>
          {/* API URL */}
          <div style={{ padding: '1rem', borderRadius: '6px', background: 'rgba(13,17,23,0.5)', border: '1px solid var(--panel-border)' }}>
            <span style={{ display: 'block', fontFamily: "var(--font-mono)", fontSize: '0.7rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '6px' }}>
              API Endpoint
            </span>
            <span style={{ fontFamily: "var(--font-mono)", fontSize: '0.85rem', color: 'var(--accent-blue)', fontWeight: 600, wordBreak: 'break-all' }}>
              {apiUrl}
            </span>
          </div>

          {/* Connection Status */}
          <div style={{ padding: '1rem', borderRadius: '6px', background: 'rgba(13,17,23,0.5)', border: '1px solid var(--panel-border)' }}>
            <span style={{ display: 'block', fontFamily: "var(--font-mono)", fontSize: '0.7rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '6px' }}>
              Connection Status
            </span>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span className={`status-indicator ${connIndicatorClass}`} />
              <span style={{ fontFamily: "var(--font-mono)", fontSize: '0.85rem', color: connColor, fontWeight: 700 }}>
                {connLabel}
              </span>
            </div>
          </div>

          {/* API Version */}
          <div style={{ padding: '1rem', borderRadius: '6px', background: 'rgba(13,17,23,0.5)', border: '1px solid var(--panel-border)' }}>
            <span style={{ display: 'block', fontFamily: "var(--font-mono)", fontSize: '0.7rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: '6px' }}>
              API Version
            </span>
            <span style={{ fontFamily: "var(--font-cyber)", fontSize: '1rem', color: 'var(--text-primary)', fontWeight: 700 }}>
              {apiVersion}
            </span>
          </div>

          {/* Test Connection */}
          <div style={{ display: 'flex', alignItems: 'center' }}>
            <button className="btn-primary" onClick={testConnection} disabled={testingConnection} style={{ width: '100%' }}>
              {testingConnection ? '⏳ TESTING...' : '🔌 TEST CONNECTION'}
            </button>
          </div>
        </div>
      </div>

      {/* ═══ Section C: Scan Profiles ═══ */}
      <div className="glass-panel" style={{ padding: '1.5rem', marginBottom: '2rem' }}>
        <h3 style={{ fontSize: '0.85rem', fontFamily: "var(--font-cyber)", marginBottom: '1.2rem', color: 'var(--text-secondary)', letterSpacing: '2px' }}>
          🎯 SCAN_PROFILES
        </h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(240px, 1fr))', gap: '1rem' }}>
          {SCAN_PROFILES.map((profile) => {
            const isActive = activeProfile === profile.id;
            return (
              <div key={profile.id} className="glass-panel" style={{
                padding: '1.2rem',
                border: isActive ? `2px solid ${profile.color}` : '1px solid var(--glass-border)',
                boxShadow: isActive ? `0 0 20px ${profile.color}30, inset 0 0 30px ${profile.color}05` : '',
                transition: 'all 0.3s ease',
                cursor: 'pointer',
                position: 'relative',
                overflow: 'hidden',
              }}
              onMouseEnter={(e) => { if (!isActive) { e.currentTarget.style.borderColor = `${profile.color}60`; e.currentTarget.style.boxShadow = `0 0 14px ${profile.color}20`; } }}
              onMouseLeave={(e) => { if (!isActive) { e.currentTarget.style.borderColor = ''; e.currentTarget.style.boxShadow = ''; } }}
              onClick={() => setActiveProfile(profile.id)}>

                {/* Active indicator */}
                {isActive && (
                  <div style={{
                    position: 'absolute', top: '8px', right: '8px',
                    padding: '2px 8px', borderRadius: '3px', fontSize: '0.6rem',
                    fontFamily: "var(--font-mono)", fontWeight: 700, letterSpacing: '1px',
                    background: `${profile.color}20`, color: profile.color, border: `1px solid ${profile.color}40`,
                  }}>ACTIVE</div>
                )}

                {/* Icon + Name */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '0.7rem' }}>
                  <span style={{ fontSize: '1.5rem' }}>{profile.icon}</span>
                  <span style={{ fontFamily: "var(--font-cyber)", fontSize: '0.85rem', color: isActive ? profile.color : 'var(--text-primary)', fontWeight: 700 }}>
                    {profile.name}
                  </span>
                </div>

                {/* Description */}
                <p style={{ fontFamily: "var(--font-mono)", fontSize: '0.72rem', color: 'var(--text-secondary)', lineHeight: 1.5, marginBottom: '0.8rem', minHeight: '3.6em' }}>
                  {profile.description}
                </p>

                {/* Stats */}
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.72rem', fontFamily: "var(--font-mono)", marginBottom: '0.8rem' }}>
                  <span style={{ color: 'var(--text-secondary)' }}>
                    Modules: <span style={{ color: 'var(--accent-blue)', fontWeight: 700 }}>{profile.modules}</span>
                  </span>
                  <span style={{ color: 'var(--text-secondary)' }}>
                    ETA: <span style={{ color: 'var(--accent-blue)', fontWeight: 700 }}>{profile.time}</span>
                  </span>
                </div>

                {/* Select button */}
                <button
                  className={isActive ? 'btn-primary' : 'btn-outline'}
                  style={{ width: '100%', padding: '0.5rem', fontSize: '0.72rem' }}
                  onClick={(e) => { e.stopPropagation(); setActiveProfile(profile.id); }}
                >
                  {isActive ? '✓ SELECTED' : 'SELECT'}
                </button>
              </div>
            );
          })}
        </div>
      </div>

      {/* ═══ Section D: Export Options ═══ */}
      <div className="glass-panel" style={{ padding: '1.5rem', marginBottom: '2rem' }}>
        <h3 style={{ fontSize: '0.85rem', fontFamily: "var(--font-cyber)", marginBottom: '1.2rem', color: 'var(--text-secondary)', letterSpacing: '2px' }}>
          📦 EXPORT_OPTIONS
        </h3>
        <div style={{ display: 'flex', gap: '0.8rem', marginBottom: '1rem', flexWrap: 'wrap', alignItems: 'center' }}>
          <span style={{ fontFamily: "var(--font-mono)", fontSize: '0.78rem', color: 'var(--text-secondary)' }}>Format:</span>
          {['JSON', 'CSV', 'PDF'].map((fmt) => (
            <button
              key={fmt}
              className={exportFormat === fmt ? 'btn-primary' : 'btn-outline'}
              style={{ padding: '0.4rem 1.2rem', fontSize: '0.75rem' }}
              onClick={() => setExportFormat(fmt)}
            >
              {fmt === 'JSON' ? '📋' : fmt === 'CSV' ? '📊' : '📄'} {fmt}
            </button>
          ))}
          <button className="btn-primary" style={{ marginLeft: 'auto', padding: '0.5rem 1.5rem', fontSize: '0.75rem' }}>
            ⬇️ DOWNLOAD ALL RESULTS
          </button>
        </div>

        {/* Export History */}
        <div style={{ borderRadius: '8px', border: '1px solid var(--panel-border)', overflow: 'hidden' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.82rem' }}>
            <thead>
              <tr>
                {['Date', 'Domain', 'Format', 'Size'].map((h) => (
                  <th key={h} style={{
                    background: 'rgba(13,17,23,0.6)', padding: '0.6rem 0.9rem', textAlign: 'left',
                    fontWeight: 600, fontSize: '0.72rem', textTransform: 'uppercase', letterSpacing: '0.5px',
                    color: 'var(--text-secondary)', borderBottom: '1px solid var(--panel-border)', fontFamily: "var(--font-mono)",
                  }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {EXPORT_HISTORY.map((exp, i) => (
                <tr key={i} style={{ transition: 'background 0.2s' }}
                  onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(0,242,254,0.03)'}
                  onMouseLeave={(e) => e.currentTarget.style.background = ''}>
                  <td style={{ padding: '0.5rem 0.9rem', fontFamily: "var(--font-mono)", fontSize: '0.78rem', color: 'var(--text-secondary)', borderBottom: '1px solid rgba(48,54,61,0.3)' }}>
                    {exp.date}
                  </td>
                  <td style={{ padding: '0.5rem 0.9rem', fontFamily: "var(--font-mono)", fontSize: '0.78rem', color: 'var(--accent-blue)', fontWeight: 600, borderBottom: '1px solid rgba(48,54,61,0.3)' }}>
                    {exp.domain}
                  </td>
                  <td style={{ padding: '0.5rem 0.9rem', borderBottom: '1px solid rgba(48,54,61,0.3)' }}>
                    <span style={{
                      display: 'inline-block', padding: '2px 8px', borderRadius: '4px', fontSize: '0.7rem',
                      fontWeight: 600, fontFamily: "var(--font-mono)",
                      background: 'rgba(218,34,255,0.1)', color: '#da22ff', border: '1px solid rgba(218,34,255,0.25)',
                    }}>{exp.format}</span>
                  </td>
                  <td style={{ padding: '0.5rem 0.9rem', fontFamily: "var(--font-mono)", fontSize: '0.78rem', color: 'var(--text-secondary)', borderBottom: '1px solid rgba(48,54,61,0.3)' }}>
                    {exp.size}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* ═══ Section E: About ═══ */}
      <div className="glass-panel" style={{ padding: '2rem', marginBottom: '2rem' }}>
        <div style={{ textAlign: 'center', marginBottom: '1.5rem' }}>
          {/* Logo / Title */}
          <div style={{ marginBottom: '0.8rem' }}>
            <svg width="60" height="60" viewBox="0 0 60 60" style={{ display: 'block', margin: '0 auto 1rem' }}>
              <defs>
                <linearGradient id="logoGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                  <stop offset="0%" stopColor="#00f2fe" />
                  <stop offset="100%" stopColor="#da22ff" />
                </linearGradient>
                <filter id="logoGlow">
                  <feGaussianBlur stdDeviation="2" result="blur" />
                  <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
                </filter>
              </defs>
              <circle cx="30" cy="30" r="28" fill="none" stroke="url(#logoGrad)" strokeWidth="2" filter="url(#logoGlow)" />
              <circle cx="30" cy="30" r="20" fill="none" stroke="rgba(0,242,254,0.3)" strokeWidth="1" />
              <circle cx="30" cy="30" r="12" fill="none" stroke="rgba(0,242,254,0.2)" strokeWidth="1" />
              <path d="M30,8 L30,52 M8,30 L52,30" stroke="rgba(0,242,254,0.15)" strokeWidth="1" />
              <circle cx="30" cy="30" r="4" fill="url(#logoGrad)" filter="url(#logoGlow)" />
              <text x="30" y="34" textAnchor="middle" fontSize="10" fontFamily="Orbitron, sans-serif" fontWeight="900" fill="url(#logoGrad)" filter="url(#logoGlow)">W</text>
            </svg>
          </div>
          <h2 style={{ fontFamily: "var(--font-cyber)", fontSize: '1.6rem', marginBottom: '0.3rem' }}>
            <span className="text-gradient">WebAnalyzer</span>
          </h2>
          <div style={{
            display: 'inline-block', padding: '3px 14px', borderRadius: '4px', marginBottom: '0.8rem',
            background: 'rgba(0,242,254,0.1)', border: '1px solid rgba(0,242,254,0.25)',
            fontFamily: "var(--font-cyber)", fontSize: '0.85rem', fontWeight: 700, color: 'var(--accent-blue)',
          }}>v3.3.0</div>
          <p style={{ fontFamily: "var(--font-mono)", fontSize: '0.82rem', color: 'var(--text-secondary)', maxWidth: '500px', margin: '0 auto', lineHeight: 1.6 }}>
            Advanced web security analysis framework. Comprehensive reconnaissance, vulnerability assessment, and threat intelligence platform.
          </p>
        </div>

        {/* Author + Links */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1rem', marginBottom: '1.5rem' }}>
          <div style={{ padding: '1rem', borderRadius: '6px', background: 'rgba(13,17,23,0.5)', border: '1px solid var(--panel-border)', textAlign: 'center' }}>
            <span style={{ display: 'block', fontFamily: "var(--font-mono)", fontSize: '0.68rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '6px' }}>Author</span>
            <span style={{ fontFamily: "var(--font-cyber)", fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)' }}>Furkan Dinçer</span>
            <span style={{ display: 'block', fontFamily: "var(--font-mono)", fontSize: '0.75rem', color: 'var(--accent-blue)', marginTop: '3px' }}>@frkndncr</span>
          </div>
          <div style={{ padding: '1rem', borderRadius: '6px', background: 'rgba(13,17,23,0.5)', border: '1px solid var(--panel-border)', textAlign: 'center' }}>
            <span style={{ display: 'block', fontFamily: "var(--font-mono)", fontSize: '0.68rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '6px' }}>GitHub</span>
            <a href="https://github.com/frkndncr/WebAnalyzer" target="_blank" rel="noopener noreferrer"
              style={{ fontFamily: "var(--font-mono)", fontSize: '0.8rem', color: 'var(--accent-blue)', textDecoration: 'none', wordBreak: 'break-all' }}>
              github.com/frkndncr/WebAnalyzer
            </a>
          </div>
          <div style={{ padding: '1rem', borderRadius: '6px', background: 'rgba(13,17,23,0.5)', border: '1px solid var(--panel-border)', textAlign: 'center' }}>
            <span style={{ display: 'block', fontFamily: "var(--font-mono)", fontSize: '0.68rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '6px' }}>License</span>
            <span style={{ fontFamily: "var(--font-cyber)", fontSize: '0.95rem', fontWeight: 700, color: 'var(--accent-green)' }}>MIT</span>
          </div>
        </div>

        {/* Star + Tech badges */}
        <div style={{ textAlign: 'center' }}>
          <a href="https://github.com/frkndncr/WebAnalyzer" target="_blank" rel="noopener noreferrer" style={{ textDecoration: 'none' }}>
            <button className="btn-primary" style={{ padding: '0.7rem 2rem', fontSize: '0.85rem', marginBottom: '1.2rem' }}>
              ⭐ STAR ON GITHUB
            </button>
          </a>

          <div style={{ marginTop: '0.5rem' }}>
            <span style={{ display: 'block', fontFamily: "var(--font-mono)", fontSize: '0.7rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '0.6rem' }}>
              Built With
            </span>
            <div style={{ display: 'flex', justifyContent: 'center', gap: '0.6rem', flexWrap: 'wrap' }}>
              {TECH_BADGES.map((tech) => (
                <span key={tech.name} style={{
                  display: 'inline-flex', alignItems: 'center', gap: '6px',
                  padding: '4px 12px', borderRadius: '5px',
                  background: `${tech.color}12`, border: `1px solid ${tech.color}35`,
                  fontFamily: "var(--font-mono)", fontSize: '0.75rem', fontWeight: 600, color: tech.color,
                  transition: 'all 0.25s ease',
                }}
                onMouseEnter={(e) => { e.currentTarget.style.boxShadow = `0 0 12px ${tech.color}30`; e.currentTarget.style.borderColor = `${tech.color}60`; }}
                onMouseLeave={(e) => { e.currentTarget.style.boxShadow = ''; e.currentTarget.style.borderColor = `${tech.color}35`; }}>
                  <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: tech.color, display: 'inline-block' }} />
                  {tech.name}
                </span>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default SettingsPage;
