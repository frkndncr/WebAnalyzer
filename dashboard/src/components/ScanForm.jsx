import React, { useState } from 'react';
import { getApiUrl } from '../config';

const MODULE_DATA = [
  { name: 'Domain Information', icon: '🌐', description: 'WHOIS, registrar, expiration dates', time: '~5s' },
  { name: 'DNS Records', icon: '📡', description: 'A, AAAA, MX, TXT, CNAME records', time: '~8s' },
  { name: 'SEO Analysis', icon: '📊', description: 'Meta tags, Open Graph, indexing', time: '~10s' },
  { name: 'Web Technologies', icon: '⚙️', description: 'Frameworks, CMS, server stack', time: '~6s' },
  { name: 'Security Analysis', icon: '🛡️', description: 'Headers, SSL, vulnerabilities', time: '~30s' },
  { name: 'Advanced Content Scan', icon: '🔬', description: 'Deep crawl, secrets, JS analysis', time: '~2m' },
  { name: 'Contact Spy', icon: '👤', description: 'Emails, phones, social links', time: '~15s' },
  { name: 'Subdomain Discovery', icon: '🗺️', description: 'Subdomain enumeration via subfinder', time: '~20s' },
  { name: 'Subdomain Takeover', icon: '⚠️', description: 'Dangling CNAMEs, takeover checks', time: '~25s' },
  { name: 'CloudFlare Bypass', icon: '☁️', description: 'Origin IP discovery behind CF', time: '~15s' },
  { name: 'Nmap Zero Day Scan', icon: '🎯', description: 'Port scan, service fingerprinting', time: '~1m' },
  { name: 'GEO Analysis', icon: '🌍', description: 'IP geolocation, hosting provider', time: '~5s' },
  { name: 'Web Archive Spy', icon: '🕒', description: 'Wayback CDX Secrets Scraper', time: '~30s' },
  { name: 'Phishing Domain Protection', icon: '🪞', description: 'Typosquatted domain resolver', time: '~40s' },
  { name: 'SSL SAN Association', icon: '🔗', description: 'crt.sh & socket certificate mapping', time: '~10s' },
  { name: 'Attack Path Planner', icon: '🗺️', description: 'Logical exploit chain generator', time: '~5s' },
];

const MODULES = MODULE_DATA.map(m => m.name);

const PRESETS = [
  {
    id: 'quick',
    name: 'Quick',
    icon: '⚡',
    description: 'Fast surface-level reconnaissance',
    time: '~20s',
    color: 'var(--accent-green)',
    modules: ['Domain Information', 'DNS Records', 'GEO Analysis'],
  },
  {
    id: 'standard',
    name: 'Standard',
    icon: '🔍',
    description: 'Balanced scan with key modules',
    time: '~1m',
    color: 'var(--accent-blue)',
    modules: ['Domain Information', 'DNS Records', 'SEO Analysis', 'Web Technologies', 'Security Analysis', 'GEO Analysis'],
  },
  {
    id: 'deep',
    name: 'Deep',
    icon: '💀',
    description: 'Full attack surface analysis',
    time: '~5m',
    color: 'var(--accent-purple)',
    modules: MODULES,
  },
  {
    id: 'stealth',
    name: 'Stealth',
    icon: '🥷',
    description: 'All modules with rate limiting',
    time: '~10m',
    color: 'var(--accent-orange)',
    modules: MODULES,
    stealth: true,
  },
];

const ScanForm = ({ setCurrentDomain, setActiveTab }) => {
  const [domain, setDomain] = useState('');
  const [batchMode, setBatchMode] = useState(false);
  const [batchDomains, setBatchDomains] = useState('');
  const [selectedModules, setSelectedModules] = useState(
    MODULES.reduce((acc, mod) => ({ ...acc, [mod]: true }), {})
  );
  const [loading, setLoading] = useState(false);
  const [activePreset, setActivePreset] = useState(null);
  const [intensity, setIntensity] = useState(5);
  const [hoveredModule, setHoveredModule] = useState(null);

  const toggleModule = (mod) => {
    setActivePreset(null);
    setSelectedModules(prev => ({ ...prev, [mod]: !prev[mod] }));
  };

  const handleSelectAll = (select) => {
    setActivePreset(null);
    setSelectedModules(MODULES.reduce((acc, mod) => ({ ...acc, [mod]: select }), {}));
  };

  const applyPreset = (preset) => {
    setActivePreset(preset.id);
    const newSel = MODULES.reduce((acc, mod) => ({ ...acc, [mod]: preset.modules.includes(mod) }), {});
    setSelectedModules(newSel);
    if (preset.stealth) {
      setIntensity(2);
    }
  };

  const selectedCount = Object.values(selectedModules).filter(Boolean).length;

  const startScan = async (e) => {
    e.preventDefault();

    const domains = batchMode
      ? batchDomains.split('\n').map(d => d.trim()).filter(Boolean)
      : [domain.trim()];

    if (domains.length === 0) return;

    setLoading(true);
    const modulesToRun = Object.keys(selectedModules).filter(m => selectedModules[m]);

    try {
      for (const d of domains) {
        const resp = await fetch(getApiUrl('/api/scan'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ domain: d, modules: modulesToRun })
        });

        if (!resp.ok) {
          alert(`Failed to start scan for ${d}.`);
        }
      }

      const primaryDomain = domains[0];
      setCurrentDomain(primaryDomain);
      setActiveTab('results');
    } catch (err) {
      alert('Error connecting to API. Is FastAPI running on port 8000?');
    } finally {
      setLoading(false);
    }
  };

  const intensityLabel = intensity <= 3 ? 'Low' : intensity <= 6 ? 'Medium' : intensity <= 8 ? 'High' : 'Maximum';
  const intensityColor = intensity <= 3 ? 'var(--accent-green)' : intensity <= 6 ? 'var(--accent-blue)' : intensity <= 8 ? 'var(--accent-orange)' : 'var(--accent-red)';

  return (
    <div className="animate-fade-in" style={{ maxWidth: '1000px', margin: '0 auto' }}>
      <h2 style={{ marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '10px', fontSize: '1.8rem' }}>
        <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="var(--accent-blue)" strokeWidth="2">
          <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"></polygon>
        </svg>
        <span className="text-gradient">Target Acquisition</span>
      </h2>
      <p style={{ color: 'var(--text-secondary)', marginBottom: '2rem', fontSize: '0.9rem' }}>
        Configure your scan parameters and launch reconnaissance
      </p>

      {/* ── Scan Presets ── */}
      <div style={{ marginBottom: '2rem' }}>
        <label style={{ display: 'block', marginBottom: '0.8rem', color: 'var(--text-secondary)', fontSize: '0.85rem', textTransform: 'uppercase', letterSpacing: '1px', fontFamily: 'var(--font-cyber)' }}>
          Scan Presets
        </label>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '1rem' }}>
          {PRESETS.map(preset => (
            <div
              key={preset.id}
              className="glass-panel"
              onClick={() => applyPreset(preset)}
              style={{
                padding: '1.2rem',
                cursor: 'pointer',
                transition: 'all 0.3s ease',
                border: activePreset === preset.id ? `2px solid ${preset.color}` : '1px solid var(--panel-border)',
                boxShadow: activePreset === preset.id ? `0 0 20px ${preset.color}33, inset 0 0 20px ${preset.color}11` : 'none',
                transform: activePreset === preset.id ? 'translateY(-2px)' : 'none',
                textAlign: 'center',
              }}
            >
              <div style={{ fontSize: '2rem', marginBottom: '0.5rem' }}>{preset.icon}</div>
              <div style={{ fontFamily: 'var(--font-cyber)', fontSize: '0.9rem', color: preset.color, marginBottom: '0.3rem' }}>
                {preset.name}
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginBottom: '0.5rem', lineHeight: '1.4' }}>
                {preset.description}
              </div>
              <div style={{
                fontSize: '0.7rem',
                color: 'var(--text-secondary)',
                padding: '0.2rem 0.5rem',
                background: 'rgba(255,255,255,0.05)',
                borderRadius: '4px',
                display: 'inline-block',
                fontFamily: 'var(--font-mono)',
              }}>
                {preset.time} • {preset.modules.length} modules
              </div>
            </div>
          ))}
        </div>
      </div>

      <form onSubmit={startScan}>
        {/* ── Domain Input ── */}
        <div className="glass-panel" style={{ padding: '1.5rem', marginBottom: '1.5rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.8rem' }}>
            <label style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', textTransform: 'uppercase', letterSpacing: '1px', fontFamily: 'var(--font-cyber)' }}>
              {batchMode ? 'Target Domains (one per line)' : 'Target Domain'}
            </label>
            <button
              type="button"
              className="btn-outline"
              onClick={() => setBatchMode(!batchMode)}
              style={{ padding: '0.25rem 0.6rem', fontSize: '0.75rem' }}
            >
              {batchMode ? '🎯 Single Mode' : '📋 Batch Mode'}
            </button>
          </div>

          {batchMode ? (
            <textarea
              className="input-glass"
              placeholder={"example.com\nanother-site.org\ntest-domain.net"}
              value={batchDomains}
              onChange={(e) => setBatchDomains(e.target.value)}
              required
              style={{
                fontSize: '1rem',
                padding: '1rem',
                minHeight: '120px',
                resize: 'vertical',
                fontFamily: 'var(--font-mono)',
                lineHeight: '1.8',
                width: '100%',
                boxSizing: 'border-box',
              }}
            />
          ) : (
            <input
              type="text"
              className="input-glass"
              placeholder="example.com"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              required={!batchMode}
              style={{ fontSize: '1.1rem', padding: '1rem' }}
            />
          )}

          {batchMode && batchDomains.trim() && (
            <div style={{ marginTop: '0.5rem', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
              {batchDomains.split('\n').filter(d => d.trim()).length} domain(s) queued
            </div>
          )}
        </div>

        {/* ── Scan Intensity ── */}
        <div className="glass-panel" style={{ padding: '1.5rem', marginBottom: '1.5rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <label style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', textTransform: 'uppercase', letterSpacing: '1px', fontFamily: 'var(--font-cyber)' }}>
              Scan Intensity
            </label>
            <span style={{
              fontFamily: 'var(--font-mono)',
              fontSize: '0.85rem',
              color: intensityColor,
              padding: '0.2rem 0.6rem',
              background: `${intensityColor}15`,
              border: `1px solid ${intensityColor}40`,
              borderRadius: '4px',
            }}>
              {intensity}/10 — {intensityLabel}
            </span>
          </div>
          <div style={{ position: 'relative' }}>
            <input
              type="range"
              min="1"
              max="10"
              value={intensity}
              onChange={(e) => setIntensity(Number(e.target.value))}
              style={{
                width: '100%',
                height: '6px',
                appearance: 'none',
                WebkitAppearance: 'none',
                background: `linear-gradient(to right, var(--accent-green), var(--accent-blue) 40%, var(--accent-orange) 70%, var(--accent-red))`,
                borderRadius: '3px',
                outline: 'none',
                cursor: 'pointer',
              }}
            />
            <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '0.4rem', fontSize: '0.7rem', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
              <span>Quiet</span>
              <span>Balanced</span>
              <span>Aggressive</span>
            </div>
          </div>
        </div>

        {/* ── Module Selection ── */}
        <div className="glass-panel" style={{ padding: '1.5rem', marginBottom: '1.5rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <div>
              <label style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', textTransform: 'uppercase', letterSpacing: '1px', fontFamily: 'var(--font-cyber)' }}>
                Analysis Modules
              </label>
              <span style={{ marginLeft: '0.8rem', fontSize: '0.8rem', color: 'var(--accent-blue)', fontFamily: 'var(--font-mono)' }}>
                {selectedCount}/{MODULES.length} selected
              </span>
            </div>
            <div style={{ display: 'flex', gap: '8px' }}>
              <button type="button" className="btn-outline" onClick={() => handleSelectAll(true)} style={{ padding: '0.25rem 0.6rem', fontSize: '0.75rem' }}>Select All</button>
              <button type="button" className="btn-outline" onClick={() => handleSelectAll(false)} style={{ padding: '0.25rem 0.6rem', fontSize: '0.75rem' }}>Deselect All</button>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: '0.8rem' }}>
            {MODULE_DATA.map(mod => {
              const isSelected = selectedModules[mod.name];
              const isHovered = hoveredModule === mod.name;
              return (
                <div
                  key={mod.name}
                  onClick={() => toggleModule(mod.name)}
                  onMouseEnter={() => setHoveredModule(mod.name)}
                  onMouseLeave={() => setHoveredModule(null)}
                  style={{
                    padding: '1rem',
                    borderRadius: '8px',
                    cursor: 'pointer',
                    transition: 'all 0.25s ease',
                    background: isSelected
                      ? 'rgba(0, 242, 254, 0.08)'
                      : 'rgba(255, 255, 255, 0.02)',
                    border: isSelected
                      ? '1px solid var(--accent-blue)'
                      : '1px solid var(--panel-border)',
                    transform: isHovered ? 'translateY(-2px)' : 'none',
                    boxShadow: isSelected && isHovered
                      ? '0 4px 20px rgba(0, 242, 254, 0.15)'
                      : isHovered
                        ? '0 4px 15px rgba(255,255,255,0.05)'
                        : 'none',
                    opacity: isSelected ? 1 : 0.6,
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '0.4rem' }}>
                    <span style={{ fontSize: '1.3rem' }}>{mod.icon}</span>
                    <span style={{ fontSize: '0.85rem', fontWeight: 600, color: isSelected ? 'var(--text-primary)' : 'var(--text-secondary)' }}>
                      {mod.name}
                    </span>
                  </div>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', lineHeight: '1.4', marginBottom: '0.3rem' }}>
                    {mod.description}
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontSize: '0.65rem', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
                      {mod.time}
                    </span>
                    <div style={{
                      width: '16px',
                      height: '16px',
                      borderRadius: '4px',
                      border: isSelected ? '2px solid var(--accent-blue)' : '2px solid var(--text-secondary)',
                      background: isSelected ? 'var(--accent-blue)' : 'transparent',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      fontSize: '10px',
                      color: '#000',
                      transition: 'all 0.2s ease',
                    }}>
                      {isSelected && '✓'}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* ── Launch Button ── */}
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '1rem', marginTop: '1.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', flex: 1 }}>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
              <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent-blue)' }}>{selectedCount}</span> modules •
              <span style={{ fontFamily: 'var(--font-mono)', color: intensityColor }}> intensity {intensity}</span>
              {activePreset && <span> • <span style={{ color: 'var(--accent-green)' }}>{PRESETS.find(p => p.id === activePreset)?.name} preset</span></span>}
            </div>
          </div>

          <button
            type="submit"
            className="btn-primary"
            disabled={loading || selectedCount === 0}
            style={{
              minWidth: '220px',
              padding: '0.9rem 2rem',
              display: 'flex',
              justifyContent: 'center',
              alignItems: 'center',
              gap: '10px',
              fontSize: '1rem',
              fontFamily: 'var(--font-cyber)',
              letterSpacing: '1px',
            }}
          >
            {loading ? (
              <>
                <div className="status-indicator pending" style={{ margin: 0 }}></div>
                Initializing...
              </>
            ) : (
              <>
                Launch Scan
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
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
