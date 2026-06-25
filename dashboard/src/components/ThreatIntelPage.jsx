import React, { useState, useEffect, useRef, useCallback } from 'react';
import { getApiUrl } from '../config';

/* ─── Threat Radar Dots (random positions in polar coords) ──── */
const generateRadarDots = (count) => {
  const dots = [];
  const num = Math.max(count || 0, 3);
  for (let i = 0; i < num; i++) {
    const angle = Math.random() * 360;
    const radius = 30 + Math.random() * 100;
    const x = 150 + radius * Math.cos((angle * Math.PI) / 180);
    const y = 150 + radius * Math.sin((angle * Math.PI) / 180);
    dots.push({
      x,
      y,
      delay: Math.random() * 3,
      severity: ['#ff0055', '#ff9f1c', '#00f2fe', '#39ff14'][Math.floor(Math.random() * 4)],
    });
  }
  return dots;
};

/* ─── Component ──────────────────────────────────────────────── */
const ThreatIntelPage = ({ domain, setCurrentDomain }) => {
  /* ── Domain input & recent scans ── */
  const [domainInput, setDomainInput] = useState(domain || '');
  const [recentDomains, setRecentDomains] = useState([]);

  /* ── API data state ── */
  const [intelData, setIntelData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  /* ── UI state ── */
  const [activeTab, setActiveTab] = useState('overview');
  const [selectedNode, setSelectedNode] = useState(null);
  const [cveSearch, setCveSearch] = useState('');
  const [iocSort, setIocSort] = useState({ key: 'confidence', asc: false });
  const [attackSurface, setAttackSurface] = useState(5);
  const [vulnDensity, setVulnDensity] = useState(5);
  const [exposure, setExposure] = useState(5);
  const [radarDots, setRadarDots] = useState(() => generateRadarDots(6));
  const riskCanvasRef = useRef(null);

  /* ── Fetch recent scans on mount ── */
  useEffect(() => {
    const fetchRecent = async () => {
      try {
        const res = await fetch(getApiUrl('/api/recent-scans'));
        if (res.ok) {
          const data = await res.json();
          const domains = Array.isArray(data)
            ? data.map((s) => s.domain || s.url || s.target).filter(Boolean)
            : [];
          // deduplicate
          setRecentDomains([...new Set(domains)]);
        }
      } catch (_) {
        /* silently ignore – recent scans is optional */
      }
    };
    fetchRecent();
  }, []);

  /* ── Fetch threat intel for a domain ── */
  const loadIntel = useCallback(async (targetDomain, isPolling = false) => {
    if (!targetDomain || !targetDomain.trim()) return;
    const target = targetDomain.trim().toLowerCase();
    if (!isPolling) {
      setLoading(true);
      setError('');
      setIntelData(null);
      setActiveTab('overview');
      setSelectedNode(null);
    }
    try {
      const res = await fetch(getApiUrl('/api/threat-intel/' + encodeURIComponent(target)));
      if (!res.ok) throw new Error(`Server responded with ${res.status}`);
      const data = await res.json();
      setIntelData(data);

      if (data.is_scanning) {
        setLoading(true);
        // Poll again in 3 seconds
        setTimeout(() => loadIntel(target, true), 3000);
      } else {
        setLoading(false);
        /* Sync sliders to API values */
        if (data.attack_surface != null) setAttackSurface(data.attack_surface);
        if (data.vuln_density != null) setVulnDensity(data.vuln_density);
        if (data.exposure_level != null) setExposure(data.exposure_level);

        /* Regenerate radar dots based on real IOC count */
        const iocCount = Array.isArray(data.iocs) ? data.iocs.length : 6;
        setRadarDots(generateRadarDots(iocCount));
      }

      if (setCurrentDomain) {
        setCurrentDomain(target);
      }
    } catch (err) {
      if (!isPolling) {
        setError(err.message || 'Failed to load threat intelligence');
        setLoading(false);
      } else {
        setTimeout(() => loadIntel(target, true), 5000);
      }
    }
  }, [setCurrentDomain]);

  /* ── Auto-fetch on mount/domain change ── */
  useEffect(() => {
    if (domain) {
      setDomainInput(domain);
      loadIntel(domain);
    }
  }, [domain, loadIntel]);

  /* ── Derived values from API or defaults ── */
  const mitreData = (intelData && Array.isArray(intelData.mitre_techniques)) ? intelData.mitre_techniques : [];
  const cveData = (intelData && Array.isArray(intelData.cves)) ? intelData.cves : [];
  const iocData = (intelData && Array.isArray(intelData.iocs)) ? intelData.iocs : [];
  const hasData = intelData ? intelData.has_data !== false : false;

  /* ── Risk Score ── */
  const riskScore = parseFloat((attackSurface * 0.35 + vulnDensity * 0.35 + exposure * 0.30).toFixed(1));
  const riskColor = riskScore < 4 ? '#39ff14' : riskScore < 7 ? '#ff9f1c' : '#ff0055';
  const riskLabel = riskScore < 4 ? 'LOW' : riskScore < 7 ? 'MODERATE' : 'CRITICAL';

  /* ── Animated risk ring ── */
  useEffect(() => {
    const canvas = riskCanvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const size = 180;
    canvas.width = size * 2;
    canvas.height = size * 2;
    ctx.scale(2, 2); // retina

    let frame;
    let progress = 0;
    const targetAngle = (riskScore / 10) * Math.PI * 2;

    const draw = () => {
      ctx.clearRect(0, 0, size, size);
      const cx = size / 2, cy = size / 2, r = 65;

      // background ring
      ctx.beginPath();
      ctx.arc(cx, cy, r, 0, Math.PI * 2);
      ctx.strokeStyle = 'rgba(255,255,255,0.06)';
      ctx.lineWidth = 10;
      ctx.stroke();

      // progress ring
      if (progress < targetAngle) progress += 0.04;
      else progress = targetAngle;
      ctx.beginPath();
      ctx.arc(cx, cy, r, -Math.PI / 2, -Math.PI / 2 + progress);
      ctx.strokeStyle = riskColor;
      ctx.lineWidth = 10;
      ctx.lineCap = 'round';
      ctx.shadowBlur = 18;
      ctx.shadowColor = riskColor;
      ctx.stroke();
      ctx.shadowBlur = 0;

      // center text
      ctx.fillStyle = riskColor;
      ctx.font = "bold 32px 'Orbitron', sans-serif";
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(riskScore.toFixed(1), cx, cy - 6);

      ctx.fillStyle = '#768390';
      ctx.font = "600 11px 'Inter', sans-serif";
      ctx.fillText(riskLabel, cx, cy + 22);

      if (progress < targetAngle) frame = requestAnimationFrame(draw);
    };
    draw();
    return () => cancelAnimationFrame(frame);
  }, [riskScore, riskColor, riskLabel]);

  /* ── CVE filtering ── */
  const filteredCVEs = cveData.filter(
    (c) =>
      c.id.toLowerCase().includes(cveSearch.toLowerCase()) ||
      (c.description && c.description.toLowerCase().includes(cveSearch.toLowerCase()))
  );

  /* ── IOC sorting ── */
  const sortedIOCs = [...iocData].sort((a, b) => {
    const av = a[iocSort.key], bv = b[iocSort.key];
    if (typeof av === 'number') return iocSort.asc ? av - bv : bv - av;
    return iocSort.asc ? String(av).localeCompare(String(bv)) : String(bv).localeCompare(String(av));
  });

  const toggleSort = (key) => {
    setIocSort((prev) => ({ key, asc: prev.key === key ? !prev.asc : false }));
  };

  const severityStyle = (sev) => {
    const map = {
      CRITICAL: { bg: 'rgba(255,0,85,0.15)', color: '#ff0055', border: 'rgba(255,0,85,0.4)' },
      HIGH: { bg: 'rgba(255,159,28,0.15)', color: '#ff9f1c', border: 'rgba(255,159,28,0.4)' },
      MEDIUM: { bg: 'rgba(0,242,254,0.15)', color: '#00f2fe', border: 'rgba(0,242,254,0.4)' },
      LOW: { bg: 'rgba(118,131,144,0.15)', color: '#768390', border: 'rgba(118,131,144,0.4)' },
    };
    const s = map[sev] || map.LOW;
    return {
      display: 'inline-block', padding: '2px 10px', borderRadius: '4px', fontSize: '0.72rem',
      fontWeight: 700, fontFamily: 'var(--font-mono)',
      background: s.bg, color: s.color, border: `1px solid ${s.border}`,
    };
  };

  const statusStyle = (status) => {
    const m = {
      Exploited: '#ff0055',
      Patched: '#39ff14',
      Mitigated: '#00f2fe',
      Investigating: '#ff9f1c',
      Detected: '#ff9f1c',
    };
    const c = m[status] || '#768390';
    return { color: c, fontFamily: 'var(--font-mono)', fontSize: '0.82rem', fontWeight: 600 };
  };

  const mitreColor = (count) => {
    if (count > 3) return '#ff0055';
    if (count > 1) return '#ff9f1c';
    if (count > 0) return '#39ff14';
    return '#768390';
  };

  /* ── Slider Component ── */
  const RiskSlider = ({ label, value, setValue, emoji }) => (
    <div style={{ marginBottom: '1.2rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{emoji} {label}</span>
        <span style={{ fontFamily: 'var(--font-cyber)', fontSize: '0.85rem', color: riskScore >= 7 ? '#ff0055' : 'var(--accent-blue)', fontWeight: 700 }}>{value}/10</span>
      </div>
      <input
        type="range"
        min="0"
        max="10"
        step="0.5"
        value={value}
        onChange={(e) => setValue(parseFloat(e.target.value))}
        style={{
          width: '100%',
          height: '6px',
          appearance: 'none',
          WebkitAppearance: 'none',
          background: `linear-gradient(90deg, ${riskColor} ${value * 10}%, rgba(255,255,255,0.06) ${value * 10}%)`,
          borderRadius: '4px',
          outline: 'none',
          cursor: 'pointer',
        }}
      />
    </div>
  );

  /* ── Handle form submit ── */
  const handleLoadIntel = (e) => {
    e.preventDefault();
    loadIntel(domainInput);
  };

  /* ── Handle dropdown select ── */
  const handleDomainSelect = (e) => {
    const val = e.target.value;
    if (val) {
      setDomainInput(val);
      loadIntel(val);
    }
  };

  /* ─────────────── RENDER ─────────────── */
  return (
    <div className="animate-fade-in" style={{ maxWidth: '1200px', margin: '0 auto' }}>

      {/* ═══ Section A: Header ═══ */}
      <div style={{ marginBottom: '2rem' }}>
        <h2 style={{ fontSize: '2.2rem', marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '15px' }}>
          <span className="text-gradient">THREAT_INTELLIGENCE</span>
          <span style={{
            fontSize: '0.7rem', padding: '3px 12px', borderRadius: '4px',
            background: 'rgba(255,0,85,0.15)', color: '#ff0055',
            border: '1px solid rgba(255,0,85,0.4)', fontFamily: 'var(--font-mono)',
            fontWeight: 700, letterSpacing: '2px',
            boxShadow: '0 0 12px rgba(255,0,85,0.3)',
            animation: 'pulse-glow-red 2s infinite',
          }}>🔴 CLASSIFIED</span>
        </h2>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', fontFamily: 'var(--font-mono)' }}>
          Advanced Threat Analysis & CVE Database
        </p>
      </div>

      {/* ═══ Domain Input Bar ═══ */}
      <form onSubmit={handleLoadIntel} className="glass-panel" style={{
        padding: '1.2rem 1.5rem', marginBottom: '2rem',
        display: 'flex', alignItems: 'center', gap: '1rem', flexWrap: 'wrap',
      }}>
        <div style={{ flex: 1, minWidth: '220px', position: 'relative' }}>
          <input
            className="input-glass"
            type="text"
            placeholder="Enter target domain (e.g. example.com)"
            value={domainInput}
            onChange={(e) => setDomainInput(e.target.value)}
            style={{ width: '100%', fontFamily: 'var(--font-mono)', fontSize: '0.9rem' }}
          />
        </div>

        {recentDomains.length > 0 && (
          <select
            className="input-glass"
            onChange={handleDomainSelect}
            value=""
            style={{
              minWidth: '200px', fontFamily: 'var(--font-mono)', fontSize: '0.82rem',
              color: 'var(--text-secondary)', cursor: 'pointer',
              background: 'rgba(13,17,23,0.6)', border: '1px solid var(--panel-border)',
              borderRadius: '6px', padding: '0.55rem 0.8rem',
            }}
          >
            <option value="">📂 Recent Scans...</option>
            {recentDomains.map((d) => (
              <option key={d} value={d} style={{ background: '#0d1117', color: '#f0f6fc' }}>{d}</option>
            ))}
          </select>
        )}

        <button type="submit" className="btn-primary" disabled={loading || !domainInput.trim()} style={{
          display: 'flex', alignItems: 'center', gap: '8px',
          padding: '0.6rem 1.6rem', fontFamily: 'var(--font-cyber)',
          fontSize: '0.82rem', letterSpacing: '2px', whiteSpace: 'nowrap',
          opacity: (loading || !domainInput.trim()) ? 0.5 : 1,
        }}>
          {loading ? (
            <>
              <span style={{ display: 'inline-block', animation: 'spin 1s linear infinite' }}>⟳</span>
              LOADING...
            </>
          ) : (
            <>⚡ LOAD INTEL</>
          )}
        </button>
      </form>

      {/* ═══ Error State ═══ */}
      {error && (
        <div className="glass-panel" style={{
          padding: '1.2rem 1.5rem', marginBottom: '2rem',
          borderLeft: '3px solid #ff0055',
          background: 'rgba(255,0,85,0.05)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <span style={{ fontSize: '1.4rem' }}>⚠️</span>
            <div>
              <div style={{ fontFamily: 'var(--font-cyber)', fontSize: '0.82rem', color: '#ff0055', marginBottom: '4px' }}>CONNECTION ERROR</div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{error}</div>
            </div>
          </div>
        </div>
      )}

      {/* ═══ Loading State ═══ */}
      {loading && (
        <div className="glass-panel animate-fade-in" style={{
          padding: '4rem 2rem', textAlign: 'center', marginBottom: '2rem',
        }}>
          <div style={{ marginBottom: '1.5rem' }}>
            <svg width="60" height="60" viewBox="0 0 60 60" style={{ animation: 'spin 2s linear infinite' }}>
              <circle cx="30" cy="30" r="24" fill="none" stroke="rgba(0,242,254,0.15)" strokeWidth="4" />
              <path d="M30,6 A24,24 0 0,1 54,30" fill="none" stroke="#00f2fe" strokeWidth="4" strokeLinecap="round" />
            </svg>
          </div>
          <div style={{ fontFamily: 'var(--font-cyber)', fontSize: '1rem', color: 'var(--accent-blue)', marginBottom: '0.5rem', letterSpacing: '3px' }}>
            {intelData?.is_scanning ? 'AUTO-TRIGGERED SECURITY SCAN IN PROGRESS' : 'SCANNING THREAT DATABASE'}
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
            {intelData?.is_scanning ? (
              <>
                Running module: <span style={{ color: 'var(--accent-orange)' }}>{intelData?.scan_progress?.current_module}</span> ({intelData?.scan_progress?.completed}/{intelData?.scan_progress?.total})
              </>
            ) : (
              'Correlating IOCs, mapping MITRE techniques, assessing risk vectors...'
            )}
          </div>
        </div>
      )}

      {/* ═══ Empty / No Data State ═══ */}
      {intelData && !hasData && !loading && (
        <div className="glass-panel animate-fade-in" style={{
          padding: '4rem 2rem', textAlign: 'center', marginBottom: '2rem',
          borderLeft: '3px solid var(--accent-blue)',
        }}>
          <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>🔎</div>
          <div style={{ fontFamily: 'var(--font-cyber)', fontSize: '1.1rem', color: 'var(--text-primary)', marginBottom: '0.8rem', letterSpacing: '2px' }}>
            NO INTELLIGENCE AVAILABLE
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', color: 'var(--text-secondary)', maxWidth: '500px', margin: '0 auto' }}>
            No threat intelligence available for this domain. Run a scan first.
          </div>
        </div>
      )}

      {/* ═══ Initial "select a domain" prompt ═══ */}
      {!intelData && !loading && !error && (
        <div className="glass-panel animate-fade-in" style={{
          padding: '4rem 2rem', textAlign: 'center', marginBottom: '2rem',
        }}>
          <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>🛰️</div>
          <div style={{ fontFamily: 'var(--font-cyber)', fontSize: '1.1rem', color: 'var(--text-primary)', marginBottom: '0.8rem', letterSpacing: '2px' }}>
            AWAITING TARGET DESIGNATION
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', color: 'var(--text-secondary)', maxWidth: '500px', margin: '0 auto' }}>
            Enter a domain above and click LOAD INTEL to begin threat analysis. You can also select from previously scanned domains.
          </div>
        </div>
      )}

      {/* ═══ Data Sections (only show when we have real data) ═══ */}
      {intelData && hasData && !loading && (
        <>
          {/* ── Domain & Scan Meta Bar ── */}
          <div className="glass-panel" style={{
            padding: '1rem 1.5rem', marginBottom: '2rem',
            display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <span style={{ fontSize: '1.3rem' }}>🌐</span>
              <span style={{ fontFamily: 'var(--font-cyber)', fontSize: '1rem', color: 'var(--text-primary)', letterSpacing: '1px' }}>
                {intelData.domain}
              </span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '1.5rem', flexWrap: 'wrap' }}>
              {intelData.security_grade && (
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>GRADE:</span>
                  <span style={{
                    fontFamily: 'var(--font-cyber)', fontSize: '1.1rem', fontWeight: 900,
                    color: intelData.security_grade === 'A' ? '#39ff14' : intelData.security_grade === 'B' ? '#00f2fe' : intelData.security_grade === 'C' ? '#ff9f1c' : '#ff0055',
                    textShadow: `0 0 8px ${intelData.security_grade === 'A' ? '#39ff14' : intelData.security_grade === 'B' ? '#00f2fe' : intelData.security_grade === 'C' ? '#ff9f1c' : '#ff0055'}60`,
                  }}>
                    {intelData.security_grade}
                  </span>
                </div>
              )}
              {intelData.risk_score != null && (
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>RISK:</span>
                  <span style={{
                    fontFamily: 'var(--font-cyber)', fontSize: '1rem', fontWeight: 700,
                    color: intelData.risk_score >= 7 ? '#ff0055' : intelData.risk_score >= 4 ? '#ff9f1c' : '#39ff14',
                  }}>
                    {Number(intelData.risk_score).toFixed(1)}
                  </span>
                </div>
              )}
              {intelData.scan_date && (
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem', color: 'var(--text-secondary)' }}>
                  📅 {new Date(intelData.scan_date).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
                </div>
              )}
            </div>
          </div>

          {/* ═══ Tab Navigation ═══ */}
          <div style={{
            display: 'flex', gap: '8px', marginBottom: '2rem', flexWrap: 'wrap',
            borderBottom: '1px solid var(--panel-border)', paddingBottom: '8px',
          }}>
            {[
              { id: 'overview', label: 'Threat Overview', icon: '📊' },
              { id: 'cves', label: 'CVEs & IOCs', icon: '🛡️' },
              { id: 'archive', label: 'Wayback Secrets', icon: '🕒' }
            ].map(tab => (
              <button
                key={tab.id}
                type="button"
                className={`btn-outline${activeTab === tab.id ? ' active' : ''}`}
                onClick={() => {
                  setActiveTab(tab.id);
                  setSelectedNode(null);
                }}
                style={{
                  fontFamily: 'var(--font-mono)', fontSize: '0.82rem', padding: '8px 20px',
                  borderRadius: '8px', display: 'flex', alignItems: 'center', gap: '8px',
                  background: activeTab === tab.id ? 'rgba(0,242,254,0.1)' : 'transparent',
                  borderColor: activeTab === tab.id ? 'var(--accent-blue)' : 'var(--panel-border)',
                  color: activeTab === tab.id ? 'var(--text-primary)' : 'var(--text-secondary)',
                  cursor: 'pointer', transition: 'all 0.2s ease',
                }}
              >
                <span>{tab.icon}</span> {tab.label}
              </button>
            ))}
          </div>

          {/* ═══ Tab Content: Overview ═══ */}
          {activeTab === 'overview' && (
            <div className="animate-fade-in">
              <div style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: '2rem', marginBottom: '2.5rem', alignItems: 'start' }}>
                {/* Section B: Threat Radar */}
                <div className="glass-panel" style={{ padding: '1.5rem', textAlign: 'center' }}>
                  <h3 style={{ fontSize: '0.85rem', fontFamily: 'var(--font-cyber)', marginBottom: '1rem', color: 'var(--text-secondary)', letterSpacing: '2px' }}>
                    ⚡ THREAT_RADAR
                  </h3>
                  <svg width="280" height="280" viewBox="0 0 300 300" style={{ display: 'block', margin: '0 auto' }}>
                    <defs>
                      <radialGradient id="radarGrad" cx="50%" cy="50%" r="50%">
                        <stop offset="0%" stopColor="rgba(0,242,254,0.06)" />
                        <stop offset="100%" stopColor="rgba(0,242,254,0)" />
                      </radialGradient>
                      <filter id="glow">
                        <feGaussianBlur stdDeviation="3" result="blur" />
                        <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
                      </filter>
                    </defs>
                    <circle cx="150" cy="150" r="130" fill="url(#radarGrad)" />
                    {[130, 100, 70, 40].map((r) => (
                      <circle key={r} cx="150" cy="150" r={r} fill="none" stroke="rgba(0,242,254,0.15)" strokeWidth="1" />
                    ))}
                    <line x1="150" y1="20" x2="150" y2="280" stroke="rgba(0,242,254,0.08)" strokeWidth="1" />
                    <line x1="20" y1="150" x2="280" y2="150" stroke="rgba(0,242,254,0.08)" strokeWidth="1" />
                    <g style={{ transformOrigin: '150px 150px', animation: 'radarSweep 4s linear infinite' }}>
                      <line x1="150" y1="150" x2="150" y2="20" stroke="rgba(0,242,254,0.8)" strokeWidth="2" filter="url(#glow)" />
                      <path d="M150,150 L150,20 A130,130 0 0,1 242,68 Z" fill="rgba(0,242,254,0.08)" />
                    </g>
                    {radarDots.map((dot, i) => (
                      <circle key={i} cx={dot.x} cy={dot.y} r="4" fill={dot.severity} filter="url(#glow)"
                        style={{ animation: `blinkDot 1.5s ease-in-out ${dot.delay}s infinite` }} />
                    ))}
                    <circle cx="150" cy="150" r="5" fill="#00f2fe" filter="url(#glow)" />
                  </svg>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.8rem' }}>
                    {iocData.length} active threat signatures detected
                  </div>
                </div>

                {/* Section C: MITRE ATT&CK Matrix */}
                <div className="glass-panel" style={{ padding: '1.5rem' }}>
                  <h3 style={{ fontSize: '0.85rem', fontFamily: 'var(--font-cyber)', marginBottom: '1rem', color: 'var(--text-secondary)', letterSpacing: '2px' }}>
                    🎯 MITRE ATT&CK MATRIX
                  </h3>
                  {mitreData.length > 0 ? (
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(155px, 1fr))', gap: '0.7rem' }}>
                      {mitreData.map((cat) => (
                        <div key={cat.id} className="glass-panel" style={{
                          padding: '0.9rem',
                          borderLeft: `3px solid ${mitreColor(cat.detected)}`,
                          cursor: 'pointer',
                          transition: 'all 0.25s ease',
                        }}
                        onMouseEnter={(e) => {
                          e.currentTarget.style.boxShadow = `0 0 18px ${mitreColor(cat.detected)}40`;
                          e.currentTarget.style.borderColor = `${mitreColor(cat.detected)}60`;
                        }}
                        onMouseLeave={(e) => {
                          e.currentTarget.style.boxShadow = '';
                          e.currentTarget.style.borderColor = '';
                        }}>
                          <div style={{ fontFamily: 'var(--font-cyber)', fontSize: '0.68rem', color: 'var(--text-primary)', marginBottom: '4px', lineHeight: 1.3 }}>
                            {cat.name}
                          </div>
                          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.65rem', color: 'var(--text-secondary)', marginBottom: '6px' }}>
                            {cat.id}
                          </div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                            <span style={{
                              fontFamily: 'var(--font-cyber)', fontSize: '1.1rem', fontWeight: 900,
                              color: mitreColor(cat.detected),
                              textShadow: `0 0 8px ${mitreColor(cat.detected)}60`,
                            }}>{cat.detected}</span>
                            <span style={{ fontSize: '0.65rem', color: 'var(--text-secondary)' }}>detected</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}>
                      No MITRE ATT&CK techniques mapped for this domain.
                    </div>
                  )}
                </div>
              </div>

              {/* Section F: Risk Score Calculator */}
              <div className="glass-panel" style={{ padding: '1.5rem' }}>
                <h3 style={{ fontSize: '0.85rem', fontFamily: 'var(--font-cyber)', marginBottom: '1rem', color: 'var(--text-secondary)', letterSpacing: '2px' }}>
                  📊 RISK_CALCULATOR
                </h3>
                <div style={{ display: 'grid', gridTemplateColumns: '180px 1fr', gap: '2rem', alignItems: 'center' }}>
                  <div style={{ display: 'flex', justifyContent: 'center' }}>
                    <canvas ref={riskCanvasRef} style={{ width: '180px', height: '180px' }} />
                  </div>
                  <div>
                    <RiskSlider label="ATTACK_SURFACE" value={attackSurface} setValue={setAttackSurface} emoji="🎯" />
                    <RiskSlider label="VULN_DENSITY" value={vulnDensity} setValue={setVulnDensity} emoji="🐛" />
                    <RiskSlider label="EXPOSURE_LEVEL" value={exposure} setValue={setExposure} emoji="🌐" />
                    <div style={{
                      marginTop: '1rem', padding: '0.8rem', borderRadius: '6px',
                      background: `${riskColor}10`, border: `1px solid ${riskColor}30`,
                      textAlign: 'center', fontFamily: 'var(--font-mono)', fontSize: '0.78rem',
                    }}>
                      <span style={{ color: 'var(--text-secondary)' }}>Composite Risk: </span>
                      <span style={{ color: riskColor, fontWeight: 700, fontSize: '0.9rem' }}>{riskScore.toFixed(1)} / 10.0</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* ═══ Tab Content: CVEs & IOCs ═══ */}
          {activeTab === 'cves' && (
            <div className="animate-fade-in">
              {/* Section D: CVE Database Search */}
              <div className="glass-panel" style={{ padding: '1.5rem', marginBottom: '2rem' }}>
                <h3 style={{ fontSize: '0.85rem', fontFamily: 'var(--font-cyber)', marginBottom: '1rem', color: 'var(--text-secondary)', letterSpacing: '2px', display: 'flex', alignItems: 'center', gap: '10px' }}>
                  🛡️ CVE DATABASE
                  <span style={{
                    fontFamily: 'var(--font-mono)', fontSize: '0.7rem', padding: '2px 8px',
                    borderRadius: '4px', background: 'rgba(0,242,254,0.1)', color: 'var(--accent-blue)',
                    border: '1px solid rgba(0,242,254,0.2)',
                  }}>
                    {cveData.length} entries
                  </span>
                </h3>
                <input
                  className="input-glass"
                  placeholder="Search CVE ID or description..."
                  value={cveSearch}
                  onChange={(e) => setCveSearch(e.target.value)}
                  style={{ marginBottom: '1rem', maxWidth: '450px' }}
                />
                <div style={{ overflowX: 'auto', borderRadius: '8px', border: '1px solid var(--panel-border)' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.83rem' }}>
                    <thead>
                      <tr>
                        {['CVE ID', 'Severity', 'CVSS', 'Description', 'Status'].map((h) => (
                          <th key={h} style={{
                            background: 'rgba(13,17,23,0.6)', padding: '0.7rem 0.9rem', textAlign: 'left',
                            fontWeight: 600, fontSize: '0.73rem', textTransform: 'uppercase', letterSpacing: '0.5px',
                            color: 'var(--text-secondary)', borderBottom: '1px solid var(--panel-border)',
                            fontFamily: 'var(--font-mono)', whiteSpace: 'nowrap',
                          }}>{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {filteredCVEs.map((cve, idx) => (
                        <tr key={cve.id + '-' + idx} style={{ transition: 'background 0.2s' }}
                          onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(0,242,254,0.03)'}
                          onMouseLeave={(e) => e.currentTarget.style.background = ''}>
                          <td style={{ padding: '0.6rem 0.9rem', fontFamily: 'var(--font-mono)', fontWeight: 700, color: 'var(--accent-blue)', whiteSpace: 'nowrap', borderBottom: '1px solid rgba(48,54,61,0.3)' }}>
                            {cve.id}
                          </td>
                          <td style={{ padding: '0.6rem 0.9rem', borderBottom: '1px solid rgba(48,54,61,0.3)' }}>
                            <span style={severityStyle(cve.severity)}>{cve.severity}</span>
                          </td>
                          <td style={{ padding: '0.6rem 0.9rem', fontFamily: 'var(--font-mono)', fontWeight: 700, color: cve.cvss >= 9 ? '#ff0055' : cve.cvss >= 7 ? '#ff9f1c' : '#00f2fe', borderBottom: '1px solid rgba(48,54,61,0.3)' }}>
                            {Number(cve.cvss).toFixed(1)}
                          </td>
                          <td style={{ padding: '0.6rem 0.9rem', color: 'var(--text-secondary)', fontSize: '0.8rem', maxWidth: '400px', borderBottom: '1px solid rgba(48,54,61,0.3)' }}>
                            {cve.description}
                          </td>
                          <td style={{ padding: '0.6rem 0.9rem', borderBottom: '1px solid rgba(48,54,61,0.3)', ...statusStyle(cve.status) }}>
                            {cve.status}
                          </td>
                        </tr>
                      ))}
                      {filteredCVEs.length === 0 && (
                        <tr><td colSpan={5} style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>No matching CVEs found.</td></tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Section E: IOC Table */}
              <div className="glass-panel" style={{ padding: '1.5rem' }}>
                <h3 style={{ fontSize: '0.85rem', fontFamily: 'var(--font-cyber)', marginBottom: '1rem', color: 'var(--text-secondary)', letterSpacing: '2px', display: 'flex', alignItems: 'center', gap: '10px' }}>
                  🔍 INDICATORS OF COMPROMISE
                  <span style={{
                    fontFamily: 'var(--font-mono)', fontSize: '0.7rem', padding: '2px 8px',
                    borderRadius: '4px', background: 'rgba(218,34,255,0.1)', color: '#da22ff',
                    border: '1px solid rgba(218,34,255,0.2)',
                  }}>
                    {iocData.length} IOCs
                  </span>
                </h3>
                <div style={{ overflowX: 'auto', borderRadius: '8px', border: '1px solid var(--panel-border)' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.83rem' }}>
                    <thead>
                      <tr>
                        {[
                          { key: 'type', label: 'Type' },
                          { key: 'value', label: 'Value' },
                          { key: 'confidence', label: 'Confidence' },
                          { key: 'firstSeen', label: 'First Seen' },
                          { key: 'source', label: 'Source' },
                        ].map((col) => (
                          <th key={col.key} onClick={() => toggleSort(col.key)} style={{
                            background: 'rgba(13,17,23,0.6)', padding: '0.7rem 0.9rem', textAlign: 'left',
                            fontWeight: 600, fontSize: '0.73rem', textTransform: 'uppercase', letterSpacing: '0.5px',
                            color: iocSort.key === col.key ? 'var(--accent-blue)' : 'var(--text-secondary)',
                            borderBottom: '1px solid var(--panel-border)', fontFamily: 'var(--font-mono)',
                            cursor: 'pointer', userSelect: 'none', whiteSpace: 'nowrap',
                          }}>
                            {col.label} {iocSort.key === col.key ? (iocSort.asc ? '▲' : '▼') : ''}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {sortedIOCs.length > 0 ? sortedIOCs.map((ioc, i) => (
                        <tr key={i} style={{ transition: 'background 0.2s' }}
                          onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(0,242,254,0.03)'}
                          onMouseLeave={(e) => e.currentTarget.style.background = ''}>
                          <td style={{ padding: '0.6rem 0.9rem', borderBottom: '1px solid rgba(48,54,61,0.3)' }}>
                            <span style={{
                              display: 'inline-block', padding: '2px 8px', borderRadius: '4px', fontSize: '0.72rem',
                              fontWeight: 600, fontFamily: 'var(--font-mono)',
                              background: 'rgba(218,34,255,0.1)', color: '#da22ff', border: '1px solid rgba(218,34,255,0.25)',
                            }}>{ioc.type}</span>
                          </td>
                          <td style={{ padding: '0.6rem 0.9rem', fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: 'var(--text-primary)', borderBottom: '1px solid rgba(48,54,61,0.3)', wordBreak: 'break-all' }}>
                            {ioc.value}
                          </td>
                          <td style={{ padding: '0.6rem 0.9rem', borderBottom: '1px solid rgba(48,54,61,0.3)' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                              <div style={{ width: '50px', height: '5px', borderRadius: '3px', background: 'rgba(255,255,255,0.06)', overflow: 'hidden' }}>
                                <div style={{
                                  width: `${ioc.confidence}%`, height: '100%', borderRadius: '3px',
                                  background: ioc.confidence > 90 ? '#ff0055' : ioc.confidence > 75 ? '#ff9f1c' : '#00f2fe',
                                }} />
                              </div>
                              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', fontWeight: 700, color: ioc.confidence > 90 ? '#ff0055' : ioc.confidence > 75 ? '#ff9f1c' : '#00f2fe' }}>
                                {ioc.confidence}%
                              </span>
                            </div>
                          </td>
                          <td style={{ padding: '0.6rem 0.9rem', fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: 'var(--text-secondary)', borderBottom: '1px solid rgba(48,54,61,0.3)', whiteSpace: 'nowrap' }}>
                            {ioc.firstSeen}
                          </td>
                          <td style={{ padding: '0.6rem 0.9rem', fontSize: '0.8rem', color: 'var(--accent-blue)', borderBottom: '1px solid rgba(48,54,61,0.3)', whiteSpace: 'nowrap' }}>
                            {ioc.source}
                          </td>
                        </tr>
                      )) : (
                        <tr><td colSpan={5} style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>No IOCs detected.</td></tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* ═══ Tab Content: Wayback Secrets ═══ */}
          {activeTab === 'archive' && (
            <div className="animate-fade-in">
              <div className="glass-panel" style={{ padding: '1.5rem' }}>
                <h3 style={{ fontSize: '0.85rem', fontFamily: 'var(--font-cyber)', marginBottom: '1rem', color: 'var(--text-secondary)', letterSpacing: '2px', display: 'flex', alignItems: 'center', gap: '10px' }}>
                  🕒 WAYBACK MACHINE HISTORICAL SECRETS
                  <span style={{
                    fontFamily: 'var(--font-mono)', fontSize: '0.7rem', padding: '2px 8px',
                    borderRadius: '4px', background: 'rgba(255,159,28,0.1)', color: 'var(--accent-orange)',
                    border: '1px solid rgba(255,159,28,0.2)',
                  }}>
                    {(intelData.archive_secrets || []).length} secrets found
                  </span>
                </h3>
                <div style={{ overflowX: 'auto', borderRadius: '8px', border: '1px solid var(--panel-border)' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.83rem' }}>
                    <thead>
                      <tr>
                        {['Secret Type', 'Exposed Value', 'File Location', 'Context Snippet', 'Severity'].map((h) => (
                          <th key={h} style={{
                            background: 'rgba(13,17,23,0.6)', padding: '0.7rem 0.9rem', textAlign: 'left',
                            fontWeight: 600, fontSize: '0.73rem', textTransform: 'uppercase', letterSpacing: '0.5px',
                            color: 'var(--text-secondary)', borderBottom: '1px solid var(--panel-border)',
                            fontFamily: 'var(--font-mono)', whiteSpace: 'nowrap',
                          }}>{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {(intelData.archive_secrets || []).length > 0 ? intelData.archive_secrets.map((sec, idx) => (
                        <tr key={idx} style={{ transition: 'background 0.2s' }}
                          onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(0,242,254,0.03)'}
                          onMouseLeave={(e) => e.currentTarget.style.background = ''}>
                          <td style={{ padding: '0.6rem 0.9rem', fontFamily: 'var(--font-mono)', fontWeight: 700, color: 'var(--accent-blue)', whiteSpace: 'nowrap', borderBottom: '1px solid rgba(48,54,61,0.3)' }}>
                            {sec.type}
                          </td>
                          <td style={{ padding: '0.6rem 0.9rem', fontFamily: 'var(--font-mono)', color: '#ff0055', fontWeight: 600, borderBottom: '1px solid rgba(48,54,61,0.3)' }}>
                            <code>{sec.value}</code>
                          </td>
                          <td style={{ padding: '0.6rem 0.9rem', borderBottom: '1px solid rgba(48,54,61,0.3)', maxWidth: '250px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            <a href={sec.wayback_url} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--accent-green)', textDecoration: 'none' }}>
                              {sec.file_url.split('/').pop()}
                            </a>
                          </td>
                          <td style={{ padding: '0.6rem 0.9rem', color: 'var(--text-secondary)', fontSize: '0.8rem', maxWidth: '350px', borderBottom: '1px solid rgba(48,54,61,0.3)', fontFamily: 'var(--font-mono)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                            {sec.context}
                          </td>
                          <td style={{ padding: '0.6rem 0.9rem', borderBottom: '1px solid rgba(48,54,61,0.3)' }}>
                            <span style={severityStyle(sec.severity ? sec.severity.toUpperCase() : 'HIGH')}>{sec.severity || 'High'}</span>
                          </td>
                        </tr>
                      )) : (
                        <tr>
                          <td colSpan={5} style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
                            No historical secrets detected in Web Archive crawls. Enable "Web Archive Spy" during scan parameters configuration.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}
        </>
      )}

      {/* ═══ CSS Keyframes (injected via style tag) ═══ */}
      <style>{`
        @keyframes radarSweep {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
        @keyframes blinkDot {
          0%, 100% { opacity: 0.3; r: 3; }
          50% { opacity: 1; r: 5; }
        }
        @keyframes pulse-glow-red {
          0% { box-shadow: 0 0 6px rgba(255,0,85,0.3); }
          50% { box-shadow: 0 0 18px rgba(255,0,85,0.6); }
          100% { box-shadow: 0 0 6px rgba(255,0,85,0.3); }
        }
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
        input[type="range"]::-webkit-slider-thumb {
          -webkit-appearance: none;
          appearance: none;
          width: 14px;
          height: 14px;
          border-radius: 50%;
          background: #00f2fe;
          cursor: pointer;
          box-shadow: 0 0 8px rgba(0,242,254,0.6);
          border: 2px solid #05070a;
        }
        input[type="range"]::-moz-range-thumb {
          width: 14px;
          height: 14px;
          border-radius: 50%;
          background: #00f2fe;
          cursor: pointer;
          box-shadow: 0 0 8px rgba(0,242,254,0.6);
          border: 2px solid #05070a;
        }
      `}</style>
    </div>
  );
};

export default ThreatIntelPage;
