import React, { useState, useEffect, useRef } from 'react';

/* ─── Sample Data ────────────────────────────────────────────── */
const MITRE_CATEGORIES = [
  { id: 'TA0043', name: 'Reconnaissance', detected: 3 },
  { id: 'TA0042', name: 'Resource Development', detected: 1 },
  { id: 'TA0001', name: 'Initial Access', detected: 4 },
  { id: 'TA0002', name: 'Execution', detected: 2 },
  { id: 'TA0003', name: 'Persistence', detected: 5 },
  { id: 'TA0004', name: 'Privilege Escalation', detected: 0 },
  { id: 'TA0005', name: 'Defense Evasion', detected: 3 },
  { id: 'TA0006', name: 'Credential Access', detected: 1 },
  { id: 'TA0007', name: 'Discovery', detected: 2 },
  { id: 'TA0008', name: 'Lateral Movement', detected: 0 },
  { id: 'TA0009', name: 'Collection', detected: 4 },
  { id: 'TA0010', name: 'Exfiltration', detected: 1 },
  { id: 'TA0040', name: 'Impact', detected: 2 },
];

const SAMPLE_CVES = [
  { id: 'CVE-2024-21762', severity: 'CRITICAL', cvss: 9.8, description: 'FortiOS out-of-bound write vulnerability in SSL VPN allowing RCE via crafted requests', status: 'Exploited' },
  { id: 'CVE-2024-3400', severity: 'CRITICAL', cvss: 10.0, description: 'Palo Alto PAN-OS command injection in GlobalProtect gateway enabling unauthenticated RCE', status: 'Exploited' },
  { id: 'CVE-2024-1709', severity: 'HIGH', cvss: 8.4, description: 'ConnectWise ScreenConnect authentication bypass allowing unauthorized admin access', status: 'Patched' },
  { id: 'CVE-2024-27198', severity: 'HIGH', cvss: 7.5, description: 'JetBrains TeamCity authentication bypass via alternate path vulnerability', status: 'Patched' },
  { id: 'CVE-2024-0012', severity: 'MEDIUM', cvss: 6.3, description: 'OpenSSL timing side-channel in PKCS#1 v1.5 RSA decryption padding oracle', status: 'Mitigated' },
  { id: 'CVE-2024-20353', severity: 'HIGH', cvss: 8.6, description: 'Cisco ASA and FTD denial of service vulnerability in web services interface', status: 'Investigating' },
];

const SAMPLE_IOCS = [
  { type: 'IP Address', value: '185.220.101.34', confidence: 95, firstSeen: '2024-12-01', source: 'AlienVault OTX' },
  { type: 'Domain', value: 'c2-payload.darknode.xyz', confidence: 99, firstSeen: '2024-11-28', source: 'VirusTotal' },
  { type: 'Hash', value: 'a3b4c5d6e7f8901234567890abcdef12', confidence: 87, firstSeen: '2024-12-05', source: 'Hybrid Analysis' },
  { type: 'URL', value: 'https://update-service.evil.com/stage2.bin', confidence: 92, firstSeen: '2024-12-03', source: 'URLhaus' },
  { type: 'Email', value: 'admin@phishing-campaign.ru', confidence: 78, firstSeen: '2024-12-07', source: 'PhishTank' },
  { type: 'IP Address', value: '91.215.85.142', confidence: 88, firstSeen: '2024-12-10', source: 'AbuseIPDB' },
  { type: 'Hash', value: 'e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0', confidence: 94, firstSeen: '2024-12-09', source: 'MalwareBazaar' },
  { type: 'Domain', value: 'exfil-data.ransomgroup.onion', confidence: 96, firstSeen: '2024-12-11', source: 'ThreatFox' },
];

/* ─── Threat Radar Dots (random positions in polar coords) ──── */
const generateRadarDots = () => {
  const dots = [];
  for (let i = 0; i < 12; i++) {
    const angle = Math.random() * 360;
    const radius = 30 + Math.random() * 100;
    const x = 150 + radius * Math.cos((angle * Math.PI) / 180);
    const y = 150 + radius * Math.sin((angle * Math.PI) / 180);
    dots.push({ x, y, delay: Math.random() * 3, severity: ['#ff0055', '#ff9f1c', '#00f2fe', '#39ff14'][Math.floor(Math.random() * 4)] });
  }
  return dots;
};

/* ─── Component ──────────────────────────────────────────────── */
const ThreatIntelPage = () => {
  const [cveSearch, setCveSearch] = useState('');
  const [iocSort, setIocSort] = useState({ key: 'confidence', asc: false });
  const [attackSurface, setAttackSurface] = useState(6);
  const [vulnDensity, setVulnDensity] = useState(4);
  const [exposure, setExposure] = useState(7);
  const [radarDots] = useState(generateRadarDots);
  const riskCanvasRef = useRef(null);

  /* ── Risk Score ── */
  const riskScore = parseFloat(((attackSurface * 0.35 + vulnDensity * 0.35 + exposure * 0.30)).toFixed(1));
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
  const filteredCVEs = SAMPLE_CVES.filter(
    (c) => c.id.toLowerCase().includes(cveSearch.toLowerCase()) || c.description.toLowerCase().includes(cveSearch.toLowerCase())
  );

  /* ── IOC sorting ── */
  const sortedIOCs = [...SAMPLE_IOCS].sort((a, b) => {
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
    return { display: 'inline-block', padding: '2px 10px', borderRadius: '4px', fontSize: '0.72rem', fontWeight: 700, fontFamily: "var(--font-mono)", background: s.bg, color: s.color, border: `1px solid ${s.border}` };
  };

  const statusStyle = (status) => {
    const m = {
      Exploited: '#ff0055',
      Patched: '#39ff14',
      Mitigated: '#00f2fe',
      Investigating: '#ff9f1c',
    };
    const c = m[status] || '#768390';
    return { color: c, fontFamily: "var(--font-mono)", fontSize: '0.82rem', fontWeight: 600 };
  };

  const mitreColor = (count) => {
    if (count > 3) return '#ff0055';
    if (count > 1) return '#ff9f1c';
    return '#39ff14';
  };

  /* ── Slider Component ── */
  const RiskSlider = ({ label, value, setValue, emoji }) => (
    <div style={{ marginBottom: '1.2rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
        <span style={{ fontFamily: "var(--font-mono)", fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{emoji} {label}</span>
        <span style={{ fontFamily: "var(--font-cyber)", fontSize: '0.85rem', color: riskScore >= 7 ? '#ff0055' : 'var(--accent-blue)', fontWeight: 700 }}>{value}/10</span>
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

  /* ─────────────── RENDER ─────────────── */
  return (
    <div className="animate-fade-in" style={{ maxWidth: '1200px', margin: '0 auto' }}>

      {/* ═══ Section A: Header ═══ */}
      <div style={{ marginBottom: '2.5rem' }}>
        <h2 style={{ fontSize: '2.2rem', marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '15px' }}>
          <span className="text-gradient">THREAT_INTELLIGENCE</span>
          <span style={{
            fontSize: '0.7rem', padding: '3px 12px', borderRadius: '4px',
            background: 'rgba(255,0,85,0.15)', color: '#ff0055',
            border: '1px solid rgba(255,0,85,0.4)', fontFamily: "var(--font-mono)",
            fontWeight: 700, letterSpacing: '2px',
            boxShadow: '0 0 12px rgba(255,0,85,0.3)',
            animation: 'pulse-glow-red 2s infinite',
          }}>🔴 CLASSIFIED</span>
        </h2>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', fontFamily: "var(--font-mono)" }}>
          Advanced Threat Analysis & CVE Database
        </p>
      </div>

      {/* ═══ Top Row: Radar + MITRE ═══ */}
      <div style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: '2rem', marginBottom: '2.5rem', alignItems: 'start' }}>

        {/* ═══ Section B: Threat Radar ═══ */}
        <div className="glass-panel" style={{ padding: '1.5rem', textAlign: 'center' }}>
          <h3 style={{ fontSize: '0.85rem', fontFamily: "var(--font-cyber)", marginBottom: '1rem', color: 'var(--text-secondary)', letterSpacing: '2px' }}>
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
            {/* Background fill */}
            <circle cx="150" cy="150" r="130" fill="url(#radarGrad)" />
            {/* Concentric circles */}
            {[130, 100, 70, 40].map((r) => (
              <circle key={r} cx="150" cy="150" r={r} fill="none" stroke="rgba(0,242,254,0.15)" strokeWidth="1" />
            ))}
            {/* Cross lines */}
            <line x1="150" y1="20" x2="150" y2="280" stroke="rgba(0,242,254,0.08)" strokeWidth="1" />
            <line x1="20" y1="150" x2="280" y2="150" stroke="rgba(0,242,254,0.08)" strokeWidth="1" />
            <line x1="55" y1="55" x2="245" y2="245" stroke="rgba(0,242,254,0.05)" strokeWidth="1" />
            <line x1="245" y1="55" x2="55" y2="245" stroke="rgba(0,242,254,0.05)" strokeWidth="1" />
            {/* Sweep */}
            <g style={{ transformOrigin: '150px 150px', animation: 'radarSweep 4s linear infinite' }}>
              <line x1="150" y1="150" x2="150" y2="20" stroke="rgba(0,242,254,0.8)" strokeWidth="2" filter="url(#glow)" />
              <path d="M150,150 L150,20 A130,130 0 0,1 242,68 Z" fill="rgba(0,242,254,0.08)" />
            </g>
            {/* Threat dots */}
            {radarDots.map((dot, i) => (
              <circle key={i} cx={dot.x} cy={dot.y} r="4" fill={dot.severity} filter="url(#glow)"
                style={{ animation: `blinkDot 1.5s ease-in-out ${dot.delay}s infinite` }} />
            ))}
            {/* Center dot */}
            <circle cx="150" cy="150" r="5" fill="#00f2fe" filter="url(#glow)" />
          </svg>
          <div style={{ fontFamily: "var(--font-mono)", fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.8rem' }}>
            {radarDots.length} active threat signatures detected
          </div>
        </div>

        {/* ═══ Section C: MITRE ATT&CK Matrix ═══ */}
        <div className="glass-panel" style={{ padding: '1.5rem' }}>
          <h3 style={{ fontSize: '0.85rem', fontFamily: "var(--font-cyber)", marginBottom: '1rem', color: 'var(--text-secondary)', letterSpacing: '2px' }}>
            🎯 MITRE ATT&CK MATRIX
          </h3>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(155px, 1fr))', gap: '0.7rem' }}>
            {MITRE_CATEGORIES.map((cat) => (
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
                <div style={{ fontFamily: "var(--font-cyber)", fontSize: '0.68rem', color: 'var(--text-primary)', marginBottom: '4px', lineHeight: 1.3 }}>
                  {cat.name}
                </div>
                <div style={{ fontFamily: "var(--font-mono)", fontSize: '0.65rem', color: 'var(--text-secondary)', marginBottom: '6px' }}>
                  {cat.id}
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <span style={{
                    fontFamily: "var(--font-cyber)", fontSize: '1.1rem', fontWeight: 900,
                    color: mitreColor(cat.detected),
                    textShadow: `0 0 8px ${mitreColor(cat.detected)}60`,
                  }}>{cat.detected}</span>
                  <span style={{ fontSize: '0.65rem', color: 'var(--text-secondary)' }}>detected</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ═══ Section D: CVE Database Search ═══ */}
      <div className="glass-panel" style={{ padding: '1.5rem', marginBottom: '2rem' }}>
        <h3 style={{ fontSize: '0.85rem', fontFamily: "var(--font-cyber)", marginBottom: '1rem', color: 'var(--text-secondary)', letterSpacing: '2px', display: 'flex', alignItems: 'center', gap: '10px' }}>
          🛡️ CVE DATABASE
        </h3>
        <input
          className="input-glass"
          placeholder="Search CVE-2024-XXXXX..."
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
                    fontFamily: "var(--font-mono)", whiteSpace: 'nowrap',
                  }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filteredCVEs.map((cve) => (
                <tr key={cve.id} style={{ transition: 'background 0.2s' }}
                  onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(0,242,254,0.03)'}
                  onMouseLeave={(e) => e.currentTarget.style.background = ''}>
                  <td style={{ padding: '0.6rem 0.9rem', fontFamily: "var(--font-mono)", fontWeight: 700, color: 'var(--accent-blue)', whiteSpace: 'nowrap', borderBottom: '1px solid rgba(48,54,61,0.3)' }}>
                    {cve.id}
                  </td>
                  <td style={{ padding: '0.6rem 0.9rem', borderBottom: '1px solid rgba(48,54,61,0.3)' }}>
                    <span style={severityStyle(cve.severity)}>{cve.severity}</span>
                  </td>
                  <td style={{ padding: '0.6rem 0.9rem', fontFamily: "var(--font-mono)", fontWeight: 700, color: cve.cvss >= 9 ? '#ff0055' : cve.cvss >= 7 ? '#ff9f1c' : '#00f2fe', borderBottom: '1px solid rgba(48,54,61,0.3)' }}>
                    {cve.cvss.toFixed(1)}
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
                <tr><td colSpan={5} style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-secondary)', fontFamily: "var(--font-mono)" }}>No matching CVEs found.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* ═══ Bottom Row: IOC + Risk Calculator ═══ */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 340px', gap: '2rem', marginBottom: '2rem' }}>

        {/* ═══ Section E: IOC Table ═══ */}
        <div className="glass-panel" style={{ padding: '1.5rem' }}>
          <h3 style={{ fontSize: '0.85rem', fontFamily: "var(--font-cyber)", marginBottom: '1rem', color: 'var(--text-secondary)', letterSpacing: '2px' }}>
            🔍 INDICATORS OF COMPROMISE
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
                      borderBottom: '1px solid var(--panel-border)', fontFamily: "var(--font-mono)",
                      cursor: 'pointer', userSelect: 'none', whiteSpace: 'nowrap',
                    }}>
                      {col.label} {iocSort.key === col.key ? (iocSort.asc ? '▲' : '▼') : ''}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {sortedIOCs.map((ioc, i) => (
                  <tr key={i} style={{ transition: 'background 0.2s' }}
                    onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(0,242,254,0.03)'}
                    onMouseLeave={(e) => e.currentTarget.style.background = ''}>
                    <td style={{ padding: '0.6rem 0.9rem', borderBottom: '1px solid rgba(48,54,61,0.3)' }}>
                      <span style={{
                        display: 'inline-block', padding: '2px 8px', borderRadius: '4px', fontSize: '0.72rem',
                        fontWeight: 600, fontFamily: "var(--font-mono)",
                        background: 'rgba(218,34,255,0.1)', color: '#da22ff', border: '1px solid rgba(218,34,255,0.25)',
                      }}>{ioc.type}</span>
                    </td>
                    <td style={{ padding: '0.6rem 0.9rem', fontFamily: "var(--font-mono)", fontSize: '0.78rem', color: 'var(--text-primary)', borderBottom: '1px solid rgba(48,54,61,0.3)', wordBreak: 'break-all' }}>
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
                        <span style={{ fontFamily: "var(--font-mono)", fontSize: '0.78rem', fontWeight: 700, color: ioc.confidence > 90 ? '#ff0055' : ioc.confidence > 75 ? '#ff9f1c' : '#00f2fe' }}>
                          {ioc.confidence}%
                        </span>
                      </div>
                    </td>
                    <td style={{ padding: '0.6rem 0.9rem', fontFamily: "var(--font-mono)", fontSize: '0.78rem', color: 'var(--text-secondary)', borderBottom: '1px solid rgba(48,54,61,0.3)', whiteSpace: 'nowrap' }}>
                      {ioc.firstSeen}
                    </td>
                    <td style={{ padding: '0.6rem 0.9rem', fontSize: '0.8rem', color: 'var(--accent-blue)', borderBottom: '1px solid rgba(48,54,61,0.3)', whiteSpace: 'nowrap' }}>
                      {ioc.source}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* ═══ Section F: Risk Score Calculator ═══ */}
        <div className="glass-panel" style={{ padding: '1.5rem' }}>
          <h3 style={{ fontSize: '0.85rem', fontFamily: "var(--font-cyber)", marginBottom: '1rem', color: 'var(--text-secondary)', letterSpacing: '2px' }}>
            📊 RISK_CALCULATOR
          </h3>
          <div style={{ display: 'flex', justifyContent: 'center', marginBottom: '1.5rem' }}>
            <canvas ref={riskCanvasRef} style={{ width: '180px', height: '180px' }} />
          </div>
          <RiskSlider label="ATTACK_SURFACE" value={attackSurface} setValue={setAttackSurface} emoji="🎯" />
          <RiskSlider label="VULN_DENSITY" value={vulnDensity} setValue={setVulnDensity} emoji="🐛" />
          <RiskSlider label="EXPOSURE_LEVEL" value={exposure} setValue={setExposure} emoji="🌐" />
          <div style={{
            marginTop: '1rem', padding: '0.8rem', borderRadius: '6px',
            background: `${riskColor}10`, border: `1px solid ${riskColor}30`,
            textAlign: 'center', fontFamily: "var(--font-mono)", fontSize: '0.78rem',
          }}>
            <span style={{ color: 'var(--text-secondary)' }}>Composite Risk: </span>
            <span style={{ color: riskColor, fontWeight: 700, fontSize: '0.9rem' }}>{riskScore.toFixed(1)} / 10.0</span>
          </div>
        </div>
      </div>

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
