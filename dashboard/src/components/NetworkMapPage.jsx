import React, { useState, useEffect, useRef } from 'react';
import { getApiUrl } from '../config';

/* ─── Sample / Fallback Data ─────────────────────────────────── */
const SAMPLE_DNS = {
  A: ['104.21.32.1', '172.67.154.2'],
  AAAA: ['2606:4700:3030::6815:2001'],
  MX: ['mail.example.com (priority: 10)', 'mail2.example.com (priority: 20)'],
  NS: ['ns1.cloudflare.com', 'ns2.cloudflare.com'],
  TXT: ['v=spf1 include:_spf.google.com ~all', 'google-site-verification=abc123'],
  CNAME: ['www → example.com'],
};

const COMMON_PORTS = [
  { port: 21, service: 'FTP', status: 'Closed' },
  { port: 22, service: 'SSH', status: 'Open' },
  { port: 25, service: 'SMTP', status: 'Filtered' },
  { port: 53, service: 'DNS', status: 'Open' },
  { port: 80, service: 'HTTP', status: 'Open' },
  { port: 110, service: 'POP3', status: 'Closed' },
  { port: 143, service: 'IMAP', status: 'Closed' },
  { port: 443, service: 'HTTPS', status: 'Open' },
  { port: 445, service: 'SMB', status: 'Filtered' },
  { port: 993, service: 'IMAPS', status: 'Closed' },
  { port: 995, service: 'POP3S', status: 'Closed' },
  { port: 1433, service: 'MSSQL', status: 'Closed' },
  { port: 3306, service: 'MySQL', status: 'Filtered' },
  { port: 3389, service: 'RDP', status: 'Closed' },
  { port: 5432, service: 'PostgreSQL', status: 'Open' },
  { port: 5900, service: 'VNC', status: 'Closed' },
  { port: 8080, service: 'HTTP-Alt', status: 'Open' },
  { port: 8443, service: 'HTTPS-Alt', status: 'Filtered' },
  { port: 8888, service: 'HTTP-Proxy', status: 'Closed' },
  { port: 9090, service: 'WebConsole', status: 'Closed' },
];

const SUBDOMAINS = [
  { name: 'www', status: 'active', ip: '104.21.32.1' },
  { name: 'mail', status: 'active', ip: '104.21.32.5' },
  { name: 'api', status: 'active', ip: '104.21.32.10' },
  { name: 'dev', status: 'inactive', ip: '—' },
  { name: 'staging', status: 'takeover', ip: '52.20.100.3' },
  { name: 'admin', status: 'active', ip: '104.21.32.15' },
  { name: 'cdn', status: 'active', ip: '172.67.154.8' },
  { name: 'blog', status: 'inactive', ip: '—' },
];

const TECH_STACK = {
  Frontend: [
    { name: 'React', version: '18.2.0' },
    { name: 'Tailwind CSS', version: '3.4.1' },
    { name: 'Vite', version: '5.1.0' },
  ],
  Backend: [
    { name: 'FastAPI', version: '0.109.0' },
    { name: 'Python', version: '3.12' },
    { name: 'Uvicorn', version: '0.27.0' },
  ],
  Server: [
    { name: 'Nginx', version: '1.25.3' },
    { name: 'Linux', version: 'Ubuntu 22.04' },
  ],
  CDN: [
    { name: 'Cloudflare', version: 'Enterprise' },
  ],
  Analytics: [
    { name: 'Google Analytics', version: 'GA4' },
    { name: 'Hotjar', version: '2.0' },
  ],
  Security: [
    { name: 'WAF', version: 'Cloudflare' },
    { name: 'HSTS', version: 'Enabled' },
    { name: 'CSP', version: 'Strict' },
  ],
};

const SSL_INFO = {
  issuer: "Let's Encrypt Authority X3",
  subject: 'CN=example.com',
  validFrom: '2024-09-15',
  validTo: '2025-12-14',
  serial: '04:8A:3F:B2:91:C7:D5:E6:F0:12:34:56:78:9A:BC:DE',
  protocols: ['TLS 1.2', 'TLS 1.3'],
  chain: ["Let's Encrypt Authority X3", 'DST Root CA X3', 'ISRG Root X1'],
};

/* ─── Helper ─────────────────────────────────────────────────── */
const daysUntil = (dateStr) => {
  const d = new Date(dateStr);
  const now = new Date();
  return Math.ceil((d - now) / (1000 * 60 * 60 * 24));
};

const DNS_ICONS = { A: '🌐', AAAA: '🔗', MX: '📧', NS: '🏷️', TXT: '📝', CNAME: '↪️' };
const TECH_ICONS = { Frontend: '🎨', Backend: '⚙️', Server: '🖥️', CDN: '🚀', Analytics: '📊', Security: '🛡️' };

/* ─── Component ──────────────────────────────────────────────── */
const NetworkMapPage = () => {
  const [domain, setDomain] = useState('example.com');
  const [dnsData, setDnsData] = useState(SAMPLE_DNS);
  const [loading, setLoading] = useState(false);
  const [scanActive, setScanActive] = useState(false);
  const [scannedPorts, setScannedPorts] = useState(new Set());

  /* ── Fetch DNS ── */
  const fetchDNS = async () => {
    if (!domain.trim()) return;
    setLoading(true);
    try {
      const resp = await fetch(getApiUrl('/api/network-map/' + domain.trim()));
      if (resp.ok) {
        const data = await resp.json();
        setDnsData({
          A: data.a_records || data.A || SAMPLE_DNS.A,
          AAAA: data.aaaa_records || data.AAAA || SAMPLE_DNS.AAAA,
          MX: data.mx_records || data.MX || SAMPLE_DNS.MX,
          NS: data.ns_records || data.NS || SAMPLE_DNS.NS,
          TXT: data.txt_records || data.TXT || SAMPLE_DNS.TXT,
          CNAME: data.cname_records || data.CNAME || SAMPLE_DNS.CNAME,
        });
      } else {
        setDnsData(SAMPLE_DNS);
      }
    } catch {
      setDnsData(SAMPLE_DNS);
    } finally {
      setLoading(false);
    }
  };

  /* ── Port scan animation ── */
  const startPortScan = () => {
    setScanActive(true);
    setScannedPorts(new Set());
    let idx = 0;
    const interval = setInterval(() => {
      if (idx >= COMMON_PORTS.length) {
        clearInterval(interval);
        setScanActive(false);
        return;
      }
      setScannedPorts((prev) => new Set([...prev, COMMON_PORTS[idx].port]));
      idx++;
    }, 120);
  };

  const portStatusColor = (status) => {
    if (status === 'Open') return '#39ff14';
    if (status === 'Filtered') return '#ff0055';
    return '#768390';
  };
  const portBg = (status) => {
    if (status === 'Open') return 'rgba(57,255,20,0.08)';
    if (status === 'Filtered') return 'rgba(255,0,85,0.08)';
    return 'rgba(118,131,144,0.05)';
  };

  const subdomainColor = (status) => {
    if (status === 'active') return '#39ff14';
    if (status === 'takeover') return '#ff0055';
    return '#768390';
  };
  const subdomainLabel = (status) => {
    if (status === 'active') return 'ACTIVE';
    if (status === 'takeover') return 'TAKEOVER RISK';
    return 'INACTIVE';
  };

  const sslDaysLeft = daysUntil(SSL_INFO.validTo);
  const sslDayColor = sslDaysLeft > 90 ? '#39ff14' : sslDaysLeft > 30 ? '#ff9f1c' : '#ff0055';

  /* ─────────────── RENDER ─────────────── */
  return (
    <div className="animate-fade-in" style={{ maxWidth: '1200px', margin: '0 auto' }}>

      {/* ═══ Section A: Header ═══ */}
      <div style={{ marginBottom: '2.5rem' }}>
        <h2 style={{ fontSize: '2.2rem', marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '15px' }}>
          <span className="text-gradient">NETWORK_TOPOLOGY</span>
          <span style={{
            fontSize: '0.7rem', padding: '3px 12px', borderRadius: '4px',
            background: 'rgba(57,255,20,0.12)', color: '#39ff14',
            border: '1px solid rgba(57,255,20,0.35)', fontFamily: "var(--font-mono)",
            fontWeight: 700, letterSpacing: '2px',
            boxShadow: '0 0 12px rgba(57,255,20,0.25)',
          }}>🟢 RECON_MODE</span>
        </h2>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', fontFamily: "var(--font-mono)" }}>
          Infrastructure Reconnaissance & Asset Discovery
        </p>
      </div>

      {/* ═══ Section B: DNS Record Visualizer ═══ */}
      <div className="glass-panel" style={{ padding: '1.5rem', marginBottom: '2rem' }}>
        <h3 style={{ fontSize: '0.85rem', fontFamily: "var(--font-cyber)", marginBottom: '1rem', color: 'var(--text-secondary)', letterSpacing: '2px' }}>
          📡 DNS_RECORDS
        </h3>
        <div style={{ display: 'flex', gap: '0.8rem', marginBottom: '1.2rem', flexWrap: 'wrap' }}>
          <input
            className="input-glass"
            placeholder="Enter domain (e.g. example.com)"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && fetchDNS()}
            style={{ maxWidth: '360px', flex: 1 }}
          />
          <button className="btn-primary" onClick={fetchDNS} disabled={loading} style={{ minWidth: '120px' }}>
            {loading ? '⏳ RESOLVING...' : '🔍 RESOLVE'}
          </button>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))', gap: '0.8rem' }}>
          {Object.entries(dnsData).map(([type, records]) => (
            <div key={type} className="glass-panel" style={{ padding: '1rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '0.6rem' }}>
                <span style={{ fontSize: '1.2rem' }}>{DNS_ICONS[type] || '📋'}</span>
                <span style={{ fontFamily: "var(--font-cyber)", fontSize: '0.8rem', color: 'var(--accent-blue)' }}>{type}</span>
                <span style={{
                  marginLeft: 'auto', fontFamily: "var(--font-mono)", fontSize: '0.7rem',
                  padding: '1px 6px', borderRadius: '4px',
                  background: 'rgba(0,242,254,0.1)', color: 'var(--accent-blue)',
                }}>{Array.isArray(records) ? records.length : 0}</span>
              </div>
              {Array.isArray(records) && records.map((r, i) => (
                <div key={i} style={{
                  fontFamily: "var(--font-mono)", fontSize: '0.72rem', color: 'var(--text-secondary)',
                  padding: '3px 0', borderTop: i > 0 ? '1px solid rgba(0,242,254,0.06)' : 'none',
                  wordBreak: 'break-all',
                }}>{r}</div>
              ))}
            </div>
          ))}
        </div>
      </div>

      {/* ═══ Middle Row: Port Scanner + Subdomain Map ═══ */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '2rem', marginBottom: '2rem' }}>

        {/* ═══ Section C: Port Scanner Grid ═══ */}
        <div className="glass-panel" style={{ padding: '1.5rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <h3 style={{ fontSize: '0.85rem', fontFamily: "var(--font-cyber)", color: 'var(--text-secondary)', letterSpacing: '2px' }}>
              🔌 PORT_SCANNER
            </h3>
            <button className="btn-primary" onClick={startPortScan} disabled={scanActive} style={{ padding: '0.4rem 1rem', fontSize: '0.72rem' }}>
              {scanActive ? '⏳ SCANNING...' : '▶ START_SCAN'}
            </button>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(90px, 1fr))', gap: '0.5rem' }}>
            {COMMON_PORTS.map((p) => {
              const visible = scannedPorts.has(p.port) || !scanActive && scannedPorts.size === 0;
              return (
                <div key={p.port} style={{
                  padding: '0.6rem 0.5rem', borderRadius: '6px', textAlign: 'center',
                  background: visible ? portBg(p.status) : 'rgba(255,255,255,0.02)',
                  border: `1px solid ${visible ? `${portStatusColor(p.status)}30` : 'rgba(255,255,255,0.04)'}`,
                  transition: 'all 0.3s ease',
                  opacity: visible ? 1 : 0.3,
                  transform: visible ? 'scale(1)' : 'scale(0.92)',
                }}>
                  <div style={{ fontFamily: "var(--font-cyber)", fontSize: '0.9rem', fontWeight: 900, color: visible ? portStatusColor(p.status) : '#333' }}>
                    {p.port}
                  </div>
                  <div style={{ fontFamily: "var(--font-mono)", fontSize: '0.6rem', color: 'var(--text-secondary)', marginTop: '2px' }}>
                    {p.service}
                  </div>
                  <div style={{
                    fontFamily: "var(--font-mono)", fontSize: '0.58rem', fontWeight: 700, marginTop: '3px',
                    color: visible ? portStatusColor(p.status) : '#333',
                  }}>
                    {visible ? p.status.toUpperCase() : '—'}
                  </div>
                </div>
              );
            })}
          </div>
          <div style={{ marginTop: '0.8rem', display: 'flex', gap: '1rem', justifyContent: 'center' }}>
            {[{ label: 'Open', color: '#39ff14' }, { label: 'Filtered', color: '#ff0055' }, { label: 'Closed', color: '#768390' }].map((l) => (
              <div key={l.label} style={{ display: 'flex', alignItems: 'center', gap: '5px', fontSize: '0.68rem', fontFamily: "var(--font-mono)", color: 'var(--text-secondary)' }}>
                <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: l.color, display: 'inline-block', boxShadow: `0 0 6px ${l.color}60` }} />
                {l.label}
              </div>
            ))}
          </div>
        </div>

        {/* ═══ Section D: Subdomain Map ═══ */}
        <div className="glass-panel" style={{ padding: '1.5rem' }}>
          <h3 style={{ fontSize: '0.85rem', fontFamily: "var(--font-cyber)", marginBottom: '1rem', color: 'var(--text-secondary)', letterSpacing: '2px' }}>
            🗺️ SUBDOMAIN_MAP
          </h3>
          {/* Root */}
          <div style={{ textAlign: 'center', marginBottom: '0.6rem' }}>
            <span style={{
              display: 'inline-block', padding: '0.5rem 1.5rem', borderRadius: '6px',
              background: 'rgba(0,242,254,0.12)', border: '1px solid rgba(0,242,254,0.35)',
              fontFamily: "var(--font-cyber)", fontSize: '0.85rem', fontWeight: 700, color: '#00f2fe',
              boxShadow: '0 0 15px rgba(0,242,254,0.2)',
            }}>{domain || 'example.com'}</span>
          </div>
          {/* Connector line */}
          <div style={{ display: 'flex', justifyContent: 'center', marginBottom: '0.3rem' }}>
            <svg width="200" height="24" viewBox="0 0 200 24">
              <line x1="100" y1="0" x2="100" y2="12" stroke="rgba(0,242,254,0.3)" strokeWidth="2" />
              <line x1="10" y1="12" x2="190" y2="12" stroke="rgba(0,242,254,0.3)" strokeWidth="2" />
            </svg>
          </div>
          {/* Subdomain nodes */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(130px, 1fr))', gap: '0.6rem' }}>
            {SUBDOMAINS.map((sub) => (
              <div key={sub.name} className="glass-panel" style={{
                padding: '0.7rem', textAlign: 'center',
                borderLeft: `3px solid ${subdomainColor(sub.status)}`,
                transition: 'all 0.25s ease',
              }}
              onMouseEnter={(e) => e.currentTarget.style.boxShadow = `0 0 14px ${subdomainColor(sub.status)}30`}
              onMouseLeave={(e) => e.currentTarget.style.boxShadow = ''}>
                <div style={{ fontFamily: "var(--font-mono)", fontSize: '0.82rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                  {sub.name}
                </div>
                <div style={{ fontFamily: "var(--font-mono)", fontSize: '0.62rem', color: 'var(--text-secondary)', marginTop: '2px' }}>
                  {sub.ip}
                </div>
                <div style={{
                  marginTop: '4px', display: 'inline-block', padding: '1px 6px', borderRadius: '3px',
                  fontSize: '0.58rem', fontWeight: 700, fontFamily: "var(--font-mono)",
                  background: `${subdomainColor(sub.status)}15`,
                  color: subdomainColor(sub.status),
                  border: `1px solid ${subdomainColor(sub.status)}30`,
                }}>
                  {subdomainLabel(sub.status)}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ═══ Bottom Row: Tech Stack + SSL Info ═══ */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '2rem', marginBottom: '2rem' }}>

        {/* ═══ Section E: Technology Stack ═══ */}
        <div className="glass-panel" style={{ padding: '1.5rem' }}>
          <h3 style={{ fontSize: '0.85rem', fontFamily: "var(--font-cyber)", marginBottom: '1rem', color: 'var(--text-secondary)', letterSpacing: '2px' }}>
            🧩 TECHNOLOGY_STACK
          </h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.9rem' }}>
            {Object.entries(TECH_STACK).map(([category, techs]) => (
              <div key={category}>
                <div style={{ fontFamily: "var(--font-mono)", fontSize: '0.72rem', color: 'var(--text-secondary)', marginBottom: '0.4rem', textTransform: 'uppercase', letterSpacing: '1px' }}>
                  {TECH_ICONS[category]} {category}
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem' }}>
                  {techs.map((tech) => (
                    <div key={tech.name} style={{
                      display: 'inline-flex', alignItems: 'center', gap: '6px',
                      padding: '4px 10px', borderRadius: '5px',
                      background: 'rgba(0,242,254,0.06)', border: '1px solid rgba(0,242,254,0.15)',
                      transition: 'all 0.25s ease', cursor: 'default',
                    }}
                    onMouseEnter={(e) => { e.currentTarget.style.borderColor = 'rgba(0,242,254,0.4)'; e.currentTarget.style.boxShadow = '0 0 10px rgba(0,242,254,0.15)'; }}
                    onMouseLeave={(e) => { e.currentTarget.style.borderColor = 'rgba(0,242,254,0.15)'; e.currentTarget.style.boxShadow = ''; }}>
                      <span style={{ fontFamily: "var(--font-mono)", fontSize: '0.75rem', color: 'var(--text-primary)', fontWeight: 600 }}>{tech.name}</span>
                      <span style={{
                        fontFamily: "var(--font-mono)", fontSize: '0.62rem', padding: '1px 5px',
                        borderRadius: '3px', background: 'rgba(218,34,255,0.1)', color: '#da22ff',
                      }}>{tech.version}</span>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* ═══ Section F: SSL Certificate Info ═══ */}
        <div className="glass-panel" style={{ padding: '1.5rem' }}>
          <h3 style={{ fontSize: '0.85rem', fontFamily: "var(--font-cyber)", marginBottom: '1rem', color: 'var(--text-secondary)', letterSpacing: '2px' }}>
            🔐 SSL_CERTIFICATE
          </h3>
          {/* Info rows */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', fontFamily: "var(--font-mono)", fontSize: '0.8rem' }}>
            {[
              { label: 'Issuer', value: SSL_INFO.issuer },
              { label: 'Subject', value: SSL_INFO.subject },
              { label: 'Valid From', value: SSL_INFO.validFrom },
              { label: 'Valid To', value: SSL_INFO.validTo },
            ].map((row) => (
              <div key={row.label} style={{ display: 'flex', justifyContent: 'space-between', padding: '0.4rem 0', borderBottom: '1px solid rgba(0,242,254,0.06)' }}>
                <span style={{ color: 'var(--text-secondary)', fontSize: '0.73rem' }}>{row.label}</span>
                <span style={{ color: 'var(--text-primary)', fontWeight: 600, fontSize: '0.75rem', textAlign: 'right' }}>{row.value}</span>
              </div>
            ))}
          </div>

          {/* Serial */}
          <div style={{ marginTop: '0.6rem', padding: '0.5rem 0.7rem', borderRadius: '5px', background: 'rgba(13,17,23,0.5)', border: '1px solid var(--panel-border)' }}>
            <span style={{ fontFamily: "var(--font-mono)", fontSize: '0.65rem', color: 'var(--text-secondary)' }}>Serial: </span>
            <span style={{ fontFamily: "var(--font-mono)", fontSize: '0.65rem', color: 'var(--accent-blue)', wordBreak: 'break-all' }}>{SSL_INFO.serial}</span>
          </div>

          {/* Days remaining */}
          <div style={{
            marginTop: '0.8rem', padding: '0.7rem', borderRadius: '6px',
            background: `${sslDayColor}10`, border: `1px solid ${sslDayColor}30`,
            display: 'flex', justifyContent: 'space-between', alignItems: 'center',
          }}>
            <span style={{ fontFamily: "var(--font-mono)", fontSize: '0.75rem', color: 'var(--text-secondary)' }}>Days Remaining</span>
            <span style={{ fontFamily: "var(--font-cyber)", fontSize: '1.3rem', fontWeight: 900, color: sslDayColor, textShadow: `0 0 10px ${sslDayColor}50` }}>
              {sslDaysLeft}
            </span>
          </div>

          {/* Protocol support */}
          <div style={{ marginTop: '0.8rem' }}>
            <span style={{ fontFamily: "var(--font-mono)", fontSize: '0.7rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '0.4rem' }}>PROTOCOL SUPPORT</span>
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              {SSL_INFO.protocols.map((p) => (
                <span key={p} style={{
                  padding: '3px 10px', borderRadius: '4px', fontFamily: "var(--font-mono)", fontSize: '0.72rem',
                  fontWeight: 700, background: 'rgba(57,255,20,0.1)', color: '#39ff14', border: '1px solid rgba(57,255,20,0.25)',
                }}>{p}</span>
              ))}
            </div>
          </div>

          {/* Certificate Chain */}
          <div style={{ marginTop: '0.8rem' }}>
            <span style={{ fontFamily: "var(--font-mono)", fontSize: '0.7rem', color: 'var(--text-secondary)', display: 'block', marginBottom: '0.4rem' }}>CERTIFICATE CHAIN</span>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
              {SSL_INFO.chain.map((cert, i) => (
                <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                    <span style={{
                      width: '20px', height: '20px', borderRadius: '50%', display: 'flex', alignItems: 'center',
                      justifyContent: 'center', fontSize: '0.6rem', fontWeight: 700, fontFamily: "var(--font-mono)",
                      background: i === 0 ? 'rgba(0,242,254,0.15)' : 'rgba(255,255,255,0.05)',
                      color: i === 0 ? '#00f2fe' : 'var(--text-secondary)',
                      border: `1px solid ${i === 0 ? 'rgba(0,242,254,0.3)' : 'rgba(255,255,255,0.08)'}`,
                    }}>{i + 1}</span>
                    {i < SSL_INFO.chain.length - 1 && <div style={{ width: '1px', height: '10px', background: 'rgba(0,242,254,0.15)' }} />}
                  </div>
                  <span style={{ fontFamily: "var(--font-mono)", fontSize: '0.72rem', color: i === 0 ? 'var(--text-primary)' : 'var(--text-secondary)' }}>
                    {cert}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default NetworkMapPage;
