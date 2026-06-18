import React, { useState, useEffect, useRef } from 'react';
import { getApiUrl } from '../config';

/* ───────────────────────────  HELPERS  ─────────────────────────── */

const TECH_CATEGORIES = {
  'Web Server':   ['web_server', 'server', 'http_server'],
  'CMS':          ['cms', 'content_management'],
  'Framework':    ['framework', 'web_framework', 'frontend_framework', 'backend_framework'],
  'Language':     ['language', 'programming_language', 'server_language'],
  'JS Library':   ['javascript_library', 'js_library', 'js_framework', 'javascript_framework', 'javascript'],
  'CSS':          ['css_framework', 'css', 'ui_framework'],
  'Analytics':    ['analytics', 'tracking'],
  'CDN':          ['cdn', 'content_delivery'],
  'Hosting':      ['hosting', 'cloud', 'paas', 'iaas'],
  'Security':     ['security', 'waf', 'firewall', 'ssl'],
  'Database':     ['database', 'db'],
  'Cache':        ['cache', 'caching'],
  'Email':        ['email', 'mail'],
  'DNS':          ['dns', 'nameserver'],
  'Other':        [],
};

const categorizeTech = (key) => {
  const lower = key.toLowerCase();
  for (const [cat, keys] of Object.entries(TECH_CATEGORIES)) {
    if (keys.some(k => lower.includes(k) || lower === k)) return cat;
  }
  return 'Other';
};

const CATEGORY_COLORS = {
  'Web Server':  'badge-blue',
  'CMS':         'badge-purple',
  'Framework':   'badge-green',
  'Language':    'badge-orange',
  'JS Library':  'badge-blue',
  'CSS':         'badge-purple',
  'Analytics':   'badge-orange',
  'CDN':         'badge-green',
  'Hosting':     'badge-blue',
  'Security':    'badge-red',
  'Database':    'badge-purple',
  'Cache':       'badge-green',
  'Email':       'badge-orange',
  'DNS':         'badge-blue',
  'Other':       'badge-blue',
};

const DNS_ICONS = { A: '🌐', AAAA: '🔗', MX: '📧', NS: '🏷️', TXT: '📝', CNAME: '🔀', SOA: '📋', SRV: '🔌', PTR: '↩️', CAA: '🔒' };

const portStateClass = (state) => {
  if (!state) return '';
  const s = String(state).toLowerCase();
  if (s === 'open') return 'port-open';
  if (s.includes('filter')) return 'port-filtered';
  return 'port-closed';
};

/* ───────────────────────────  SCAN LINE ANIMATION  ─────────────── */

const ScanLineOverlay = ({ active }) => {
  if (!active) return null;
  return (
    <div style={{
      position: 'fixed', inset: 0, pointerEvents: 'none', zIndex: 9999,
      overflow: 'hidden',
    }}>
      <div style={{
        position: 'absolute', left: 0, right: 0, height: 2,
        background: 'linear-gradient(90deg, transparent, var(--accent-blue), var(--accent-purple), transparent)',
        boxShadow: '0 0 20px var(--accent-blue), 0 0 60px var(--accent-purple)',
        animation: 'scanDown 2s ease-in-out infinite',
      }} />
      <style>{`@keyframes scanDown{0%{top:-2px}100%{top:100%}}`}</style>
    </div>
  );
};

/* ───────────────────────────  SUB-COMPONENTS  ─────────────────── */

const EmptyState = ({ icon, message }) => (
  <div style={{
    textAlign: 'center', padding: '40px 20px',
    color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)',
    fontSize: 14,
  }}>
    <div style={{ fontSize: 36, marginBottom: 12 }}>{icon}</div>
    <div>{message}</div>
  </div>
);

/* DNS Records Panel */
const DnsSection = ({ dns }) => {
  if (!dns || Object.keys(dns).length === 0) {
    return <EmptyState icon="📡" message="No DNS records found for this domain." />;
  }

  const dnsRecords = dns.records || dns;
  const responseTime = dns.response_time_ms;
  const securityAudit = dns.security_audit;

  const types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'SRV', 'PTR', 'CAA'];

  const getRecordValues = (type) => {
    if (dnsRecords[type]) return dnsRecords[type];
    const matchKey = Object.keys(dnsRecords).find(k => k === type || k.startsWith(type + ' '));
    return matchKey ? dnsRecords[matchKey] : [];
  };

  const active = types.filter(t => {
    const vals = getRecordValues(t);
    return vals && vals.length > 0;
  });
  const empty = types.filter(t => {
    const vals = getRecordValues(t);
    return !vals || vals.length === 0;
  });
  const ordered = [...active, ...empty];

  Object.keys(dnsRecords).forEach(k => {
    const isCovered = types.some(t => k === t || k.startsWith(t + ' '));
    if (!isCovered && k !== 'timestamp' && k !== 'domain') {
      ordered.push(k);
    }
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
      <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', alignItems: 'center' }}>
        {responseTime != null && (
          <div className="glass-panel" style={{ padding: '8px 16px', borderRadius: 8, fontSize: 13, fontFamily: 'var(--font-mono)' }}>
            ⚡ Response Time: <span style={{ color: 'var(--accent-blue)', fontWeight: 'bold' }}>{responseTime} ms</span>
          </div>
        )}
        {securityAudit && securityAudit.score != null && (
          <div className="glass-panel" style={{ padding: '8px 16px', borderRadius: 8, fontSize: 13, fontFamily: 'var(--font-cyber)', display: 'flex', alignItems: 'center', gap: 8 }}>
            🛡️ Security Grade: 
            <span style={{ 
              color: securityAudit.score >= 80 ? 'var(--accent-green)' : securityAudit.score >= 60 ? 'var(--accent-orange)' : 'var(--accent-red)',
              fontWeight: 'bold',
              background: 'rgba(255,255,255,0.05)',
              padding: '2px 8px',
              borderRadius: 4
            }}>
              {securityAudit.grade || 'N/A'} ({securityAudit.score}/100)
            </span>
          </div>
        )}
      </div>

      {securityAudit && (
        <div className="glass-panel" style={{ padding: 20, borderRadius: 12 }}>
          <h4 style={{ margin: '0 0 16px', fontSize: 14, fontFamily: 'var(--font-cyber)', color: 'var(--text-primary)', letterSpacing: 1 }}>
            🛡️ DNS SECURITY AUDIT
          </h4>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 16, marginBottom: 16 }}>
            {securityAudit.spf && (
              <div style={{ padding: 12, background: 'rgba(255,255,255,0.02)', borderRadius: 8, border: '1px solid var(--panel-border)' }}>
                <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 4 }}>SPF RECORD</div>
                <div style={{ display: 'flex', gap: 6, alignItems: 'center', fontSize: 12, fontFamily: 'var(--font-mono)' }}>
                  <span style={{ color: securityAudit.spf.status === 'Found' ? 'var(--accent-green)' : 'var(--accent-red)' }}>
                    ● {securityAudit.spf.status}
                  </span>
                </div>
                {securityAudit.spf.record && (
                  <div style={{ fontSize: 10, fontFamily: 'var(--font-mono)', wordBreak: 'break-all', marginTop: 6, color: 'var(--text-secondary)', background: 'rgba(0,0,0,0.2)', padding: 6, borderRadius: 4 }}>
                    {securityAudit.spf.record}
                  </div>
                )}
              </div>
            )}
            {securityAudit.dmarc && (
              <div style={{ padding: 12, background: 'rgba(255,255,255,0.02)', borderRadius: 8, border: '1px solid var(--panel-border)' }}>
                <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 4 }}>DMARC POLICY</div>
                <div style={{ display: 'flex', gap: 6, alignItems: 'center', fontSize: 12, fontFamily: 'var(--font-mono)' }}>
                  <span style={{ color: securityAudit.dmarc.status === 'Found' ? 'var(--accent-green)' : 'var(--accent-red)' }}>
                    ● {securityAudit.dmarc.status}
                  </span>
                </div>
                {securityAudit.dmarc.record && (
                  <div style={{ fontSize: 10, fontFamily: 'var(--font-mono)', wordBreak: 'break-all', marginTop: 6, color: 'var(--text-secondary)', background: 'rgba(0,0,0,0.2)', padding: 6, borderRadius: 4 }}>
                    {securityAudit.dmarc.record}
                  </div>
                )}
              </div>
            )}
            {securityAudit.dnssec && (
              <div style={{ padding: 12, background: 'rgba(255,255,255,0.02)', borderRadius: 8, border: '1px solid var(--panel-border)' }}>
                <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 4 }}>DNSSEC STATUS</div>
                <div style={{ fontSize: 12, fontFamily: 'var(--font-mono)', color: securityAudit.dnssec.enabled ? 'var(--accent-green)' : 'var(--text-secondary)' }}>
                  {securityAudit.dnssec.enabled ? '🟢 Enabled' : '⚪ Disabled'}
                </div>
              </div>
            )}
            {securityAudit.caa && (
              <div style={{ padding: 12, background: 'rgba(255,255,255,0.02)', borderRadius: 8, border: '1px solid var(--panel-border)' }}>
                <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 4 }}>CAA POLICY</div>
                <div style={{ fontSize: 12, fontFamily: 'var(--font-mono)', color: securityAudit.caa.status === 'Found' ? 'var(--accent-green)' : 'var(--text-secondary)' }}>
                  {securityAudit.caa.status === 'Found' ? '🟢 Found' : '⚪ Missing'}
                </div>
              </div>
            )}
          </div>
          {securityAudit.weaknesses && securityAudit.weaknesses.length > 0 && (
            <div style={{ borderTop: '1px solid var(--panel-border)', paddingTop: 16 }}>
              <div style={{ fontSize: 12, color: 'var(--accent-orange)', fontFamily: 'var(--font-cyber)', marginBottom: 8, letterSpacing: 0.5 }}>
                ⚠️ VULNERABILITIES & WEAKNESSES
              </div>
              <ul style={{ margin: 0, paddingLeft: 20, display: 'flex', flexDirection: 'column', gap: 6 }}>
                {securityAudit.weaknesses.map((w, idx) => (
                  <li key={idx} style={{ fontSize: 12, color: 'var(--text-secondary)', fontFamily: 'var(--font-sans)' }}>{w}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: 16 }}>
        {ordered.map(type => {
          const vals = getRecordValues(type);
          const icon = DNS_ICONS[type.split(' ')[0]] || '📄';
          return (
            <div key={type} className="glass-panel" style={{
              padding: 16, borderRadius: 12,
              borderLeft: vals.length > 0 ? '3px solid var(--accent-blue)' : '3px solid var(--panel-border)',
            }}>
              <div style={{
                display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10,
                fontFamily: 'var(--font-cyber)', fontSize: 13, color: 'var(--text-primary)',
                letterSpacing: 1,
              }}>
                <span>{icon}</span>
                <span>{type}</span>
                <span style={{
                  marginLeft: 'auto', fontSize: 11,
                  background: vals.length > 0 ? 'rgba(0,242,254,0.15)' : 'rgba(118,131,144,0.15)',
                  color: vals.length > 0 ? 'var(--accent-blue)' : 'var(--text-secondary)',
                  padding: '2px 8px', borderRadius: 6,
                }}>
                  {vals.length > 0 ? `${vals.length} record${vals.length > 1 ? 's' : ''}` : '—'}
                </span>
              </div>
              {vals.length > 0 ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  {vals.map((rec, i) => {
                    const val = typeof rec === 'object' ? (rec.value || rec.address || rec.exchange || JSON.stringify(rec)) : String(rec);
                    return (
                      <div key={i} style={{
                        fontFamily: 'var(--font-mono)', fontSize: 12,
                        color: 'var(--accent-green)',
                        background: 'rgba(57,255,20,0.05)',
                        padding: '6px 10px', borderRadius: 6,
                        wordBreak: 'break-all',
                      }}>
                        {typeof rec === 'object' && rec.priority != null && (
                          <span style={{ color: 'var(--accent-orange)', marginRight: 8 }}>[pri:{rec.priority}]</span>
                        )}
                        {val}
                      </div>
                    );
                  })}
                </div>
              ) : (
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-secondary)' }}>—</div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};

/* Port Scanner Panel */
const PortSection = ({ ports }) => {
  if (!ports || ports.length === 0) {
    return <EmptyState icon="🔌" message="No port scan data available. Enable Nmap module." />;
  }

  const openCount = ports.filter(p => String(p.state || p.status || '').toLowerCase() === 'open').length;
  const filteredCount = ports.filter(p => String(p.state || p.status || '').toLowerCase().includes('filter')).length;
  const closedCount = ports.length - openCount - filteredCount;

  return (
    <>
      {/* summary bar */}
      <div style={{
        display: 'flex', gap: 20, marginBottom: 16, flexWrap: 'wrap',
        fontFamily: 'var(--font-mono)', fontSize: 13,
      }}>
        <span style={{ color: 'var(--accent-green)' }}>● Open: {openCount}</span>
        <span style={{ color: 'var(--accent-orange)' }}>◐ Filtered: {filteredCount}</span>
        <span style={{ color: 'var(--text-secondary)' }}>○ Closed: {closedCount}</span>
        <span style={{ marginLeft: 'auto', color: 'var(--text-secondary)' }}>Total: {ports.length}</span>
      </div>
      <div className="port-grid">
        {ports.map((p, i) => {
          const state = String(p.state || p.status || 'unknown').toLowerCase();
          return (
            <div key={i} className={`port-card ${portStateClass(state)}`}>
              <div style={{
                fontFamily: 'var(--font-cyber)', fontSize: 18,
                color: state === 'open' ? 'var(--accent-green)' : state.includes('filter') ? 'var(--accent-orange)' : 'var(--text-secondary)',
                marginBottom: 4,
              }}>
                {p.port}
              </div>
              <div style={{
                fontFamily: 'var(--font-mono)', fontSize: 11,
                color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: 1,
                marginBottom: 4,
              }}>
                {p.service || 'unknown'}
              </div>
              <div style={{
                fontSize: 10, fontFamily: 'var(--font-mono)', textTransform: 'uppercase',
                color: state === 'open' ? 'var(--accent-green)' : state.includes('filter') ? 'var(--accent-orange)' : 'var(--text-secondary)',
                letterSpacing: 1.5,
              }}>
                {state}
              </div>
              {p.version && (
                <div style={{ fontSize: 10, color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', marginTop: 4 }}>
                  {p.version}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </>
  );
};

/* Subdomain Map Panel */
const SubdomainSection = ({ subdomains, takeoverData }) => {
  if (!subdomains || subdomains.length === 0) {
    return <EmptyState icon="🗺️" message="No subdomains discovered." />;
  }

  const takeoverMap = {};
  if (takeoverData && Array.isArray(takeoverData)) {
    takeoverData.forEach(item => {
      takeoverMap[item.subdomain] = item.vulnerable;
    });
  }

  const atRisk = subdomains.filter(s => takeoverMap[s]);

  return (
    <>
      {atRisk.length > 0 && (
        <div style={{
          background: 'rgba(255,0,85,0.08)', border: '1px solid rgba(255,0,85,0.3)',
          borderRadius: 10, padding: '12px 16px', marginBottom: 16,
          fontFamily: 'var(--font-mono)', fontSize: 12,
          color: 'var(--accent-red)', display: 'flex', alignItems: 'center', gap: 10,
        }}>
          <span style={{ fontSize: 20 }}>⚠️</span>
          <span>{atRisk.length} subdomain{atRisk.length > 1 ? 's' : ''} at risk of takeover</span>
        </div>
      )}
      <div style={{ marginBottom: 12, fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-secondary)' }}>
        {subdomains.length} subdomain{subdomains.length !== 1 ? 's' : ''} discovered
      </div>
      {/* Subdomain visual map – SVG node graph */}
      <SubdomainGraph subdomains={subdomains} takeoverMap={takeoverMap} />
      {/* List fallback */}
      <div style={{
        display: 'flex', flexWrap: 'wrap', gap: 8, marginTop: 16,
      }}>
        {subdomains.map((sub, i) => {
          const isRisk = takeoverMap[sub];
          return (
            <div key={i} style={{
              fontFamily: 'var(--font-mono)', fontSize: 11,
              padding: '5px 12px', borderRadius: 20,
              background: isRisk ? 'rgba(255,0,85,0.12)' : 'rgba(0,242,254,0.08)',
              border: `1px solid ${isRisk ? 'rgba(255,0,85,0.4)' : 'rgba(0,242,254,0.2)'}`,
              color: isRisk ? 'var(--accent-red)' : 'var(--accent-blue)',
              display: 'flex', alignItems: 'center', gap: 6,
            }}>
              {isRisk && <span style={{ fontSize: 10 }}>🔓</span>}
              {sub}
            </div>
          );
        })}
      </div>
    </>
  );
};

/* SVG subdomain graph */
const SubdomainGraph = ({ subdomains, takeoverMap }) => {
  const containerRef = useRef(null);
  const [transform, setTransform] = useState({ x: 0, y: 0, scale: 1 });
  const [isDragging, setIsDragging] = useState(false);
  const dragStart = useRef({ x: 0, y: 0 });

  const maxShow = Math.min(subdomains.length, 60);
  const subs = subdomains.slice(0, maxShow);
  const cx = 300, cy = 200, R = 160;

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const handleWheel = (e) => {
      e.preventDefault();
      const scaleFactor = 1.1;
      let newScale = transform.scale;
      if (e.deltaY < 0) {
        newScale = Math.min(transform.scale * scaleFactor, 5);
      } else {
        newScale = Math.max(transform.scale / scaleFactor, 0.25);
      }
      setTransform(prev => ({ ...prev, scale: newScale }));
    };

    container.addEventListener('wheel', handleWheel, { passive: false });
    return () => {
      container.removeEventListener('wheel', handleWheel);
    };
  }, [transform.scale]);

  const handleMouseDown = (e) => {
    if (e.button !== 0) return;
    setIsDragging(true);
    dragStart.current = { x: e.clientX - transform.x, y: e.clientY - transform.y };
  };

  const handleMouseMove = (e) => {
    if (!isDragging) return;
    setTransform(prev => ({
      ...prev,
      x: e.clientX - dragStart.current.x,
      y: e.clientY - dragStart.current.y
    }));
  };

  const handleMouseUp = () => {
    setIsDragging(false);
  };

  const zoomIn = () => {
    setTransform(prev => ({ ...prev, scale: Math.min(prev.scale * 1.2, 5) }));
  };

  const zoomOut = () => {
    setTransform(prev => ({ ...prev, scale: Math.max(prev.scale / 1.2, 0.25) }));
  };

  const resetZoom = () => {
    setTransform({ x: 0, y: 0, scale: 1 });
  };

  return (
    <div 
      ref={containerRef}
      onMouseDown={handleMouseDown}
      onMouseMove={handleMouseMove}
      onMouseUp={handleMouseUp}
      onMouseLeave={handleMouseUp}
      style={{
        position: 'relative',
        width: '100%',
        height: '400px',
        border: '1px solid var(--panel-border)',
        borderRadius: '12px',
        background: 'rgba(0,0,0,0.3)',
        overflow: 'hidden',
        cursor: isDragging ? 'grabbing' : 'grab',
        userSelect: 'none'
      }}
    >
      <div style={{
        position: 'absolute',
        top: '12px',
        right: '12px',
        display: 'flex',
        flexDirection: 'column',
        gap: '6px',
        zIndex: 10,
      }}>
        <button className="btn-outline" onClick={zoomIn} style={{ padding: '6px 12px', minWidth: '32px', fontFamily: 'var(--font-cyber)' }}>+</button>
        <button className="btn-outline" onClick={zoomOut} style={{ padding: '6px 12px', minWidth: '32px', fontFamily: 'var(--font-cyber)' }}>-</button>
        <button className="btn-outline" onClick={resetZoom} style={{ padding: '6px 10px', fontSize: '10px', fontFamily: 'var(--font-cyber)', textTransform: 'uppercase' }}>Reset</button>
      </div>

      <svg 
        viewBox="0 0 600 400" 
        style={{ 
          width: '100%', 
          height: '100%', 
          fontFamily: 'var(--font-mono)' 
        }}
      >
        <g transform={`translate(${transform.x}, ${transform.y}) scale(${transform.scale})`} style={{ transformOrigin: '300px 200px', transition: isDragging ? 'none' : 'transform 0.1s ease-out' }}>
          <circle cx={cx} cy={cy} r={28} fill="rgba(0,242,254,0.12)" stroke="var(--accent-blue)" strokeWidth={2} />
          <text x={cx} y={cy + 4} textAnchor="middle" fill="var(--accent-blue)" fontSize={10} fontWeight="bold">ROOT</text>
          
          {subs.map((sub, i) => {
            const angle = (2 * Math.PI * i) / subs.length - Math.PI / 2;
            const r = R + (i % 2 === 0 ? 0 : 30);
            const nx = cx + r * Math.cos(angle);
            const ny = cy + r * Math.sin(angle);
            const isRisk = takeoverMap[sub];
            const color = isRisk ? 'var(--accent-red)' : 'var(--accent-green)';
            return (
              <g key={i}>
                <line x1={cx} y1={cy} x2={nx} y2={ny} stroke={isRisk ? 'rgba(255,0,85,0.25)' : 'rgba(0,242,254,0.15)'} strokeWidth={1} />
                <circle cx={nx} cy={ny} r={6} fill={isRisk ? 'rgba(255,0,85,0.25)' : 'rgba(57,255,20,0.2)'} stroke={color} strokeWidth={1.5}>
                  {isRisk && <animate attributeName="r" values="6;9;6" dur="1.5s" repeatCount="indefinite" />}
                </circle>
                <text x={nx} y={ny - 10} textAnchor="middle" fill={color} fontSize={7} style={{ pointerEvents: 'none' }}>
                  {sub.length > 22 ? sub.slice(0, 20) + '…' : sub}
                </text>
              </g>
            );
          })}
        </g>
      </svg>
      {subdomains.length > maxShow && (
        <div style={{
          position: 'absolute',
          bottom: '12px',
          left: '50%',
          transform: 'translateX(-50%)',
          fontFamily: 'var(--font-mono)',
          fontSize: '11px',
          color: 'var(--text-secondary)',
          background: 'rgba(0,0,0,0.6)',
          padding: '4px 8px',
          borderRadius: '4px',
          border: '1px solid var(--panel-border)',
          pointerEvents: 'none'
        }}>
          +{subdomains.length - maxShow} more subdomains (zoom / drag to explore)
        </div>
      )}
    </div>
  );
};

/* Technology Stack Panel */
const TechSection = ({ technologies }) => {
  if (!technologies || Object.keys(technologies).length === 0) {
    return <EmptyState icon="⚙️" message="No technology data." />;
  }

  // Group techs by category
  const grouped = {};
  Object.entries(technologies).forEach(([key, value]) => {
    if (value == null || value === '' || value === false) return;
    const cat = categorizeTech(key);
    if (!grouped[cat]) grouped[cat] = [];
    // value can be string, array, or object
    const vals = Array.isArray(value) ? value : [value];
    vals.forEach(v => {
      const display = typeof v === 'object' ? JSON.stringify(v) : String(v);
      grouped[cat].push({ key, display });
    });
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {Object.entries(grouped).map(([cat, items]) => (
        <div key={cat}>
          <div style={{
            fontFamily: 'var(--font-cyber)', fontSize: 12, letterSpacing: 1,
            color: 'var(--text-secondary)', marginBottom: 10, textTransform: 'uppercase',
          }}>
            {cat}
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
            {items.map((item, i) => (
              <span key={i} className={`badge ${CATEGORY_COLORS[cat] || 'badge-blue'}`} style={{ fontSize: 12 }}>
                {item.display}
              </span>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
};

/* SSL & Domain Info Panel */
const InfoSection = ({ domainInfo, sslInfo }) => {
  const hasDomain = domainInfo && Object.keys(domainInfo).length > 0;
  const hasSsl = sslInfo && (sslInfo.issues?.length > 0 || Object.keys(sslInfo).length > 1);

  if (!hasDomain && !hasSsl) {
    return <EmptyState icon="🔒" message="No domain/SSL information available. Run a domain info scan." />;
  }

  const formatKey = (k) => k.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());

  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 20 }}>
      {/* Domain info */}
      {hasDomain && (
        <div className="glass-panel" style={{ padding: 20, borderRadius: 14 }}>
          <div style={{
            fontFamily: 'var(--font-cyber)', fontSize: 14, letterSpacing: 1,
            color: 'var(--accent-blue)', marginBottom: 14,
            display: 'flex', alignItems: 'center', gap: 8,
          }}>
            <span>🌐</span> Domain Info
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {Object.entries(domainInfo).map(([k, v]) => {
              if (v == null || v === '' || (Array.isArray(v) && v.length === 0)) return null;
              const display = Array.isArray(v) ? v.join(', ') : typeof v === 'object' ? JSON.stringify(v) : String(v);
              return (
                <div key={k} style={{ display: 'flex', gap: 12, fontSize: 12, fontFamily: 'var(--font-mono)' }}>
                  <span style={{ color: 'var(--text-secondary)', minWidth: 140, flexShrink: 0 }}>{formatKey(k)}</span>
                  <span style={{ color: 'var(--text-primary)', wordBreak: 'break-all' }}>{display}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* SSL info */}
      {hasSsl && (
        <div className="glass-panel" style={{ padding: 20, borderRadius: 14 }}>
          <div style={{
            fontFamily: 'var(--font-cyber)', fontSize: 14, letterSpacing: 1,
            color: 'var(--accent-purple)', marginBottom: 14,
            display: 'flex', alignItems: 'center', gap: 8,
          }}>
            <span>🔒</span> SSL / TLS Info
          </div>
          {/* show issues */}
          {sslInfo.issues && sslInfo.issues.length > 0 && (
            <div style={{ marginBottom: 14 }}>
              <div style={{ fontSize: 12, fontFamily: 'var(--font-mono)', color: 'var(--accent-red)', marginBottom: 8 }}>Issues Found:</div>
              {sslInfo.issues.map((issue, i) => (
                <div key={i} style={{
                  fontSize: 12, fontFamily: 'var(--font-mono)',
                  color: 'var(--accent-orange)',
                  background: 'rgba(255,159,28,0.06)', borderRadius: 6,
                  padding: '6px 10px', marginBottom: 4,
                  borderLeft: '3px solid var(--accent-orange)',
                }}>
                  ⚠ {typeof issue === 'object' ? JSON.stringify(issue) : issue}
                </div>
              ))}
            </div>
          )}
          {/* other ssl fields */}
          {Object.entries(sslInfo).filter(([k]) => k !== 'issues').map(([k, v]) => {
            if (v == null || v === '') return null;
            const display = Array.isArray(v) ? v.join(', ') : typeof v === 'object' ? JSON.stringify(v) : String(v);
            return (
              <div key={k} style={{ display: 'flex', gap: 12, fontSize: 12, fontFamily: 'var(--font-mono)', marginBottom: 6 }}>
                <span style={{ color: 'var(--text-secondary)', minWidth: 140 }}>{formatKey(k)}</span>
                <span style={{ color: 'var(--text-primary)', wordBreak: 'break-all' }}>{display}</span>
              </div>
            );
          })}
          {(!sslInfo.issues || sslInfo.issues.length === 0) && Object.keys(sslInfo).filter(k => k !== 'issues').length === 0 && (
            <div style={{ fontSize: 12, fontFamily: 'var(--font-mono)', color: 'var(--accent-green)' }}>✓ No SSL issues detected</div>
          )}
        </div>
      )}
    </div>
  );
};

/* Phishing Monitor Panel */
const PhishingSection = ({ phishingDomains }) => {
  if (!phishingDomains || phishingDomains.length === 0) {
    return <EmptyState icon="🪞" message="No active typosquatted domains found. Brand reputation is secure." />;
  }

  return (
    <div>
      <div style={{ marginBottom: 12, fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-secondary)' }}>
        Discovered {phishingDomains.length} typosquatted/homoglyph domain variations resolved in public DNS.
      </div>
      <div style={{ overflowX: 'auto', borderRadius: '8px', border: '1px solid var(--panel-border)' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.83rem' }}>
          <thead>
            <tr>
              {['Variation Domain', 'IP Addresses', 'Threat Severity', 'Status'].map((h) => (
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
            {phishingDomains.map((item, idx) => (
              <tr key={idx} style={{ transition: 'background 0.2s' }}
                onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(255,0,85,0.03)'}
                onMouseLeave={(e) => e.currentTarget.style.background = ''}>
                <td style={{ padding: '0.6rem 0.9rem', fontFamily: 'var(--font-mono)', fontWeight: 700, color: 'var(--accent-red)', borderBottom: '1px solid rgba(48,54,61,0.3)' }}>
                  {item.domain}
                </td>
                <td style={{ padding: '0.6rem 0.9rem', fontFamily: 'var(--font-mono)', color: 'var(--text-primary)', borderBottom: '1px solid rgba(48,54,61,0.3)' }}>
                  {item.ips.join(', ')}
                </td>
                <td style={{ padding: '0.6rem 0.9rem', borderBottom: '1px solid rgba(48,54,61,0.3)' }}>
                  <span style={{
                    display: 'inline-block', padding: '2px 10px', borderRadius: '4px', fontSize: '0.72rem',
                    fontWeight: 700, fontFamily: 'var(--font-mono)',
                    background: 'rgba(255,0,85,0.15)', color: '#ff0055', border: '1px solid rgba(255,0,85,0.4)',
                  }}>{item.severity || 'High'}</span>
                </td>
                <td style={{ padding: '0.6rem 0.9rem', borderBottom: '1px solid rgba(48,54,61,0.3)', color: '#ff0055', fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
                  ● Active
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

/* SSL Associated Infrastructure Panel */
const AssociatedSection = ({ associatedSans }) => {
  if (!associatedSans || associatedSans.length === 0) {
    return <EmptyState icon="🔗" message="No certificate SAN association records discovered." />;
  }

  return (
    <div>
      <div style={{ marginBottom: 12, fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-secondary)' }}>
        Discovered {associatedSans.length} associated target domains and sibling infrastructure registered under common certificates.
      </div>
      <div style={{
        display: 'flex', flexWrap: 'wrap', gap: 8, marginTop: 12,
      }}>
        {associatedSans.map((san, i) => (
          <div key={i} style={{
            fontFamily: 'var(--font-mono)', fontSize: 11,
            padding: '5px 12px', borderRadius: 20,
            background: 'rgba(0,242,254,0.08)',
            border: '1px solid rgba(0,242,254,0.2)',
            color: 'var(--accent-blue)',
          }}>
            {san}
          </div>
        ))}
      </div>
    </div>
  );
};

/* ───────────────────────────  MAIN COMPONENT  ─────────────────── */

const TABS = [
  { id: 'dns',      label: 'DNS Records',     icon: '📡' },
  { id: 'ports',    label: 'Port Scanner',     icon: '🔌' },
  { id: 'subs',     label: 'Subdomain Map',    icon: '🗺️' },
  { id: 'tech',     label: 'Tech Stack',       icon: '⚙️' },
  { id: 'info',     label: 'SSL & Domain',     icon: '🔒' },
  { id: 'phishing', label: 'Phishing Monitor', icon: '🪞' },
  { id: 'associated', label: 'Associated SAN', icon: '🔗' },
];

const NetworkMapPage = () => {
  /* ── state ── */
  const [domain, setDomain]             = useState('');
  const [activeDomain, setActiveDomain] = useState('');
  const [data, setData]                 = useState(null);
  const [loading, setLoading]           = useState(false);
  const [error, setError]               = useState('');
  const [activeTab, setActiveTab]       = useState('dns');
  const [recentScans, setRecentScans]   = useState([]);
  const [scanAnim, setScanAnim]         = useState(false);

  /* ── fetch recent scans on mount ── */
  useEffect(() => {
    (async () => {
      try {
        const res = await fetch(getApiUrl('/api/recent-scans'));
        if (res.ok) {
          const json = await res.json();
          // might be array of strings or array of objects with .domain
          const list = Array.isArray(json) ? json : (json.scans || json.domains || json.results || []);
          const domains = list.map(item => typeof item === 'string' ? item : (item.domain || item.target || '')).filter(Boolean);
          // dedupe
          setRecentScans([...new Set(domains)].slice(0, 12));
        }
      } catch (_) { /* silent */ }
    })();
  }, []);

  /* ── fetch network map data ── */
  const fetchData = async (targetDomain) => {
    const clean = targetDomain.trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    if (!clean) return;
    setLoading(true);
    setError('');
    setData(null);
    setActiveDomain(clean);
    setScanAnim(true);
    try {
      const res = await fetch(getApiUrl('/api/network-map/' + encodeURIComponent(clean)));
      if (!res.ok) throw new Error(`Server returned ${res.status}`);
      const json = await res.json();
      setData(json);
      if (!json.has_data) {
        setError('No network data available. Run a scan first.');
      }
    } catch (e) {
      setError(e.message || 'Failed to fetch network data.');
    } finally {
      setLoading(false);
      setTimeout(() => setScanAnim(false), 2200);
    }
  };

  const handleScan = () => fetchData(domain);
  const handleKeyDown = (e) => { if (e.key === 'Enter') handleScan(); };

  /* ── derived stats ── */
  const stats = data && data.has_data ? {
    dnsCount:   data.dns_records  ? Object.values(data.dns_records).flat().length : 0,
    portCount:  data.ports        ? data.ports.length : 0,
    subCount:   data.subdomains   ? data.subdomains.length : 0,
    techCount:  data.technologies ? Object.keys(data.technologies).length : 0,
    sslIssues:  data.ssl_info?.issues?.length || 0,
  } : null;

  /* ── render ── */
  return (
    <div className="animate-fade-in" style={{ padding: '0 4px' }}>
      <ScanLineOverlay active={scanAnim} />

      {/* ── HEADER ── */}
      <div style={{ marginBottom: 28 }}>
        <h1 className="text-gradient" style={{
          fontFamily: 'var(--font-cyber)', fontSize: 28, margin: 0, letterSpacing: 2,
        }}>
          🛰️ NETWORK MAP
        </h1>
        <p style={{ fontFamily: 'var(--font-mono)', fontSize: 13, color: 'var(--text-secondary)', margin: '6px 0 0' }}>
          Real-time infrastructure reconnaissance & attack surface visualization
        </p>
      </div>

      {/* ── SEARCH BAR ── */}
      <div className="glass-panel" style={{
        padding: 20, borderRadius: 14, marginBottom: 20,
      }}>
        <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
          <div style={{ position: 'relative', flex: 1, minWidth: 260 }}>
            <input
              className="input-glass"
              type="text"
              placeholder="Enter domain (e.g. example.com)"
              value={domain}
              onChange={e => setDomain(e.target.value)}
              onKeyDown={handleKeyDown}
              style={{
                width: '100%', padding: '12px 16px 12px 40px',
                fontFamily: 'var(--font-mono)', fontSize: 14,
                boxSizing: 'border-box',
              }}
            />
            <span style={{ position: 'absolute', left: 14, top: '50%', transform: 'translateY(-50%)', fontSize: 16, pointerEvents: 'none' }}>🔍</span>
          </div>
          <button
            className="btn-primary"
            onClick={handleScan}
            disabled={loading || !domain.trim()}
            style={{
              fontFamily: 'var(--font-cyber)', letterSpacing: 2, padding: '12px 28px',
              fontSize: 13, whiteSpace: 'nowrap', display: 'flex', alignItems: 'center', gap: 8,
            }}
          >
            {loading ? (
              <>
                <span style={{ display: 'inline-block', animation: 'spin 1s linear infinite', fontSize: 16 }}>⟳</span>
                SCANNING...
              </>
            ) : (
              <>🛰️ SCAN NETWORK</>
            )}
          </button>
        </div>
        <style>{`@keyframes spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}`}</style>

        {/* Recent scans quick-select */}
        {recentScans.length > 0 && (
          <div style={{ marginTop: 14, display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'center' }}>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-secondary)', marginRight: 4 }}>Recent:</span>
            {recentScans.map((d, i) => (
              <button
                key={i}
                className="btn-outline"
                onClick={() => { setDomain(d); fetchData(d); }}
                style={{
                  fontFamily: 'var(--font-mono)', fontSize: 11,
                  padding: '4px 12px', borderRadius: 20,
                }}
              >
                {d}
              </button>
            ))}
          </div>
        )}
      </div>

      {/* ── ERROR ── */}
      {error && !loading && (
        <div className="glass-panel" style={{
          padding: 24, borderRadius: 14, marginBottom: 20, textAlign: 'center',
          border: '1px solid rgba(255,0,85,0.25)',
        }}>
          <div style={{ fontSize: 40, marginBottom: 10 }}>📡</div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 14, color: 'var(--accent-red)' }}>{error}</div>
        </div>
      )}

      {/* ── LOADING ── */}
      {loading && (
        <div className="glass-panel" style={{
          padding: 60, borderRadius: 14, marginBottom: 20, textAlign: 'center',
        }}>
          <div style={{ fontSize: 52, marginBottom: 16, animation: 'pulse 1.5s ease-in-out infinite' }}>🛰️</div>
          <div style={{ fontFamily: 'var(--font-cyber)', fontSize: 16, color: 'var(--accent-blue)', letterSpacing: 3, marginBottom: 8 }}>
            SCANNING NETWORK
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-secondary)' }}>
            Mapping infrastructure for <span style={{ color: 'var(--accent-green)' }}>{activeDomain}</span>
          </div>
          {/* animated progress bar */}
          <div style={{
            margin: '20px auto 0', maxWidth: 400, height: 3, borderRadius: 3,
            background: 'rgba(0,242,254,0.1)', overflow: 'hidden',
          }}>
            <div style={{
              height: '100%', width: '40%', borderRadius: 3,
              background: 'linear-gradient(90deg, var(--accent-blue), var(--accent-purple))',
              animation: 'loadSlide 1.2s ease-in-out infinite',
            }} />
          </div>
          <style>{`
            @keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}
            @keyframes loadSlide{0%{transform:translateX(-100%)}100%{transform:translateX(350%)}}
          `}</style>
        </div>
      )}

      {/* ── DATA DISPLAY ── */}
      {data && data.has_data && !loading && (
        <div className="animate-fade-in">
          {/* Stats ribbon */}
          {stats && (
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
              gap: 12, marginBottom: 20,
            }}>
              {[
                { label: 'DNS Records',   value: stats.dnsCount,  icon: '📡', color: 'var(--accent-blue)' },
                { label: 'Open Ports',     value: stats.portCount, icon: '🔌', color: 'var(--accent-green)' },
                { label: 'Subdomains',     value: stats.subCount,  icon: '🗺️', color: 'var(--accent-purple)' },
                { label: 'Technologies',   value: stats.techCount, icon: '⚙️', color: 'var(--accent-orange)' },
                { label: 'SSL Issues',     value: stats.sslIssues, icon: '🔒', color: stats.sslIssues > 0 ? 'var(--accent-red)' : 'var(--accent-green)' },
              ].map((s, i) => (
                <div key={i} className="glass-panel" style={{
                  padding: '16px 18px', borderRadius: 12, textAlign: 'center',
                  borderTop: `2px solid ${s.color}`,
                }}>
                  <div style={{ fontSize: 22, marginBottom: 4 }}>{s.icon}</div>
                  <div style={{ fontFamily: 'var(--font-cyber)', fontSize: 22, color: s.color, letterSpacing: 1 }}>{s.value}</div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: 1, marginTop: 2 }}>{s.label}</div>
                </div>
              ))}
            </div>
          )}

          {/* Tabs */}
          <div style={{
            display: 'flex', gap: 6, marginBottom: 20, flexWrap: 'wrap',
            borderBottom: '1px solid var(--panel-border)', paddingBottom: 6,
          }}>
            {TABS.map(tab => (
              <button
                key={tab.id}
                className={`btn-outline${activeTab === tab.id ? ' active' : ''}`}
                onClick={() => setActiveTab(tab.id)}
                style={{
                  fontFamily: 'var(--font-mono)', fontSize: 12, padding: '8px 18px',
                  borderRadius: 8, display: 'flex', alignItems: 'center', gap: 6,
                }}
              >
                <span>{tab.icon}</span> {tab.label}
              </button>
            ))}
          </div>

          {/* Active domain banner */}
          <div style={{
            fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-secondary)',
            marginBottom: 16, display: 'flex', alignItems: 'center', gap: 8,
          }}>
            <span className="status-indicator active" />
            Target: <span style={{ color: 'var(--accent-green)' }}>{activeDomain}</span>
          </div>

          {/* Tab content */}
          <div className="glass-panel animate-fade-in" style={{ padding: 24, borderRadius: 14, minHeight: 200 }}>
            <div style={{
              fontFamily: 'var(--font-cyber)', fontSize: 16, letterSpacing: 2,
              color: 'var(--text-primary)', marginBottom: 20,
              display: 'flex', alignItems: 'center', gap: 10,
            }}>
              <span>{TABS.find(t => t.id === activeTab)?.icon}</span>
              {TABS.find(t => t.id === activeTab)?.label.toUpperCase()}
            </div>

            {activeTab === 'dns'   && <DnsSection dns={data.dns_records} />}
            {activeTab === 'ports' && <PortSection ports={data.ports} />}
            {activeTab === 'subs'  && <SubdomainSection subdomains={data.subdomains} takeoverData={data.subdomain_takeover} />}
            {activeTab === 'tech'  && <TechSection technologies={data.technologies} />}
            {activeTab === 'info'  && <InfoSection domainInfo={data.domain_info} sslInfo={data.ssl_info} />}
            {activeTab === 'phishing' && <PhishingSection phishingDomains={data.phishing_domains} />}
            {activeTab === 'associated' && <AssociatedSection associatedSans={data.associated_sans} />}
          </div>
        </div>
      )}

      {/* ── INITIAL EMPTY STATE ── */}
      {!data && !loading && !error && (
        <div className="glass-panel" style={{
          padding: 60, borderRadius: 14, textAlign: 'center',
        }}>
          <div style={{ fontSize: 64, marginBottom: 16, opacity: 0.7 }}>🛰️</div>
          <div style={{ fontFamily: 'var(--font-cyber)', fontSize: 18, color: 'var(--text-primary)', letterSpacing: 3, marginBottom: 8 }}>
            NETWORK MAPPER
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 13, color: 'var(--text-secondary)', maxWidth: 500, margin: '0 auto' }}>
            Enter a domain above to map its infrastructure — DNS records, open ports, subdomains, technology stack, and SSL configuration.
          </div>
          {/* decorative grid */}
          <svg viewBox="0 0 400 120" style={{ width: '100%', maxWidth: 400, marginTop: 24, opacity: 0.3 }}>
            {Array.from({ length: 8 }).map((_, i) => {
              const x = 30 + (i % 4) * 100;
              const y = 20 + Math.floor(i / 4) * 70;
              return (
                <g key={i}>
                  <circle cx={x} cy={y} r={4} fill="none" stroke="var(--accent-blue)" strokeWidth={1} opacity={0.6}>
                    <animate attributeName="r" values="3;5;3" dur={`${2 + i * 0.3}s`} repeatCount="indefinite" />
                  </circle>
                  {i > 0 && (
                    <line
                      x1={30 + ((i - 1) % 4) * 100} y1={20 + Math.floor((i - 1) / 4) * 70}
                      x2={x} y2={y}
                      stroke="var(--accent-blue)" strokeWidth={0.5} opacity={0.3}
                    />
                  )}
                </g>
              );
            })}
          </svg>
        </div>
      )}
    </div>
  );
};

export default NetworkMapPage;
