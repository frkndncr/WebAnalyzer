import React, { useState, useEffect, Component } from 'react';
import EducationModal from './EducationModal';
import InteractiveJson from './InteractiveJson';
import { getApiUrl } from '../config';

/* ── Universal Score Extractor ──
 * Handles all backend score formats:
 *   - integer: 68
 *   - string: "50/100"
 *   - object: {Score: "50/100", Percentage: "50.0%", Grade: "D"}
 *   - object: {overall_score: 77, grade: "C", ...}
 */
const extractScore = (raw) => {
  if (raw == null) return { score: null, grade: null };
  if (typeof raw === 'number') return { score: raw, grade: null };
  if (typeof raw === 'string') {
    const m = raw.match(/(\d+)/); 
    return { score: m ? parseInt(m[1], 10) : null, grade: null };
  }
  if (typeof raw === 'object') {
    let s = raw.overall_score ?? raw.score ?? raw.Score ?? null;
    if (typeof s === 'string') { const m2 = s.match(/(\d+)/); s = m2 ? parseInt(m2[1], 10) : null; }
    const g = raw.grade ?? raw.Grade ?? raw.security_grade ?? null;
    return { score: s, grade: g };
  }
  return { score: null, grade: null };
};

/* ── Safe Text Renderer ──
 * Prevents React crash when an object is accidentally rendered as a child.
 * Converts any non-primitive to a readable string.
 */
const safeText = (val) => {
  if (val == null) return '';
  if (typeof val === 'string' || typeof val === 'number' || typeof val === 'boolean') return String(val);
  if (typeof val === 'object') {
    // Try common display-friendly fields first
    if (val.provider) return String(val.provider);
    if (val.status) return String(val.status);
    if (val.name) return String(val.name);
    if (val.Score) return String(val.Score);
    if (val.value) return String(val.value);
    return JSON.stringify(val);
  }
  return String(val);
};

// Specialized Markdown/Highlight parser for making vulnerabilities bold
const HighlightVuln = ({ text }) => {
  if (typeof text !== 'string') return <span>{JSON.stringify(text)}</span>;

  const vulnKeywords = [
    'vulnerability', 'vulnerabilities', 'xss', 'sqli', 'ssrf', 'csrf', 
    'cve-', 'critical', 'high', 'exposure', 'exposed', 'disclosure',
    'leak', 'crlf', 'rce', 'ssti', 'misconfiguration', 'missing'
  ];

  const regex = new RegExp(`(${vulnKeywords.join('|')})`, 'gi');
  
  const parts = text.split(regex);
  return (
    <span>
      {parts.map((part, i) => {
        if (regex.test(part)) {
          return <span key={i} className="vuln-highlight">{part}</span>;
        }
        return <span key={i}>{part}</span>;
      })}
    </span>
  );
};

/* ── CVSS-style Score Badge ── */
const CVSSBadge = ({ severity }) => {
  const sev = (severity || 'medium').toLowerCase();
  const scoreMap = { critical: 9.5, high: 7.5, medium: 5.0, low: 2.5, info: 0.5 };
  const colorMap = {
    critical: 'var(--accent-red)',
    high: 'var(--accent-orange)',
    medium: 'var(--accent-blue)',
    low: 'var(--text-secondary)',
    info: 'var(--accent-green)',
  };
  const score = scoreMap[sev] || 5.0;
  const color = colorMap[sev] || 'var(--accent-blue)';

  return (
    <div style={{
      display: 'flex',
      alignItems: 'center',
      gap: '6px',
    }}>
      <div style={{
        width: '40px',
        height: '40px',
        borderRadius: '50%',
        border: `2px solid ${color}`,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        fontFamily: 'var(--font-mono)',
        fontSize: '0.85rem',
        fontWeight: 700,
        color: color,
        background: `${color}15`,
        flexShrink: 0,
      }}>
        {score.toFixed(1)}
      </div>
      <span className={`severity-${sev}`} style={{
        textTransform: 'uppercase',
        fontSize: '0.7rem',
        padding: '0.15rem 0.45rem',
        background: 'var(--panel-bg)',
        borderRadius: '4px',
        fontFamily: 'var(--font-cyber)',
        letterSpacing: '0.5px',
      }}>
        {severity || 'Medium'}
      </span>
    </div>
  );
};

const VulnerabilityCard = ({ finding }) => {
  const severityClass = finding.severity?.toLowerCase() || 'medium';
  const [copied, setCopied] = useState(false);

  const copyToClipboard = () => {
    const text = JSON.stringify(finding, null, 2);
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }).catch(() => {});
  };

  return (
    <div className="glass-panel" style={{
      padding: '1.5rem',
      marginBottom: '1rem',
      borderLeft: `4px solid var(--accent-${severityClass === 'critical' || severityClass === 'high' ? 'red' : severityClass === 'medium' ? 'blue' : 'orange'})`,
      transition: 'all 0.2s ease',
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flex: 1 }}>
          <CVSSBadge severity={finding.severity || finding.confidence} />
          <h3 style={{ margin: 0, fontSize: '1.05rem', flex: 1 }}>
            <HighlightVuln text={finding.type || finding.title || 'Vulnerability Finding'} />
          </h3>
        </div>
        <button
          onClick={copyToClipboard}
          style={{
            background: copied ? 'rgba(57, 255, 20, 0.15)' : 'rgba(255,255,255,0.05)',
            border: copied ? '1px solid var(--accent-green)' : '1px solid var(--panel-border)',
            color: copied ? 'var(--accent-green)' : 'var(--text-secondary)',
            padding: '0.3rem 0.6rem',
            borderRadius: '4px',
            cursor: 'pointer',
            fontSize: '0.75rem',
            fontFamily: 'var(--font-mono)',
            transition: 'all 0.2s ease',
            flexShrink: 0,
          }}
          title="Copy finding to clipboard"
        >
          {copied ? '✓ Copied' : '📋 Copy'}
        </button>
      </div>
      
      {finding.description && (
        <p style={{ color: 'var(--text-secondary)', marginBottom: '0.8rem', fontSize: '0.95rem' }}>
          <HighlightVuln text={finding.description} />
        </p>
      )}
      
      {finding.recommendation && (
        <div style={{ padding: '0.8rem', background: 'rgba(63, 185, 80, 0.1)', borderRadius: '6px', border: '1px solid rgba(63, 185, 80, 0.2)' }}>
          <strong style={{ color: 'var(--accent-green)', display: 'block', fontSize: '0.8rem', marginBottom: '0.3rem', textTransform: 'uppercase' }}>Recommendation</strong>
          <span style={{ fontSize: '0.9rem', color: '#e6edf3' }}>{finding.recommendation}</span>
        </div>
      )}

      {Object.keys(finding).filter(k => !['type', 'title', 'severity', 'description', 'recommendation', 'confidence'].includes(k)).length > 0 && (
        <details style={{ marginTop: '1rem' }}>
          <summary style={{ cursor: 'pointer', color: 'var(--accent-blue)', fontSize: '0.85rem' }}>View Technical Details</summary>
          <div className="json-view" style={{ marginTop: '0.5rem' }}>
            <InteractiveJson data={Object.fromEntries(Object.entries(finding).filter(([k]) => !['type', 'title', 'severity', 'description', 'recommendation', 'confidence'].includes(k)))} />
          </div>
        </details>
      )}
    </div>
  );
};

/* ── Severity Breakdown Bar ── */
const SeverityBar = ({ results, activeFilter, onSelectSeverity }) => {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

  if (results) {
    Object.values(results).forEach(moduleData => {
      const vulns = Array.isArray(moduleData)
        ? moduleData
        : Array.isArray(moduleData?.vulnerabilities)
          ? moduleData.vulnerabilities
          : Array.isArray(moduleData?.vulnerable_subdomains)
            ? moduleData.vulnerable_subdomains
            : [];
      vulns.forEach(v => {
        if (typeof v === 'object' && v) {
          const sev = (v.severity || v.confidence || 'medium').toLowerCase();
          if (sev in counts) counts[sev]++;
          else counts['info']++;
        }
      });
    });
  }

  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  if (total === 0) return null;

  const segments = [
    { key: 'critical', color: 'var(--accent-red)', label: 'Critical' },
    { key: 'high', color: 'var(--accent-orange)', label: 'High' },
    { key: 'medium', color: 'var(--accent-blue)', label: 'Medium' },
    { key: 'low', color: 'var(--text-secondary)', label: 'Low' },
    { key: 'info', color: 'var(--accent-green)', label: 'Info' },
  ];

  return (
    <div className="glass-panel" style={{ 
      padding: '1.2rem 1.5rem', 
      marginBottom: '1.5rem', 
      borderLeft: activeFilter && ['critical', 'high', 'medium', 'low', 'info'].includes(activeFilter) 
        ? `4px solid var(--accent-${activeFilter === 'low' ? 'gray' : activeFilter === 'critical' ? 'red' : activeFilter === 'high' ? 'orange' : activeFilter === 'medium' ? 'blue' : 'green'})` 
        : '1px solid var(--panel-border)' 
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.6rem' }}>
        <span style={{ fontSize: '0.8rem', fontFamily: 'var(--font-cyber)', textTransform: 'uppercase', letterSpacing: '1px', color: 'var(--text-secondary)' }}>
          Severity Filter (Click to Filter)
        </span>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: '8px' }}>
          {activeFilter !== 'all' && (
            <button 
              className="btn-outline" 
              onClick={() => onSelectSeverity('all')}
              style={{ padding: '2px 8px', fontSize: '10px', borderRadius: '4px', cursor: 'pointer' }}
            >
              Clear Filter
            </button>
          )}
          <span>{total} finding{total !== 1 ? 's' : ''}</span>
        </span>
      </div>
      <div style={{ display: 'flex', height: '10px', borderRadius: '5px', overflow: 'hidden', marginBottom: '0.8rem', background: 'rgba(255,255,255,0.05)', cursor: 'pointer' }}>
        {segments.map(seg => {
          const pct = total > 0 ? (counts[seg.key] / total) * 100 : 0;
          const isSelected = activeFilter === seg.key;
          return pct > 0 ? (
            <div 
              key={seg.key} 
              onClick={() => onSelectSeverity(seg.key)}
              title={`Filter by ${seg.label} (${counts[seg.key]} findings)`}
              style={{ 
                width: `${pct}%`, 
                background: seg.color, 
                transition: 'all 0.3s ease',
                opacity: activeFilter === 'all' || isSelected ? 1 : 0.35,
                transform: isSelected ? 'scaleY(1.3)' : 'none',
                position: 'relative'
              }} 
            />
          ) : null;
        })}
      </div>
      <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
        {segments.map(seg => {
          if (counts[seg.key] === 0) return null;
          const isSelected = activeFilter === seg.key;
          return (
            <div 
              key={seg.key} 
              onClick={() => onSelectSeverity(isSelected ? 'all' : seg.key)}
              style={{ 
                display: 'flex', 
                alignItems: 'center', 
                gap: '6px', 
                fontSize: '0.75rem',
                cursor: 'pointer',
                padding: '4px 8px',
                borderRadius: '4px',
                background: isSelected ? 'rgba(255,255,255,0.05)' : 'transparent',
                border: isSelected ? `1px solid ${seg.color}` : '1px solid transparent',
                transition: 'all 0.2s ease',
                opacity: activeFilter === 'all' || isSelected ? 1 : 0.5
              }}
            >
              <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: seg.color }} />
              <span style={{ color: isSelected ? 'var(--text-primary)' : 'var(--text-secondary)', fontWeight: isSelected ? 'bold' : 'normal' }}>{seg.label}</span>
              <span style={{ fontFamily: 'var(--font-mono)', color: seg.color, fontWeight: 'bold' }}>{counts[seg.key]}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
};

/* ── Category Helpers ── */
const categorizeModule = (moduleName, moduleData) => {
  const categories = [];
  if (moduleData && typeof moduleData === 'object') {
    if (moduleData.error) {
      categories.push('errors');
    }
    if (moduleData.vulnerabilities || moduleData.vulnerable_subdomains || moduleData.security_issues ||
      (Array.isArray(moduleData) && moduleData.some(v => v && v.severity))) {
      categories.push('vulnerabilities');
    }
  }
  if (categories.length === 0) categories.push('information');
  return categories;
};

const DNS_ICONS = { A: '🌐', AAAA: '🔗', MX: '📧', NS: '🏷️', TXT: '📝', CNAME: '🔀', SOA: '📋', SRV: '🔌', PTR: '↩️', CAA: '🔒' };

const RenderDnsRecords = ({ data }) => {
  const records = data.records || {};
  const responseTime = data.response_time_ms;
  const audit = data.security_audit;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
        {responseTime != null && (
          <div className="glass-panel" style={{ padding: '8px 16px', borderRadius: '8px', fontSize: '0.85rem', fontFamily: 'var(--font-mono)' }}>
            ⚡ Response Time: <span style={{ color: 'var(--accent-blue)', fontWeight: 'bold' }}>{responseTime} ms</span>
          </div>
        )}
        {audit && audit.score != null && (
          <div className="glass-panel" style={{ padding: '8px 16px', borderRadius: '8px', fontSize: '0.85rem', fontFamily: 'var(--font-cyber)', display: 'flex', alignItems: 'center', gap: '8px' }}>
            🛡️ Security Grade: 
            <span style={{ 
              color: audit.score >= 80 ? 'var(--accent-green)' : audit.score >= 60 ? 'var(--accent-orange)' : 'var(--accent-red)',
              fontWeight: 'bold',
              background: 'rgba(255,255,255,0.05)',
              padding: '2px 8px',
              borderRadius: '4px'
            }}>
              {safeText(audit.grade) || 'N/A'} ({safeText(audit.score)}/100)
            </span>
          </div>
        )}
      </div>

      {audit && (
        <div className="glass-panel" style={{ padding: '1.25rem', borderRadius: '12px', borderLeft: '4px solid var(--accent-blue)' }}>
          <h4 style={{ margin: '0 0 1rem', fontSize: '0.9rem', fontFamily: 'var(--font-cyber)', letterSpacing: '0.5px' }}>🛡️ DNS SECURITY POLICY AUDIT</h4>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1rem', marginBottom: '1rem' }}>
            {audit.spf && (
              <div style={{ padding: '10px', background: 'rgba(255,255,255,0.02)', borderRadius: '6px', border: '1px solid var(--panel-border)' }}>
                <strong style={{ display: 'block', fontSize: '0.7rem', color: 'var(--text-secondary)', marginBottom: '4px' }}>SPF RECORD</strong>
                <span style={{ fontSize: '0.85rem', color: audit.spf.status === 'Found' ? 'var(--accent-green)' : 'var(--accent-red)' }}>
                  ● {audit.spf.status}
                </span>
                {audit.spf.record && <div style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', wordBreak: 'break-all', marginTop: '6px', opacity: 0.8, color: 'var(--text-secondary)' }}>{safeText(audit.spf.record)}</div>}
              </div>
            )}
            {audit.dmarc && (
              <div style={{ padding: '10px', background: 'rgba(255,255,255,0.02)', borderRadius: '6px', border: '1px solid var(--panel-border)' }}>
                <strong style={{ display: 'block', fontSize: '0.7rem', color: 'var(--text-secondary)', marginBottom: '4px' }}>DMARC POLICY</strong>
                <span style={{ fontSize: '0.85rem', color: audit.dmarc.status === 'Found' ? 'var(--accent-green)' : 'var(--accent-red)' }}>
                  ● {audit.dmarc.status}
                </span>
                {audit.dmarc.record && <div style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', wordBreak: 'break-all', marginTop: '6px', opacity: 0.8, color: 'var(--text-secondary)' }}>{safeText(audit.dmarc.record)}</div>}
              </div>
            )}
            {audit.dnssec && (
              <div style={{ padding: '10px', background: 'rgba(255,255,255,0.02)', borderRadius: '6px', border: '1px solid var(--panel-border)' }}>
                <strong style={{ display: 'block', fontSize: '0.7rem', color: 'var(--text-secondary)', marginBottom: '4px' }}>DNSSEC STATUS</strong>
                <span style={{ fontSize: '0.85rem', color: audit.dnssec.enabled ? 'var(--accent-green)' : 'var(--text-secondary)' }}>
                  {audit.dnssec.enabled ? '🟢 Enabled' : '⚪ Disabled'}
                </span>
              </div>
            )}
            {audit.caa && (
              <div style={{ padding: '10px', background: 'rgba(255,255,255,0.02)', borderRadius: '6px', border: '1px solid var(--panel-border)' }}>
                <strong style={{ display: 'block', fontSize: '0.7rem', color: 'var(--text-secondary)', marginBottom: '4px' }}>CAA POLICY</strong>
                <span style={{ fontSize: '0.85rem', color: audit.caa.status === 'Found' ? 'var(--accent-green)' : 'var(--text-secondary)' }}>
                  {audit.caa.status === 'Found' ? '🟢 Found' : '⚪ Missing'}
                </span>
              </div>
            )}
          </div>
          {audit.weaknesses && audit.weaknesses.length > 0 && (
            <div style={{ borderTop: '1px solid var(--panel-border)', paddingTop: '0.75rem' }}>
              <div style={{ fontSize: '0.8rem', color: 'var(--accent-orange)', fontWeight: 'bold', marginBottom: '6px' }}>⚠️ Weaknesses Detected:</div>
              <ul style={{ margin: 0, paddingLeft: '20px', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
                {audit.weaknesses.map((w, idx) => <li key={idx}>{w}</li>)}
              </ul>
            </div>
          )}
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '1rem' }}>
        {Object.entries(records).map(([key, list]) => {
          const vals = Array.isArray(list) ? list : [list];
          const typeKey = key.split(' ')[0];
          const icon = DNS_ICONS[typeKey] || '📄';
          return (
            <div key={key} className="glass-panel" style={{ padding: '1rem', borderRadius: '10px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px', borderBottom: '1px solid var(--panel-border)', paddingBottom: '4px' }}>
                <strong style={{ fontSize: '0.85rem', color: 'var(--text-primary)' }}>{icon} {key}</strong>
                <span className="badge badge-blue" style={{ fontSize: '10px' }}>{vals.length} record{vals.length !== 1 ? 's' : ''}</span>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                {vals.map((v, idx) => (
                  <div key={idx} style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--accent-green)', background: 'rgba(57,255,20,0.03)', padding: '4px 8px', borderRadius: '4px', wordBreak: 'break-all' }}>
                    {typeof v === 'object' ? JSON.stringify(v) : String(v)}
                  </div>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

const RenderDomainInfo = ({ data }) => {
  const { score: scoreVal, grade: gradeVal } = extractScore(data['Security Score']);
  
  const getIcon = (key) => {
    const k = key.toLowerCase();
    if (k.includes('ip')) return '🌐';
    if (k.includes('registrar')) return '🏢';
    if (k.includes('date') || k.includes('expiry') || k.includes('created') || k.includes('updated')) return '📅';
    if (k.includes('status')) return '🚦';
    if (k.includes('whois')) return '🔍';
    if (k.includes('name server') || k.includes('ns')) return '🏷️';
    if (k.includes('ssl')) return '🔒';
    return '📄';
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
        {scoreVal != null && (
          <div className="glass-panel" style={{ padding: '12px 20px', borderRadius: '8px', display: 'flex', alignItems: 'center', gap: '8px', borderLeft: '4px solid var(--accent-green)' }}>
            <span style={{ fontSize: '0.95rem' }}>🛡️ Domain Security:</span>
            <span style={{ fontWeight: 'bold', fontSize: '1.1rem', color: scoreVal >= 75 ? 'var(--accent-green)' : 'var(--accent-orange)' }}>
              {gradeVal ? `${gradeVal} (${scoreVal}/100)` : `${scoreVal}/100`}
            </span>
          </div>
        )}
        {data['HTTP Status'] && (
          <div className="glass-panel" style={{ padding: '12px 20px', borderRadius: '8px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span>🚦 Status: </span>
            <span style={{ color: String(data['HTTP Status']).startsWith('2') ? 'var(--accent-green)' : 'var(--accent-orange)', fontWeight: 'bold' }}>
              {data['HTTP Status']}
            </span>
          </div>
        )}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem' }}>
        {Object.entries(data).map(([key, value]) => {
          if (value == null || value === '' || key === 'Security Score' || key === 'HTTP Status') return null;
          
          const icon = getIcon(key);
          
          return (
            <div key={key} className="glass-panel" style={{ padding: '1.2rem', borderRadius: '10px', display: 'flex', flexDirection: 'column', gap: '6px', border: '1px solid var(--panel-border)' }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', textTransform: 'uppercase', display: 'flex', alignItems: 'center', gap: '6px', fontWeight: '600', letterSpacing: '0.5px' }}>
                <span>{icon}</span> {key}
              </div>
              <div style={{ fontSize: '0.9rem', color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', wordBreak: 'break-all', marginTop: '4px' }}>
                {Array.isArray(value) ? (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                    {value.map((val, idx) => (
                      <div key={idx} style={{ background: 'rgba(255,255,255,0.02)', padding: '4px 8px', borderRadius: '4px', border: '1px solid var(--panel-border)', fontSize: '0.8rem' }}>
                        {typeof val === 'object' ? JSON.stringify(val) : String(val)}
                      </div>
                    ))}
                  </div>
                ) : typeof value === 'object' ? (
                  <details style={{ width: '100%' }}>
                    <summary style={{ cursor: 'pointer', color: 'var(--accent-blue)', userSelect: 'none', fontSize: '0.8rem' }}>Show {Object.keys(value).length} items</summary>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', marginTop: '6px', background: 'rgba(0,0,0,0.1)', padding: '6px', borderRadius: '6px' }}>
                      {Object.entries(value).map(([subK, subV]) => (
                        <div key={subK} style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,0.02)', padding: '4px 0', fontSize: '0.75rem' }}>
                          <span style={{ color: 'var(--text-secondary)' }}>{subK}:</span>
                          <span style={{ color: 'var(--text-primary)', textAlign: 'right' }}>{typeof subV === 'object' ? JSON.stringify(subV) : String(subV)}</span>
                        </div>
                      ))}
                    </div>
                  </details>
                ) : (
                  String(value)
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

/* ── Web Technologies Detail Renderers for Security Keys ── */
const RenderTechHeaders = ({ headers }) => {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '0.8rem', width: '100%' }}>
      {Object.entries(headers).map(([name, info]) => {
        const present = info.present === true || String(info.present).toLowerCase() === 'true';
        return (
          <div key={name} style={{ padding: '10px 14px', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', border: '1px solid var(--panel-border)', fontSize: '0.8rem', display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <span style={{ color: 'var(--text-secondary)', fontWeight: '500' }}>{name}</span>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '4px' }}>
              <span style={{ color: present ? 'var(--accent-green)' : 'var(--accent-red)', fontWeight: 'bold' }}>
                {present ? '✓ Present' : '✗ Missing'}
              </span>
              {info.value && info.value !== 'Not Set' && (
                <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', opacity: 0.8, color: 'var(--text-primary)', wordBreak: 'break-all' }}>{info.value}</span>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
};

const RenderTechVulns = ({ vulns }) => {
  const entries = Object.entries(vulns).filter(([_, list]) => Array.isArray(list) && list.length > 0);
  if (entries.length === 0) return <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>✓ No technology vulnerabilities detected.</div>;
  
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', width: '100%' }}>
      {entries.map(([cat, list]) => (
        <div key={cat}>
          <div style={{ fontSize: '0.75rem', color: 'var(--accent-orange)', fontWeight: 'bold', textTransform: 'uppercase', marginBottom: '6px', letterSpacing: '0.5px' }}>
            ⚠️ {cat.replace(/_/g, ' ')}
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
            {list.map((item, idx) => (
              <div key={idx} style={{ padding: '6px 10px', background: 'rgba(255, 85, 85, 0.03)', borderLeft: '3px solid var(--accent-red)', borderRadius: '0 4px 4px 0', fontSize: '0.8rem', color: 'var(--text-primary)' }}>
                {String(item)}
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
};

const RenderTechDisclosure = ({ disclosure }) => {
  const entries = Object.entries(disclosure).filter(([_, list]) => Array.isArray(list) && list.length > 0);
  if (entries.length === 0) return <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>✓ No sensitive information disclosure detected.</div>;
  
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', width: '100%' }}>
      {entries.map(([cat, list]) => (
        <div key={cat}>
          <div style={{ fontSize: '0.75rem', color: 'var(--accent-blue)', fontWeight: 'bold', textTransform: 'uppercase', marginBottom: '6px' }}>
            🔍 {cat.replace(/_/g, ' ')}
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
            {list.map((item, idx) => (
              <div key={idx} style={{ padding: '6px 10px', background: 'rgba(0, 242, 254, 0.03)', borderLeft: '3px solid var(--accent-blue)', borderRadius: '0 4px 4px 0', fontSize: '0.8rem' }}>
                {String(item)}
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
};

const RenderTechSSL = ({ ssl }) => {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '0.8rem', width: '100%' }}>
      {Object.entries(ssl).map(([key, val]) => {
        if (val == null || val === '' || typeof val === 'object') return null;
        const isStrong = String(val).toLowerCase() === 'strong' || String(val).toLowerCase() === 'excellent' || String(val).toLowerCase() === 'secure';
        return (
          <div key={key} style={{ padding: '8px 12px', background: 'rgba(255,255,255,0.02)', borderRadius: '6px', border: '1px solid var(--panel-border)', fontSize: '0.8rem', display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <span style={{ color: 'var(--text-secondary)', textTransform: 'capitalize' }}>{key.replace(/_/g, ' ')}</span>
            <span style={{ 
              fontWeight: 'bold', 
              color: isStrong ? 'var(--accent-green)' : 'var(--text-primary)',
              fontFamily: 'var(--font-mono)'
            }}>
              {String(val)}
            </span>
          </div>
        );
      })}
    </div>
  );
};

const RenderTechServices = ({ services }) => {
  const entries = Object.entries(services).filter(([_, list]) => Array.isArray(list) && list.length > 0);
  if (entries.length === 0) return <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>No active third-party security services detected.</div>;
  
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '0.8rem', width: '100%' }}>
      {entries.map(([cat, list]) => (
        <div key={cat} style={{ padding: '10px', background: 'rgba(255,255,255,0.02)', borderRadius: '8px', border: '1px solid var(--panel-border)' }}>
          <strong style={{ display: 'block', fontSize: '0.75rem', color: 'var(--accent-purple)', textTransform: 'uppercase', marginBottom: '6px' }}>🛡️ {cat}</strong>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
            {list.map((item, idx) => (
              <span key={idx} className="badge badge-purple" style={{ fontSize: '0.8rem' }}>{String(item)}</span>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
};

const RenderTechCookies = ({ cookies }) => {
  if (!cookies) return null;
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '0.8rem', width: '100%' }}>
      {Object.entries(cookies).map(([key, val]) => {
        if (val == null || val === '') return null;
        if (Array.isArray(val)) {
          if (val.length === 0) return null;
          return (
            <div key={key} style={{ padding: '8px 12px', background: 'rgba(255,255,255,0.02)', borderRadius: '6px', border: '1px solid var(--panel-border)', fontSize: '0.8rem', gridColumn: '1 / -1' }}>
              <span style={{ color: 'var(--text-secondary)', textTransform: 'capitalize', display: 'block', marginBottom: '4px' }}>{key.replace(/_/g, ' ')}</span>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                {val.map((item, idx) => <div key={idx} style={{ fontSize: '0.75rem', color: 'var(--accent-orange)' }}>• {String(item)}</div>)}
              </div>
            </div>
          );
        }
        return (
          <div key={key} style={{ padding: '8px 12px', background: 'rgba(255,255,255,0.02)', borderRadius: '6px', border: '1px solid var(--panel-border)', fontSize: '0.8rem' }}>
            <span style={{ color: 'var(--text-secondary)', textTransform: 'capitalize', display: 'block', marginBottom: '2px' }}>{key.replace(/_/g, ' ')}</span>
            <span style={{ fontWeight: 'bold' }}>{String(val)}</span>
          </div>
        );
      })}
    </div>
  );
};

const RenderWebTech = ({ data }) => {
  const { score: scoreVal, grade: gradeVal } = extractScore(data['Security Score']);

  const getTechSectionContent = (key, val) => {
    if (!val || typeof val !== 'object') return null;
    
    switch (key) {
      case 'Security Headers':
        return <RenderTechHeaders headers={val} />;
      case 'Security Vulnerabilities':
        return <RenderTechVulns vulns={val} />;
      case 'Information Disclosure':
        return <RenderTechDisclosure disclosure={val} />;
      case 'SSL/TLS Security':
        return <RenderTechSSL ssl={val} />;
      case 'Security Services':
        return <RenderTechServices services={val} />;
      case 'Cookie Security':
        return <RenderTechCookies cookies={val} />;
      default:
        return null;
    }
  };

  const securityKeys = ['Security Headers', 'Security Vulnerabilities', 'Information Disclosure', 'SSL/TLS Security', 'Security Services', 'Cookie Security'];
  
  const standardTechs = Object.entries(data).filter(([key]) => key !== 'Security Score' && key !== 'Technology Security Analysis' && !securityKeys.includes(key));
  const securityTechs = Object.entries(data).filter(([key]) => securityKeys.includes(key));

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {scoreVal != null && (
        <div className="glass-panel" style={{ padding: '10px 16px', borderRadius: '8px', display: 'flex', alignItems: 'center', gap: '8px', width: 'fit-content' }}>
          <span>⚙️ Technology Grade:</span>
          <span style={{ fontWeight: 'bold', color: scoreVal >= 80 ? 'var(--accent-green)' : 'var(--accent-orange)' }}>{gradeVal ? `${gradeVal} (${scoreVal}/100)` : `${scoreVal}/100`}</span>
        </div>
      )}
      
      {/* Standard detected technologies */}
      <div>
        <h4 style={{ margin: '0 0 1rem 0', fontSize: '0.9rem', fontFamily: 'var(--font-cyber)' }}>⚙️ DETECTED WEB STACK</h4>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))', gap: '1rem' }}>
          {standardTechs.map(([key, val]) => {
            const vals = Array.isArray(val) ? val : [val];
            if (vals.length === 0 || vals[0] === 'Not Detected') return null;
            return (
              <div key={key} className="glass-panel" style={{ padding: '1rem', borderRadius: '10px' }}>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', textTransform: 'uppercase', marginBottom: '8px' }}>{key.replace(/_/g, ' ')}</div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                  {vals.map((v, i) => (
                    <span key={i} className="badge badge-blue" style={{ fontSize: '0.8rem', padding: '3px 8px' }}>
                      {String(v)}
                    </span>
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Security-related analysis of technologies */}
      {securityTechs.length > 0 && (
        <div>
          <h4 style={{ margin: '1rem 0 1rem 0', fontSize: '0.9rem', fontFamily: 'var(--font-cyber)', color: 'var(--accent-orange)' }}>🛡️ WEB TECH SECURITY ASSESSMENT</h4>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.2rem' }}>
            {securityTechs.map(([key, val]) => {
              const content = getTechSectionContent(key, val);
              if (!content) return null;
              return (
                <div key={key} className="glass-panel" style={{ padding: '1.25rem', borderRadius: '12px' }}>
                  <div style={{ fontSize: '0.85rem', color: 'var(--text-primary)', fontFamily: 'var(--font-cyber)', borderBottom: '1px solid var(--panel-border)', paddingBottom: '6px', marginBottom: '12px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                    {key}
                  </div>
                  {content}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};

const RenderSecurityAnalysis = ({ data, activeFilter }) => {
  const { score: scoreVal, grade: extractedGrade } = extractScore(data.security_score);
  const gradeVal = data.security_grade || extractedGrade;
  const allVulns = data.vulnerability_scan || data.vulnerabilities || [];
  const vulns = ['critical', 'high', 'medium', 'low', 'info'].includes(activeFilter)
    ? allVulns.filter(v => v && typeof v === 'object' && (v.severity || 'medium').toLowerCase() === activeFilter)
    : allVulns;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
        {scoreVal != null && (
          <div className="glass-panel" style={{ padding: '12px 20px', borderRadius: '8px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span>🛡️ SECURITY SCORE:</span>
            <span style={{ 
              fontWeight: 'bold', 
              fontSize: '1.2rem',
              color: scoreVal >= 80 ? 'var(--accent-green)' : scoreVal >= 60 ? 'var(--accent-orange)' : 'var(--accent-red)' 
            }}>
              {gradeVal ? `${gradeVal} (${scoreVal}/100)` : `${scoreVal}/100`}
            </span>
          </div>
        )}
        {data.waf_detection && (
          <div className="glass-panel" style={{ padding: '12px 20px', borderRadius: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span>WAF Protection: </span>
            <span className="badge badge-purple" style={{ fontSize: '0.85rem' }}>{safeText(data.waf_detection)}</span>
          </div>
        )}
      </div>

      {data.security_headers && (() => {
        let headersObj = data.security_headers;
        if (headersObj && headersObj.headers && typeof headersObj.headers === 'object') {
          headersObj = headersObj.headers;
        }
        return (
          <div className="glass-panel" style={{ padding: '1.25rem', borderRadius: '12px' }}>
            <h4 style={{ margin: '0 0 1rem', fontSize: '0.9rem', fontFamily: 'var(--font-cyber)' }}>HTTP SECURITY HEADERS</h4>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: '1rem' }}>
              {Object.entries(headersObj).map(([hdr, status]) => {
                let present = false;
                if (status && typeof status === 'object') {
                  present = status.present === true || String(status.present).toLowerCase() === 'true' || String(status.status || '').toLowerCase() === 'found' || String(status.present).toLowerCase() === 'present';
                } else {
                  present = String(status).toLowerCase().includes('found') || String(status).toLowerCase() === 'present' || String(status).toLowerCase() === 'ok' || String(status).toLowerCase().includes('configured');
                }
                return (
                  <div key={hdr} style={{ padding: '10px', background: 'rgba(255,255,255,0.02)', borderRadius: '6px', border: '1px solid var(--panel-border)', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', wordBreak: 'break-all' }}>{hdr}</span>
                    <span style={{ fontSize: '0.8rem', fontWeight: 'bold', color: present ? 'var(--accent-green)' : 'var(--accent-red)', marginTop: '4px' }}>
                      {present ? '✓ Set' : '✗ Missing'}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        );
      })()}

      {vulns.length > 0 && (
        <div>
          <h4 style={{ margin: '0 0 0.8rem', fontSize: '0.9rem', fontFamily: 'var(--font-cyber)', color: 'var(--accent-red)' }}>⚠️ DETECTED VULNERABILITIES ({vulns.length})</h4>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            {vulns.map((v, i) => (
              <div key={i} className="glass-panel" style={{ padding: '1rem', borderLeft: `4px solid var(--accent-${(v.severity || 'medium').toLowerCase() === 'high' || (v.severity || 'medium').toLowerCase() === 'critical' ? 'red' : 'blue'})` }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                  <strong style={{ fontSize: '0.95rem' }}>{v.type || v.title || 'Vulnerability'}</strong>
                  <span className={`badge severity-${(v.severity || 'medium').toLowerCase()}`}>{v.severity || 'Medium'}</span>
                </div>
                <p style={{ margin: '0 0 6px', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>{v.description || v.detail}</p>
                {v.recommendation && (
                  <div style={{ fontSize: '0.8rem', color: 'var(--accent-green)', background: 'rgba(57,255,20,0.03)', padding: '6px', borderRadius: '4px', marginTop: '6px' }}>
                    <strong>Remediation: </strong> {v.recommendation}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

const RenderAdvancedContentScan = ({ data, activeFilter }) => {
  const [showAllSecrets, setShowAllSecrets] = React.useState(false);
  const [showAllJs, setShowAllJs] = React.useState(false);
  const [showAllSsrf, setShowAllSsrf] = React.useState(false);
  const [showAllActive, setShowAllActive] = React.useState(false);
  const [showAllChains, setShowAllChains] = React.useState(false);

  const isSeverityFilter = ['critical', 'high', 'medium', 'low', 'info'].includes(activeFilter);
  
  const secrets = (data.secrets || []).filter(s => {
    if (!isSeverityFilter) return true;
    const sev = (s.severity || 'critical').toLowerCase();
    return sev === activeFilter;
  });
  
  const jsVulns = (data.js_vulnerabilities || []).filter(jv => {
    if (!isSeverityFilter) return true;
    const sev = (jv.severity || 'high').toLowerCase();
    return sev === activeFilter;
  });
  
  const ssrf = (data.ssrf_vulnerabilities || []).filter(sv => {
    if (!isSeverityFilter) return true;
    const sev = (sv.severity || 'high').toLowerCase();
    return sev === activeFilter;
  });
  
  const active = (data.active_vulnerabilities || []).filter(av => {
    if (!isSeverityFilter) return true;
    const sev = (av.severity || 'high').toLowerCase();
    return sev === activeFilter;
  });

  const chains = (data.exploit_chains || []).filter(c => {
    if (!isSeverityFilter) return true;
    const sev = (c.severity || 'critical').toLowerCase();
    return sev === activeFilter;
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
      {/* Secrets section */}
      {secrets.length > 0 && (() => {
        const visibleSecrets = showAllSecrets ? secrets : secrets.slice(0, 5);
        return (
          <div>
            <h4 style={{ margin: '0 0 0.75rem', fontSize: '0.9rem', fontFamily: 'var(--font-cyber)', color: 'var(--accent-red)' }}>🔑 LEAKED SECRETS & KEYS ({secrets.length})</h4>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              {visibleSecrets.map((s, idx) => (
                <div key={idx} className="glass-panel" style={{ padding: '1rem', borderLeft: '4px solid var(--accent-red)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                    <strong style={{ fontSize: '0.85rem', fontFamily: 'var(--font-mono)' }}>{s.type || 'Secret API Key'}</strong>
                    <span className="badge severity-critical" style={{ fontSize: '10px' }}>Conf: {s.confidence || 90}%</span>
                  </div>
                  <div style={{ fontSize: '0.8rem', background: 'rgba(0,0,0,0.2)', padding: '6px', borderRadius: '4px', fontFamily: 'var(--font-mono)', wordBreak: 'break-all', color: 'var(--accent-orange)' }}>
                    {s.value}
                  </div>
                  {s.source_url && (
                    <div style={{ fontSize: '0.75rem', marginTop: '6px', color: 'var(--text-secondary)' }}>
                      Source file: <span style={{ fontFamily: 'var(--font-mono)' }}>{s.source_url}</span>
                    </div>
                  )}
                </div>
              ))}
              {secrets.length > 5 && (
                <button 
                  className="btn-outline" 
                  onClick={() => setShowAllSecrets(!showAllSecrets)}
                  style={{ padding: '6px 12px', fontSize: '0.8rem', width: 'fit-content', marginTop: '4px', cursor: 'pointer' }}
                >
                  {showAllSecrets ? 'Show Less' : `Show More (+${secrets.length - 5})`}
                </button>
              )}
            </div>
          </div>
        );
      })()}

      {/* Javascript Vulnerabilities */}
      {jsVulns.length > 0 && (() => {
        const visibleJs = showAllJs ? jsVulns : jsVulns.slice(0, 5);
        return (
          <div>
            <h4 style={{ margin: '0 0 0.75rem', fontSize: '0.9rem', fontFamily: 'var(--font-cyber)', color: 'var(--accent-orange)' }}>⚙️ JAVASCRIPT VULNERABILITIES ({jsVulns.length})</h4>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              {visibleJs.map((jv, idx) => (
                <div key={idx} className="glass-panel" style={{ padding: '1rem', borderLeft: '4px solid var(--accent-orange)' }}>
                  <strong style={{ fontSize: '0.85rem', display: 'block', marginBottom: '4px' }}>{jv.type || 'JS Vulnerability'}</strong>
                  <p style={{ margin: '0 0 6px', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>{jv.description || jv.detail}</p>
                  <div style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', wordBreak: 'break-all', opacity: 0.8 }}>
                    File: {jv.source_url}
                  </div>
                </div>
              ))}
              {jsVulns.length > 5 && (
                <button 
                  className="btn-outline" 
                  onClick={() => setShowAllJs(!showAllJs)}
                  style={{ padding: '6px 12px', fontSize: '0.8rem', width: 'fit-content', marginTop: '4px', cursor: 'pointer' }}
                >
                  {showAllJs ? 'Show Less' : `Show More (+${jsVulns.length - 5})`}
                </button>
              )}
            </div>
          </div>
        );
      })()}

      {/* SSRF Vulnerabilities */}
      {ssrf.length > 0 && (() => {
        const visibleSsrf = showAllSsrf ? ssrf : ssrf.slice(0, 5);
        return (
          <div>
            <h4 style={{ margin: '0 0 0.75rem', fontSize: '0.9rem', fontFamily: 'var(--font-cyber)', color: 'var(--accent-orange)' }}>🌐 SSRF VULNERABILITIES ({ssrf.length})</h4>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              {visibleSsrf.map((s, idx) => (
                <div key={idx} className="glass-panel" style={{ padding: '1rem', borderLeft: '4px solid var(--accent-orange)' }}>
                  <strong style={{ fontSize: '0.85rem', display: 'block', marginBottom: '4px' }}>{s.type || 'SSRF Risk'}</strong>
                  <p style={{ margin: '0 0 6px', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>{s.description || s.detail}</p>
                  {s.url && <div style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', wordBreak: 'break-all' }}>URL: {s.url}</div>}
                </div>
              ))}
              {ssrf.length > 5 && (
                <button 
                  className="btn-outline" 
                  onClick={() => setShowAllSsrf(!showAllSsrf)}
                  style={{ padding: '6px 12px', fontSize: '0.8rem', width: 'fit-content', marginTop: '4px', cursor: 'pointer' }}
                >
                  {showAllSsrf ? 'Show Less' : `Show More (+${ssrf.length - 5})`}
                </button>
              )}
            </div>
          </div>
        );
      })()}

      {/* Active Vulnerabilities */}
      {active.length > 0 && (() => {
        const visibleActive = showAllActive ? active : active.slice(0, 5);
        return (
          <div>
            <h4 style={{ margin: '0 0 0.75rem', fontSize: '0.9rem', fontFamily: 'var(--font-cyber)', color: 'var(--accent-red)' }}>🔬 ACTIVE VULNERABILITIES ({active.length})</h4>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              {visibleActive.map((av, idx) => (
                <div key={idx} className="glass-panel" style={{ padding: '1rem', borderLeft: '4px solid var(--accent-red)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                    <strong style={{ fontSize: '0.85rem' }}>{av.type || av.title || 'Active Exploit Opportunity'}</strong>
                    <span className={`badge severity-${(av.severity || 'high').toLowerCase()}`}>{av.severity || 'High'}</span>
                  </div>
                  <p style={{ margin: '0 0 6px', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>{av.description || av.detail}</p>
                  {av.payload && <div style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', background: 'rgba(0,0,0,0.2)', padding: '4px 8px', borderRadius: '4px', wordBreak: 'break-all', color: 'var(--accent-orange)' }}>Payload: {av.payload}</div>}
                </div>
              ))}
              {active.length > 5 && (
                <button 
                  className="btn-outline" 
                  onClick={() => setShowAllActive(!showAllActive)}
                  style={{ padding: '6px 12px', fontSize: '0.8rem', width: 'fit-content', marginTop: '4px', cursor: 'pointer' }}
                >
                  {showAllActive ? 'Show Less' : `Show More (+${active.length - 5})`}
                </button>
              )}
            </div>
          </div>
        );
      })()}

      {/* Exploit Chains */}
      {chains.length > 0 && (() => {
        const visibleChains = showAllChains ? chains : chains.slice(0, 5);
        return (
          <div>
            <h4 style={{ margin: '0 0 0.75rem', fontSize: '0.9rem', fontFamily: 'var(--font-cyber)', color: 'var(--accent-red)' }}>🕸️ AUTOMATED EXPLOIT CHAINS MAPPED ({chains.length})</h4>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              {visibleChains.map((c, idx) => (
                <div key={idx} className="glass-panel" style={{ padding: '1rem', borderLeft: '4px solid var(--accent-red)' }}>
                  <strong style={{ fontSize: '0.9rem', color: 'var(--accent-red)', display: 'block', marginBottom: '6px' }}>Chain #{idx+1}: {c.name || 'Exploit Sequence'}</strong>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap', fontSize: '0.8rem', fontFamily: 'var(--font-mono)' }}>
                    {c.steps && c.steps.map((step, sidx) => (
                      <React.Fragment key={sidx}>
                        <span style={{ background: 'rgba(255,255,255,0.05)', padding: '4px 8px', borderRadius: '4px', border: '1px solid var(--panel-border)' }}>
                          {step}
                        </span>
                        {sidx < c.steps.length - 1 && <span style={{ color: 'var(--accent-red)' }}>➔</span>}
                      </React.Fragment>
                    ))}
                  </div>
                </div>
              ))}
              {chains.length > 5 && (
                <button 
                  className="btn-outline" 
                  onClick={() => setShowAllChains(!showAllChains)}
                  style={{ padding: '6px 12px', fontSize: '0.8rem', width: 'fit-content', marginTop: '4px', cursor: 'pointer' }}
                >
                  {showAllChains ? 'Show Less' : `Show More (+${chains.length - 5})`}
                </button>
              )}
            </div>
          </div>
        );
      })()}

      {secrets.length === 0 && jsVulns.length === 0 && ssrf.length === 0 && active.length === 0 && chains.length === 0 && (
        <div className="glass-panel" style={{ padding: '1.5rem', textAlign: 'center', color: 'var(--text-secondary)' }}>
          ✓ No critical code or content secrets exposed.
        </div>
      )}
    </div>
  );
};

const RenderContactSpy = ({ data }) => {
  const pageResults = data.page_results || [];
  
  const emails = [];
  const phones = [];
  const socials = [];
  
  if (Array.isArray(pageResults)) {
    pageResults.forEach(pr => {
      if (pr.emails) pr.emails.forEach(e => emails.push({ val: typeof e === 'object' ? (e.email || e.value || JSON.stringify(e)) : e, source: pr.url }));
      if (pr.phones) pr.phones.forEach(p => phones.push({ val: typeof p === 'object' ? (p.phone || p.value || JSON.stringify(p)) : p, source: pr.url }));
      if (pr.social_media) {
        if (Array.isArray(pr.social_media)) {
          // New format: array of {platform, username, url, found_on}
          pr.social_media.forEach(sm => {
            if (typeof sm === 'object' && sm) {
              socials.push({ platform: sm.platform || 'Unknown', val: sm.url || sm.value || '', source: sm.found_on || pr.url });
            } else {
              socials.push({ platform: 'Link', val: String(sm), source: pr.url });
            }
          });
        } else if (typeof pr.social_media === 'object') {
          // Old format: {platform: [urls]} or {platform: url}
          Object.entries(pr.social_media).forEach(([platform, urls]) => {
            const urlList = Array.isArray(urls) ? urls : [urls];
            urlList.forEach(u => socials.push({ platform, val: typeof u === 'object' ? (u.url || JSON.stringify(u)) : String(u), source: pr.url }));
          });
        }
      }
    });
  }

  const uniqEmails = Array.from(new Set(emails.map(e => e.val))).map(val => emails.find(e => e.val === val));
  const uniqPhones = Array.from(new Set(phones.map(p => p.val))).map(val => phones.find(p => p.val === val));
  const uniqSocials = Array.from(new Set(socials.map(s => s.val))).map(val => socials.find(s => s.val === val));

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '1rem' }}>
        <div className="glass-panel" style={{ padding: '1rem', textAlign: 'center' }}>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '4px' }}>EMAILS DISCOVERED</div>
          <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: 'var(--accent-blue)' }}>{uniqEmails.length}</div>
        </div>
        <div className="glass-panel" style={{ padding: '1rem', textAlign: 'center' }}>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '4px' }}>PHONE NUMBERS</div>
          <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: 'var(--accent-blue)' }}>{uniqPhones.length}</div>
        </div>
        <div className="glass-panel" style={{ padding: '1rem', textAlign: 'center' }}>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '4px' }}>SOCIAL PROFILES</div>
          <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: 'var(--accent-blue)' }}>{uniqSocials.length}</div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1.2rem' }}>
        <div className="glass-panel" style={{ padding: '1.25rem' }}>
          <h4 style={{ margin: '0 0 1rem', fontSize: '0.9rem', fontFamily: 'var(--font-cyber)' }}>📧 EMAILS</h4>
          {uniqEmails.length > 0 ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              {uniqEmails.map((e, idx) => (
                <div key={idx} style={{ padding: '6px', background: 'rgba(255,255,255,0.02)', borderRadius: '4px', fontSize: '0.85rem' }}>
                  <div style={{ color: 'var(--accent-green)', fontFamily: 'var(--font-mono)' }}>{e.val}</div>
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', wordBreak: 'break-all', marginTop: '2px' }}>Source: {e.source}</div>
                </div>
              ))}
            </div>
          ) : <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>No emails found.</div>}
        </div>

        <div className="glass-panel" style={{ padding: '1.25rem' }}>
          <h4 style={{ margin: '0 0 1rem', fontSize: '0.9rem', fontFamily: 'var(--font-cyber)' }}>📞 PHONE NUMBERS</h4>
          {uniqPhones.length > 0 ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              {uniqPhones.map((p, idx) => (
                <div key={idx} style={{ padding: '6px', background: 'rgba(255,255,255,0.02)', borderRadius: '4px', fontSize: '0.85rem' }}>
                  <div style={{ color: 'var(--accent-blue)', fontFamily: 'var(--font-mono)' }}>{p.val}</div>
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', wordBreak: 'break-all', marginTop: '2px' }}>Source: {p.source}</div>
                </div>
              ))}
            </div>
          ) : <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>No phone numbers found.</div>}
        </div>

        <div className="glass-panel" style={{ padding: '1.25rem' }}>
          <h4 style={{ margin: '0 0 1rem', fontSize: '0.9rem', fontFamily: 'var(--font-cyber)' }}>🔗 SOCIAL MEDIA ACCOUNTS</h4>
          {uniqSocials.length > 0 ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              {uniqSocials.map((s, idx) => (
                <div key={idx} style={{ padding: '6px', background: 'rgba(255,255,255,0.02)', borderRadius: '4px', fontSize: '0.85rem' }}>
                  <strong style={{ fontSize: '0.7rem', textTransform: 'uppercase', color: 'var(--text-secondary)' }}>{s.platform}</strong>
                  <div style={{ marginTop: '2px' }}>
                    <a href={s.val} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--accent-blue)', textDecoration: 'none', wordBreak: 'break-all', fontSize: '0.8rem' }}>{s.val}</a>
                  </div>
                </div>
              ))}
            </div>
          ) : <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>No social profiles found.</div>}
        </div>
      </div>
    </div>
  );
};

const RenderSubdomainTakeover = ({ data, activeFilter }) => {
  const allVulns = data.vulnerable_subdomains || [];
  const vulns = ['critical', 'high', 'medium', 'low', 'info'].includes(activeFilter)
    ? allVulns.filter(v => v && typeof v === 'object' && (v.severity || 'high').toLowerCase() === activeFilter)
    : allVulns;
  
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
        <div className="glass-panel" style={{ padding: '8px 16px', borderRadius: '8px' }}>
          Subdomains Scanned: <span style={{ fontWeight: 'bold' }}>{data.scan_info?.subdomains_scanned || 0}</span>
        </div>
        <div className="glass-panel" style={{ padding: '8px 16px', borderRadius: '8px', borderLeft: `3px solid var(--accent-${vulns.length > 0 ? 'red' : 'green'})` }}>
          Vulnerable: <span style={{ fontWeight: 'bold', color: vulns.length > 0 ? 'var(--accent-red)' : 'var(--accent-green)' }}>{vulns.length}</span>
        </div>
      </div>

      {vulns.length > 0 ? (
        <div>
          <h4 style={{ margin: '0 0 0.8rem', fontSize: '0.9rem', fontFamily: 'var(--font-cyber)', color: 'var(--accent-red)' }}>⚠️ SUBDOMAIN TAKEOVER VULNERABILITIES</h4>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            {vulns.map((v, i) => (
              <div key={i} className="glass-panel" style={{ padding: '1rem', borderLeft: '4px solid var(--accent-red)', background: 'rgba(255,0,85,0.02)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                  <strong style={{ fontSize: '0.9rem', color: 'var(--accent-red)' }}>{v.subdomain || v.domain}</strong>
                  <span className="badge severity-high">{v.vulnerability_type || 'Takeover Risk'}</span>
                </div>
                <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                  CNAME Target: <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent-blue)' }}>{v.cname || 'N/A'}</span>
                </div>
                {v.service && (
                  <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '4px' }}>
                    Service: <span style={{ fontWeight: 'bold' }}>{v.service}</span>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      ) : (
        <div className="glass-panel" style={{ padding: '1.5rem', textAlign: 'center', color: 'var(--text-secondary)' }}>
          ✓ No subdomain takeover vulnerabilities detected.
        </div>
      )}
    </div>
  );
};

const RenderCloudFlareBypass = ({ data }) => {
  const protected_status = data.cloudflare_protected;
  const ips = data.real_ips || [];
  
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <div className="glass-panel" style={{ padding: '10px 16px', borderRadius: '8px', borderLeft: `3px solid var(--accent-${protected_status ? 'blue' : 'green'})`, width: 'fit-content' }}>
        Cloudflare WAF Status: <span style={{ fontWeight: 'bold', color: protected_status ? 'var(--accent-blue)' : 'var(--accent-green)' }}>
          {protected_status ? '🛡️ Protected' : '🔓 Not Detected / Direct IP Access Possible'}
        </span>
      </div>

      {ips.length > 0 ? (
        <div>
          <h4 style={{ margin: '0 0 0.8rem', fontSize: '0.9rem', fontFamily: 'var(--font-cyber)', color: 'var(--accent-green)' }}>🌐 DIRECT REAL IP ADDRESSES UNCOVERED</h4>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '1rem' }}>
            {ips.map((item, i) => {
              const ipVal = typeof item === 'object' ? item.ip : String(item);
              const sourceVal = typeof item === 'object' ? item.source : '';
              const portsList = typeof item === 'object' ? item.ports : [];
              return (
                <div key={i} className="glass-panel" style={{ padding: '1rem', borderLeft: '3px solid var(--accent-green)' }}>
                  <div style={{ fontSize: '1.1rem', fontFamily: 'var(--font-mono)', color: 'var(--accent-green)', fontWeight: 'bold', marginBottom: '6px' }}>{ipVal}</div>
                  {sourceVal && <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>Source: {sourceVal}</div>}
                  {portsList && portsList.length > 0 && (
                    <div style={{ marginTop: '8px' }}>
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginBottom: '4px' }}>Open Ports:</div>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                        {portsList.map((p, pidx) => <span key={pidx} className="badge badge-blue" style={{ fontSize: '9px' }}>{p}</span>)}
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      ) : (
        <div className="glass-panel" style={{ padding: '1.5rem', textAlign: 'center', color: 'var(--text-secondary)' }}>
          No bypassable direct IP addresses found.
        </div>
      )}
    </div>
  );
};

const RenderNmapScan = ({ data, activeFilter }) => {
  let ports = [];
  if (data.port_scan) {
    if (Array.isArray(data.port_scan)) {
      ports = data.port_scan;
    } else if (typeof data.port_scan === 'object') {
      ports = Object.entries(data.port_scan).map(([portNum, details]) => ({
        port: portNum,
        service: typeof details === 'object' && details ? (details.service || '') : '',
        state: typeof details === 'object' && details ? (details.state || details.status || '') : String(details),
        product: typeof details === 'object' && details ? (details.product || '') : '',
        version: typeof details === 'object' && details ? (details.version || '') : '',
        ...(typeof details === 'object' ? details : {})
      }));
    }
  }
  const allVulns = data.zero_day_vulnerabilities || [];
  const vulns = ['critical', 'high', 'medium', 'low', 'info'].includes(activeFilter)
    ? allVulns.filter(v => v && typeof v === 'object' && (v.severity || 'medium').toLowerCase() === activeFilter)
    : allVulns;
  
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {data.scan_time != null && (
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
          Scan Duration: {parseFloat(data.scan_time).toFixed(2)} seconds
        </div>
      )}

      <div>
        <h4 style={{ margin: '0 0 0.8rem', fontSize: '0.9rem', fontFamily: 'var(--font-cyber)' }}>🔌 PORT SCANNING RESULTS</h4>
        {ports.length > 0 ? (
          <div className="glass-panel" style={{ padding: '1rem', overflowX: 'auto' }}>
            <table className="cyber-table" style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.85rem' }}>
              <thead>
                <tr style={{ borderBottom: '2px solid var(--panel-border)', textAlign: 'left' }}>
                  <th style={{ padding: '8px' }}>Port</th>
                  <th style={{ padding: '8px' }}>Service</th>
                  <th style={{ padding: '8px' }}>State</th>
                  <th style={{ padding: '8px' }}>Product/Version</th>
                </tr>
              </thead>
              <tbody>
                {ports.map((p, i) => {
                  const isOpen = String(p.state || p.status).toLowerCase() === 'open';
                  return (
                    <tr key={i} style={{ borderBottom: '1px solid var(--panel-border)' }}>
                      <td style={{ padding: '8px', fontFamily: 'var(--font-mono)', fontWeight: 'bold', color: isOpen ? 'var(--accent-green)' : 'var(--text-secondary)' }}>{p.port}</td>
                      <td style={{ padding: '8px' }}>{p.service || 'N/A'}</td>
                      <td style={{ padding: '8px' }}>
                        <span className={`badge ${isOpen ? 'badge-green' : 'badge-red'}`} style={{ fontSize: '10px', padding: '2px 6px' }}>{p.state || p.status}</span>
                      </td>
                      <td style={{ padding: '8px', fontFamily: 'var(--font-mono)', opacity: 0.8 }}>{p.product ? `${p.product} ${p.version || ''}` : 'Unknown'}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : <div className="glass-panel" style={{ padding: '1rem', textAlign: 'center', color: 'var(--text-secondary)' }}>No open ports discovered.</div>}
      </div>

      {vulns.length > 0 && (
        <div>
          <h4 style={{ margin: '0 0 0.8rem', fontSize: '0.9rem', fontFamily: 'var(--font-cyber)', color: 'var(--accent-red)' }}>🎯 ASSIGNED CVEs & ZERO-DAY ANALYSIS ({vulns.length})</h4>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            {vulns.map((v, i) => (
              <div key={i} className="glass-panel" style={{ padding: '1rem', borderLeft: '4px solid var(--accent-red)', background: 'rgba(255,0,85,0.02)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                  <strong style={{ fontSize: '0.9rem', fontFamily: 'var(--font-mono)' }}>{v.cve_id || v.id || 'Zero Day Alert'}</strong>
                  <span className="badge severity-critical">CVSS: {v.cvss || '9.8'}</span>
                </div>
                <p style={{ margin: '0 0 4px', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>{v.description || v.detail}</p>
                {v.affected_service && (
                  <div style={{ fontSize: '0.75rem', color: 'var(--accent-blue)', fontFamily: 'var(--font-mono)', marginTop: '4px' }}>
                    Target Service: {v.affected_service}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

const RenderNestedValue = ({ value }) => {
  if (value == null) return <span style={{ color: 'var(--text-secondary)' }}>—</span>;
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
    return <span style={{ fontFamily: 'var(--font-mono)' }}>{String(value)}</span>;
  }
  if (Array.isArray(value)) {
    if (value.length === 0) return <span style={{ color: 'var(--text-secondary)' }}>Empty List</span>;
    return (
      <ul style={{ margin: 0, paddingLeft: '16px', listStyleType: 'square' }}>
        {value.map((item, idx) => (
          <li key={idx} style={{ marginBottom: '2px' }}>
            <RenderNestedValue value={item} />
          </li>
        ))}
      </ul>
    );
  }
  if (typeof value === 'object') {
    if ('status' in value && ('text' in value || 'value' in value || 'count' in value || 'texts' in value)) {
      const isPass = ['pass', 'ok', 'good', 'found', 'true', 'yes'].includes(String(value.status).toLowerCase());
      const isFail = ['fail', 'error', 'missing', 'too short', 'too long', 'false', 'no'].includes(String(value.status).toLowerCase());
      const color = isPass ? 'var(--accent-green)' : isFail ? 'var(--accent-red)' : 'var(--accent-orange)';
      return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ color, fontWeight: 'bold', fontSize: '0.8rem', textTransform: 'uppercase' }}>
              ● {value.status}
            </span>
            {value.length != null && (
              <span className="badge badge-blue" style={{ fontSize: '9px' }}>
                Len: {value.length}
              </span>
            )}
            {value.count != null && (
              <span className="badge badge-blue" style={{ fontSize: '9px' }}>
                Count: {value.count}
              </span>
            )}
          </div>
          {(value.text || value.value) && (
            <div style={{ opacity: 0.9, fontSize: '0.8rem', wordBreak: 'break-all', fontFamily: 'var(--font-mono)', background: 'rgba(255,255,255,0.02)', padding: '2px 6px', borderRadius: '4px' }}>
              {value.text || value.value}
            </div>
          )}
          {value.texts && Array.isArray(value.texts) && value.texts.length > 0 && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '2px', paddingLeft: '6px' }}>
              {value.texts.map((t, tidx) => (
                <div key={tidx} style={{ fontSize: '0.75rem', color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', background: 'rgba(255,255,255,0.01)', padding: '2px 4px', borderLeft: '2px solid var(--accent-blue)' }}>
                  {t}
                </div>
              ))}
            </div>
          )}
          {value.issues && Array.isArray(value.issues) && value.issues.length > 0 && (
            <div style={{ fontSize: '0.75rem', color: 'var(--accent-orange)', paddingLeft: '8px' }}>
              ⚠️ Issues: {value.issues.join(', ')}
            </div>
          )}
        </div>
      );
    }
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', width: '100%' }}>
        {Object.entries(value).map(([k, v]) => (
          <div key={k} style={{ 
            display: 'flex', 
            flexDirection: 'column', 
            padding: '6px 8px', 
            background: 'rgba(255,255,255,0.01)', 
            borderRadius: '4px',
            border: '1px solid rgba(255,255,255,0.03)'
          }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', fontWeight: 'bold', marginBottom: '4px' }}>{k}</span>
            <div style={{ paddingLeft: '4px' }}>
              <RenderNestedValue value={v} />
            </div>
          </div>
        ))}
      </div>
    );
  }
  return <span>{JSON.stringify(value)}</span>;
};

const RenderSeoAnalysis = ({ data }) => {
  const { score: seoScoreVal, grade: seoGradeVal } = extractScore(data['SEO Score']);
  const seoSections = Object.entries(data).filter(([k]) => k !== 'SEO Score');

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {seoScoreVal != null && (
        <div className="glass-panel" style={{ padding: '10px 16px', borderRadius: '8px', display: 'flex', alignItems: 'center', gap: '8px', width: 'fit-content' }}>
          <span>📊 SEO Score:</span>
          <span style={{ fontWeight: 'bold', color: seoScoreVal >= 80 ? 'var(--accent-green)' : 'var(--accent-orange)' }}>{seoGradeVal ? `${seoGradeVal} (${seoScoreVal}/100)` : `${seoScoreVal}/100`}</span>
        </div>
      )}
      
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
        {seoSections.map(([sectionName, sectionData]) => {
          if (!sectionData || typeof sectionData !== 'object' || Object.keys(sectionData).length === 0) return null;
          
          return (
            <details key={sectionName} className="glass-panel" style={{ padding: '1rem', borderRadius: '10px' }}>
              <summary style={{ cursor: 'pointer', fontWeight: 'bold', fontFamily: 'var(--font-cyber)', fontSize: '0.9rem', color: 'var(--accent-blue)', userSelect: 'none', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span>📋 {sectionName.toUpperCase()}</span>
                <span className="badge badge-blue" style={{ fontSize: '10px' }}>
                  {Object.keys(sectionData).length} metric{Object.keys(sectionData).length !== 1 ? 's' : ''}
                </span>
              </summary>
              <div style={{ marginTop: '1rem', borderTop: '1px solid var(--panel-border)', paddingTop: '1rem' }}>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '1rem' }}>
                  {Object.entries(sectionData).map(([metricName, metricValue]) => (
                    <div key={metricName} style={{ 
                      padding: '10px', 
                      background: 'rgba(255,255,255,0.02)', 
                      borderRadius: '6px', 
                      border: '1px solid var(--panel-border)' 
                    }}>
                      <strong style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '6px' }}>
                        {metricName}
                      </strong>
                      <RenderNestedValue value={metricValue} />
                    </div>
                  ))}
                </div>
              </div>
            </details>
          );
        })}
      </div>
    </div>
  );
};

const RenderGeoAnalysis = ({ data }) => {
  if (!data) return <div style={{ color: 'var(--text-secondary)' }}>No GEO Analysis data available.</div>;

  const geoScoreObj = data['GEO Score'] || {};
  const { score: scoreVal, grade: gradeVal } = extractScore(geoScoreObj);
  const llmsTxt = data['LLMs Optimization (llms.txt)'] || {};
  const webMcp = data['WebMCP Integration'] || {};
  const aiCrawlers = data['AI Crawler Directives'] || {};

  const getScoreColor = (val) => {
    if (val >= 80) return 'var(--accent-green)';
    if (val >= 50) return 'var(--accent-orange)';
    return 'var(--accent-red)';
  };

  const scoreColor = getScoreColor(scoreVal ?? 0);
  const strokeDashoffset = 251.2 - (251.2 * (scoreVal ?? 0)) / 100;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Top Section: Score and Overview */}
      <div style={{ display: 'flex', gap: '1.5rem', flexWrap: 'wrap', alignItems: 'center' }}>
        <div className="glass-panel" style={{
          display: 'flex',
          alignItems: 'center',
          gap: '1.5rem',
          padding: '1.5rem',
          borderRadius: '12px',
          flex: '1 1 300px',
          borderLeft: `4px solid ${scoreColor}`
        }}>
          {/* Circular SVG Gauge */}
          <div style={{ position: 'relative', width: '90px', height: '90px', flexShrink: 0 }}>
            <svg width="90" height="90" viewBox="0 0 100 100" style={{ transform: 'rotate(-90deg)' }}>
              <circle cx="50" cy="50" r="40" fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="8" />
              <circle
                cx="50"
                cy="50"
                r="40"
                fill="none"
                stroke={scoreColor}
                strokeWidth="8"
                strokeDasharray="251.2"
                strokeDashoffset={strokeDashoffset}
                strokeLinecap="round"
                style={{ transition: 'stroke-dashoffset 1s ease' }}
              />
            </svg>
            <div style={{
              position: 'absolute',
              top: '50%',
              left: '50%',
              transform: 'translate(-50%, -50%)',
              textAlign: 'center',
              fontFamily: 'var(--font-mono)',
            }}>
              <div style={{ fontSize: '1.25rem', fontWeight: 'bold', color: scoreColor }}>{scoreVal ?? 0}</div>
              <div style={{ fontSize: '0.65rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>GEO Score</div>
            </div>
          </div>
          <div>
            <h4 style={{ margin: '0 0 4px 0', fontFamily: 'var(--font-cyber)', fontSize: '1rem' }}>Generative Engine Optimization</h4>
            <p style={{ margin: 0, fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
              Evaluates target discoverability and integration maturity for LLM engines, AI search crawlers, and WebMCP agents.
            </p>
            <div style={{ marginTop: '8px' }}>
              <span className="badge" style={{
                background: `${scoreColor}15`,
                color: scoreColor,
                border: `1px solid ${scoreColor}`,
                fontSize: '0.8rem',
                fontFamily: 'var(--font-cyber)'
              }}>
                Grade: {gradeVal || 'F'}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Grid of details */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '1rem' }}>
        {/* llms.txt optimization */}
        <div className="glass-panel" style={{ padding: '1.2rem', borderRadius: '10px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px', borderBottom: '1px solid var(--panel-border)', paddingBottom: '6px' }}>
            <span style={{ fontWeight: 'bold', fontSize: '0.85rem', color: 'var(--text-primary)', fontFamily: 'var(--font-cyber)' }}>
              🤖 LLMs Optimization
            </span>
            <span className={`badge ${llmsTxt.status === 'Found' ? 'badge-green' : 'badge-orange'}`} style={{ fontSize: '10px' }}>
              {llmsTxt.status || 'Not Found'}
            </span>
          </div>
          <div style={{ fontSize: '0.85rem', display: 'flex', flexDirection: 'column', gap: '6px' }}>
            <div style={{ color: 'var(--text-secondary)' }}>
              Presence of standard machine-readable description files (`llms.txt`) for indexing.
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginTop: '6px' }}>
              <span style={{ color: 'var(--text-secondary)', fontSize: '0.75rem' }}>Discovered files:</span>
              {llmsTxt.files && llmsTxt.files !== 'None' ? (
                llmsTxt.files.split(',').map((f, i) => (
                  <span key={i} className="badge badge-blue" style={{ fontFamily: 'var(--font-mono)', fontSize: '10px' }}>
                    {f.trim()}
                  </span>
                ))
              ) : (
                <span style={{ color: 'var(--accent-red)', fontSize: '0.8rem', fontWeight: 'bold' }}>None Detected</span>
              )}
            </div>
          </div>
        </div>

        {/* WebMCP Integration */}
        <div className="glass-panel" style={{ padding: '1.2rem', borderRadius: '10px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px', borderBottom: '1px solid var(--panel-border)', paddingBottom: '6px' }}>
            <span style={{ fontWeight: 'bold', fontSize: '0.85rem', color: 'var(--text-primary)', fontFamily: 'var(--font-cyber)' }}>
              🔌 WebMCP Integration
            </span>
            <span className={`badge ${webMcp.status === 'Found' ? 'badge-green' : 'badge-blue'}`} style={{ fontSize: '10px' }}>
              {webMcp.status || 'Not Found'}
            </span>
          </div>
          <div style={{ fontSize: '0.85rem', display: 'flex', flexDirection: 'column', gap: '6px' }}>
            <div style={{ color: 'var(--text-secondary)' }}>
              Model Context Protocol (MCP) handlers and metadata for AI agent interaction.
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', marginTop: '6px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-secondary)', fontSize: '0.75rem' }}>MCP Endpoints:</span>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>{webMcp.endpoints && webMcp.endpoints !== 'None' ? webMcp.endpoints : '—'}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--text-secondary)', fontSize: '0.75rem' }}>HTML Features:</span>
                <span style={{ fontSize: '0.8rem', textAlign: 'right' }}>{webMcp.html_features && webMcp.html_features !== 'None' ? webMcp.html_features : '—'}</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Robots.txt AI Crawlers */}
      {aiCrawlers && aiCrawlers.bots && (
        <div className="glass-panel" style={{ padding: '1.2rem', borderRadius: '10px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px', borderBottom: '1px solid var(--panel-border)', paddingBottom: '6px' }}>
            <span style={{ fontWeight: 'bold', fontSize: '0.85rem', color: 'var(--text-primary)', fontFamily: 'var(--font-cyber)' }}>
              🕷️ AI Crawler robots.txt Directives
            </span>
            <span className={`badge ${aiCrawlers.status === 'Permissive' ? 'badge-green' : 'badge-orange'}`} style={{ fontSize: '10px' }}>
              {aiCrawlers.status || 'Unknown'} Policy
            </span>
          </div>
          <p style={{ margin: '0 0 10px 0', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
            Policies configured in `robots.txt` regulating AI agents and scrapers:
          </p>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: '0.6rem' }}>
            {Object.entries(aiCrawlers.bots).map(([bot, status]) => {
              const isAllowed = status.toLowerCase().includes('allow');
              const isBlocked = status.toLowerCase().includes('block');
              const statusColor = isAllowed ? 'var(--accent-green)' : isBlocked ? 'var(--accent-red)' : 'var(--accent-orange)';
              return (
                <div key={bot} style={{
                  padding: '8px 10px',
                  background: 'rgba(255,255,255,0.01)',
                  border: '1px solid var(--panel-border)',
                  borderRadius: '6px',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center'
                }}>
                  <span style={{ fontSize: '0.8rem', fontFamily: 'var(--font-mono)', fontWeight: '500' }}>{bot}</span>
                  <span style={{
                    fontSize: '10px',
                    fontFamily: 'var(--font-cyber)',
                    color: statusColor,
                    padding: '2px 6px',
                    background: `${statusColor}10`,
                    borderRadius: '4px',
                    border: `1px solid ${statusColor}30`
                  }}>
                    {status}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};

const RenderWebArchiveSpy = ({ data }) => {
  if (!data) return <div style={{ color: 'var(--text-secondary)' }}>No Web Archive Spy data available.</div>;

  const secrets = data.secrets || [];
  const totalSecrets = data.total_secrets_found ?? secrets.length;
  const message = data.message;

  if (totalSecrets === 0) {
    return (
      <div className="glass-panel" style={{
        padding: '2rem',
        borderRadius: '12px',
        textAlign: 'center',
        border: '1px solid rgba(57, 255, 20, 0.2)',
        background: 'linear-gradient(135deg, rgba(57,255,20,0.02) 0%, rgba(0,0,0,0) 100%)'
      }}>
        <div style={{ fontSize: '2.5rem', marginBottom: '0.8rem' }}>🛡️</div>
        <h4 style={{ margin: '0 0 6px 0', fontFamily: 'var(--font-cyber)', color: 'var(--accent-green)', letterSpacing: '0.5px' }}>
          WAYBACK MACHINE SECRETS SHIELDED
        </h4>
        <p style={{ margin: 0, fontSize: '0.85rem', color: 'var(--text-secondary)', maxWidth: '550px', margin: '0 auto' }}>
          No historical API keys, tokens, or credentials detected in files archived by the Wayback Machine ({message || 'Clean history'}).
        </p>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div className="glass-panel" style={{
        padding: '1rem 1.25rem',
        borderRadius: '8px',
        borderLeft: '4px solid var(--accent-red)',
        background: 'rgba(255, 85, 85, 0.02)',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center'
      }}>
        <div>
          <strong style={{ color: 'var(--accent-red)', fontSize: '0.9rem', fontFamily: 'var(--font-cyber)' }}>
            ⚠️ LEAKED HISTORICAL SECRETS DETECTED
          </strong>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '2px' }}>
            Wayback Machine archive contains historical snapshots exposing credentials in scripts/configurations.
          </div>
        </div>
        <span className="badge badge-red" style={{ fontSize: '0.85rem', padding: '4px 10px', fontFamily: 'var(--font-mono)' }}>
          {totalSecrets} leak{totalSecrets > 1 ? 's' : ''} found
        </span>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.8rem' }}>
        {secrets.map((secret, index) => {
          const isHigh = secret.severity?.toLowerCase() === 'high';
          const badgeColor = isHigh ? 'var(--accent-red)' : 'var(--accent-orange)';
          return (
            <div key={index} className="glass-panel" style={{ padding: '1.25rem', borderRadius: '10px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span style={{ fontSize: '1.1rem' }}>🔑</span>
                  <span style={{ fontWeight: 'bold', fontSize: '0.9rem', color: 'var(--text-primary)' }}>{secret.type}</span>
                </div>
                <span className="badge" style={{
                  background: `${badgeColor}15`,
                  color: badgeColor,
                  border: `1px solid ${badgeColor}`,
                  fontSize: '10px'
                }}>
                  {secret.severity || 'Medium'} Severity
                </span>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
                <div style={{
                  background: 'rgba(0, 0, 0, 0.2)',
                  padding: '6px 12px',
                  borderRadius: '6px',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '0.8rem',
                  color: 'var(--accent-green)',
                  border: '1px solid var(--panel-border)',
                  wordBreak: 'break-all'
                }}>
                  Value: {secret.value}
                </div>

                <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                  <strong>Source Asset: </strong>
                  <a href={secret.file_url} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--accent-blue)', textDecoration: 'underline', wordBreak: 'break-all' }}>
                    {secret.file_url}
                  </a>
                </div>

                <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                  <strong>Wayback Archive Snapshot: </strong>
                  <a href={secret.wayback_url} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--accent-purple)', textDecoration: 'underline', wordBreak: 'break-all' }}>
                    View Wayback Capture 🔍
                  </a>
                </div>

                {secret.context && (
                  <details style={{ marginTop: '4px' }}>
                    <summary style={{ cursor: 'pointer', fontSize: '0.75rem', color: 'var(--text-secondary)', userSelect: 'none' }}>
                      Show Code Context Match
                    </summary>
                    <div style={{
                      marginTop: '6px',
                      background: 'rgba(0, 0, 0, 0.4)',
                      padding: '8px 12px',
                      borderRadius: '6px',
                      fontFamily: 'var(--font-mono)',
                      fontSize: '0.75rem',
                      color: 'var(--text-secondary)',
                      borderLeft: '3px solid var(--accent-blue)',
                      overflowX: 'auto',
                      whiteSpace: 'pre-wrap',
                      wordBreak: 'break-all'
                    }}>
                      {secret.context}
                    </div>
                  </details>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

const RenderPhishingProtection = ({ data }) => {
  if (!data) return <div style={{ color: 'var(--text-secondary)' }}>No Phishing Protection data available.</div>;

  const scannedCount = data.total_candidates_scanned ?? 0;
  const activeCount = data.total_active_phishing_domains ?? 0;
  const phishingDomains = data.phishing_domains || [];

  if (activeCount === 0) {
    return (
      <div className="glass-panel" style={{
        padding: '2.5rem 2rem',
        borderRadius: '12px',
        textAlign: 'center',
        border: '1px solid rgba(57, 255, 20, 0.2)',
        background: 'linear-gradient(135deg, rgba(57,255,20,0.02) 0%, rgba(0,0,0,0) 100%)'
      }}>
        <div style={{ fontSize: '3rem', marginBottom: '0.8rem', color: 'var(--accent-green)' }}>🛡️</div>
        <h4 style={{ margin: '0 0 6px 0', fontFamily: 'var(--font-cyber)', color: 'var(--accent-green)', letterSpacing: '1px' }}>
          NO ACTIVE PHISHING THREATS DETECTED
        </h4>
        <p style={{ margin: '0 auto 1.2rem auto', fontSize: '0.85rem', color: 'var(--text-secondary)', maxWidth: '550px' }}>
          We generated typosquatted, homoglyph lookalike, and phishing variation domains, and monitored active DNS resolutions. No active typosquatting servers were detected.
        </p>
        <div style={{ display: 'inline-flex', gap: '1.5rem', background: 'rgba(255,255,255,0.02)', padding: '8px 20px', borderRadius: '8px', border: '1px solid var(--panel-border)' }}>
          <div style={{ textAlign: 'left' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Candidates Scanned</span>
            <div style={{ fontSize: '1.2rem', fontWeight: 'bold', fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>{scannedCount}</div>
          </div>
          <div style={{ width: '1px', background: 'var(--panel-border)' }}></div>
          <div style={{ textAlign: 'left' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--accent-green)', textTransform: 'uppercase' }}>Active Threats</span>
            <div style={{ fontSize: '1.2rem', fontWeight: 'bold', fontFamily: 'var(--font-mono)', color: 'var(--accent-green)' }}>0</div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.2rem' }}>
      <div className="glass-panel" style={{
        padding: '1.2rem 1.5rem',
        borderRadius: '10px',
        borderLeft: '4px solid var(--accent-red)',
        background: 'rgba(255, 85, 85, 0.03)',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        flexWrap: 'wrap',
        gap: '1rem'
      }}>
        <div>
          <strong style={{ color: 'var(--accent-red)', fontSize: '1rem', fontFamily: 'var(--font-cyber)', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span className="status-indicator alert-pulse" style={{ width: '10px', height: '10px', background: 'var(--accent-red)', display: 'inline-block' }}></span>
            CRITICAL PHISHING RISK DETECTED
          </strong>
          <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginTop: '4px' }}>
            Active domains using typosquatting/homoglyphs detected resolving to IP addresses. These could host spoofed logins.
          </div>
        </div>
        <div style={{ display: 'flex', gap: '1rem', background: 'rgba(0,0,0,0.2)', padding: '6px 12px', borderRadius: '6px' }}>
          <div>
            <div style={{ fontSize: '10px', color: 'var(--text-secondary)' }}>SCANNED</div>
            <div style={{ fontSize: '1.1rem', fontWeight: 'bold', fontFamily: 'var(--font-mono)' }}>{scannedCount}</div>
          </div>
          <div>
            <div style={{ fontSize: '10px', color: 'var(--accent-red)' }}>ACTIVE</div>
            <div style={{ fontSize: '1.1rem', fontWeight: 'bold', fontFamily: 'var(--font-mono)', color: 'var(--accent-red)' }}>{activeCount}</div>
          </div>
        </div>
      </div>

      <div style={{ overflowX: 'auto' }}>
        <table className="cyber-table" style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.85rem' }}>
          <thead>
            <tr style={{ borderBottom: '2px solid var(--panel-border)', textAlign: 'left' }}>
              <th style={{ padding: '10px 12px', color: 'var(--text-secondary)' }}>TYPOSQUAT TARGET DOMAIN</th>
              <th style={{ padding: '10px 12px', color: 'var(--text-secondary)' }}>RESOLVED IP ADDRESS(ES)</th>
              <th style={{ padding: '10px 12px', color: 'var(--text-secondary)' }}>RISK LEVEL</th>
              <th style={{ padding: '10px 12px', color: 'var(--text-secondary)' }}>STATUS</th>
            </tr>
          </thead>
          <tbody>
            {phishingDomains.map((item, idx) => (
              <tr key={idx} style={{ borderBottom: '1px solid var(--panel-border)' }}>
                <td style={{ padding: '12px', fontWeight: 'bold', color: 'var(--accent-red)', fontFamily: 'var(--font-mono)' }}>
                  {item.domain}
                </td>
                <td style={{ padding: '12px' }}>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                    {Array.isArray(item.ips) ? (
                      item.ips.map((ip, i) => (
                        <span key={i} className="badge badge-blue" style={{ fontFamily: 'var(--font-mono)', fontSize: '11px' }}>{ip}</span>
                      ))
                    ) : (
                      <span className="badge badge-blue" style={{ fontFamily: 'var(--font-mono)', fontSize: '11px' }}>{String(item.ips)}</span>
                    )}
                  </div>
                </td>
                <td style={{ padding: '12px' }}>
                  <span className="badge badge-red" style={{ fontSize: '10px', textTransform: 'uppercase' }}>
                    {item.severity || 'HIGH'}
                  </span>
                </td>
                <td style={{ padding: '12px' }}>
                  <span style={{
                    color: 'var(--accent-red)',
                    fontSize: '11px',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '4px',
                    fontWeight: 'bold',
                    textTransform: 'uppercase'
                  }}>
                    ● {item.status || 'Active'}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

const RenderSslSanAssociation = ({ data }) => {
  if (!data) return <div style={{ color: 'var(--text-secondary)' }}>No SSL SAN Association data available.</div>;

  const associated = data.associated_domains || [];
  const totalSan = data.total_san_domains ?? associated.length;
  const [searchTerm, setSearchTerm] = useState('');

  if (totalSan === 0 || associated.length === 0) {
    return (
      <div className="glass-panel" style={{ padding: '1.5rem', borderRadius: '10px', textAlign: 'center', color: 'var(--text-secondary)' }}>
        No associated SSL Subject Alternative Names (SAN) domains found.
      </div>
    );
  }

  const filteredDomains = associated.filter(d => d.toLowerCase().includes(searchTerm.toLowerCase()));

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.2rem' }}>
      {/* Header and Search */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
            SSL Subject Alternative Names
          </span>
          <h4 style={{ margin: '4px 0 0 0', fontSize: '1.1rem', fontFamily: 'var(--font-cyber)' }}>
            Associated Domain Graph Nodes ({totalSan})
          </h4>
        </div>

        {associated.length > 8 && (
          <input
            type="text"
            className="input-glass"
            placeholder="🔍 Search SAN nodes..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            style={{
              padding: '6px 12px',
              fontSize: '0.85rem',
              borderRadius: '6px',
              width: '220px',
              border: '1px solid var(--panel-border)',
              background: 'rgba(0,0,0,0.3)',
              color: 'var(--text-primary)',
              fontFamily: 'var(--font-mono)'
            }}
          />
        )}
      </div>

      <p style={{ margin: 0, fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
        These domains are cryptographically linked under the same certificate authority scope. Shared certificates often reveal development, staging, or partner infrastructures.
      </p>

      {/* Domain Node Grid */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))',
        gap: '0.75rem',
        maxHeight: '400px',
        overflowY: 'auto',
        padding: '8px',
        background: 'rgba(0,0,0,0.15)',
        borderRadius: '8px',
        border: '1px solid var(--panel-border)'
      }}>
        {filteredDomains.map((dom, idx) => {
          const isWildcard = dom.startsWith('*.');
          const badgeClass = isWildcard ? 'badge-purple' : 'badge-blue';
          
          return (
            <div
              key={idx}
              className="glass-panel"
              style={{
                padding: '10px 12px',
                borderRadius: '6px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                border: isWildcard ? '1px solid rgba(191, 64, 191, 0.25)' : '1px solid var(--panel-border)',
                background: isWildcard ? 'rgba(191, 64, 191, 0.02)' : 'rgba(255,255,255,0.01)',
                transition: 'all 0.2s ease',
                cursor: 'default',
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.transform = 'translateY(-2px)';
                e.currentTarget.style.boxShadow = isWildcard 
                  ? '0 0 10px rgba(191, 64, 191, 0.2)' 
                  : '0 0 10px rgba(0, 242, 254, 0.15)';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.transform = 'none';
                e.currentTarget.style.boxShadow = 'none';
              }}
            >
              <span style={{
                fontFamily: 'var(--font-mono)',
                fontSize: '0.8rem',
                color: isWildcard ? 'var(--accent-purple)' : 'var(--text-primary)',
                wordBreak: 'break-all',
                marginRight: '6px'
              }}>
                {dom}
              </span>
              
              <span className={`badge ${badgeClass}`} style={{
                fontSize: '9px',
                padding: '1px 5px',
                textTransform: 'uppercase',
                flexShrink: 0
              }}>
                {isWildcard ? 'Wildcard' : 'Node'}
              </span>
            </div>
          );
        })}
        {filteredDomains.length === 0 && (
          <div style={{ gridColumn: '1 / -1', textAlign: 'center', padding: '2rem', color: 'var(--text-secondary)', fontSize: '0.85rem' }}>
            No matching SAN domains found.
          </div>
        )}
      </div>
    </div>
  );
};

/* ── Error Boundary: prevents one module from crashing the whole page ── */
class ModuleErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }
  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }
  componentDidCatch(error, info) {
    console.error(`[ResultsPanel] Module "${this.props.moduleName}" crashed:`, error, info);
  }
  render() {
    if (this.state.hasError) {
      return (
        <div className="glass-panel" style={{ padding: '1rem', borderLeft: '4px solid var(--accent-orange)', color: 'var(--accent-orange)', fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}>
          ⚠️ Render error in module <strong>{this.props.moduleName}</strong>: {String(this.state.error?.message || 'Unknown error')}
          <details style={{ marginTop: '0.5rem', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
            <summary style={{ cursor: 'pointer' }}>Stack trace</summary>
            <pre style={{ whiteSpace: 'pre-wrap', marginTop: '4px' }}>{String(this.state.error?.stack || '')}</pre>
          </details>
        </div>
      );
    }
    return this.props.children;
  }
}

const ModuleResultRenderer = ({ moduleName, moduleData, activeFilter }) => {
  if (moduleData && moduleData.error) {
    return (
      <div className="glass-panel" style={{ padding: '1rem', borderLeft: '4px solid var(--accent-red)', color: 'var(--accent-red)', fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}>
        ⚠️ Error executing module: {moduleData.error}
      </div>
    );
  }

  let content = null;
  switch (moduleName) {
    case 'DNS Records':
      content = <RenderDnsRecords data={moduleData} />;
      break;
    case 'Domain Information':
      content = <RenderDomainInfo data={moduleData} />;
      break;
    case 'Web Technologies':
      content = <RenderWebTech data={moduleData} />;
      break;
    case 'Security Analysis':
      content = <RenderSecurityAnalysis data={moduleData} activeFilter={activeFilter} />;
      break;
    case 'Advanced Content Scan':
      content = <RenderAdvancedContentScan data={moduleData} activeFilter={activeFilter} />;
      break;
    case 'Contact Spy':
      content = <RenderContactSpy data={moduleData} />;
      break;
    case 'Subdomain Takeover':
      content = <RenderSubdomainTakeover data={moduleData} activeFilter={activeFilter} />;
      break;
    case 'CloudFlare Bypass':
      content = <RenderCloudFlareBypass data={moduleData} />;
      break;
    case 'Nmap Zero Day Scan':
      content = <RenderNmapScan data={moduleData} activeFilter={activeFilter} />;
      break;
    case 'SEO Analysis':
      content = <RenderSeoAnalysis data={moduleData} />;
      break;
    case 'GEO Analysis':
      content = <RenderGeoAnalysis data={moduleData} />;
      break;
    case 'Web Archive Spy':
      content = <RenderWebArchiveSpy data={moduleData} />;
      break;
    case 'Phishing Domain Protection':
      content = <RenderPhishingProtection data={moduleData} />;
      break;
    case 'SSL SAN Association':
      content = <RenderSslSanAssociation data={moduleData} />;
      break;
    case 'Subdomain Discovery':
      if (Array.isArray(moduleData)) {
        content = (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <span style={{ fontSize: '0.85rem', color: 'var(--text-secondary)' }}>Total discovered: {moduleData.length} subdomains</span>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px', maxHeight: '250px', overflowY: 'auto', padding: '6px', background: 'rgba(0,0,0,0.2)', borderRadius: '6px', border: '1px solid var(--panel-border)' }}>
              {moduleData.map((sub, i) => (
                <span key={i} className="badge badge-blue" style={{ fontSize: '0.8rem', padding: '2px 6px', fontFamily: 'var(--font-mono)' }}>{sub}</span>
              ))}
            </div>
          </div>
        );
      }
      break;
    default:
      if (Array.isArray(moduleData)) {
        content = (
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
            {moduleData.map((item, i) => (
              <span key={i} className="badge badge-blue" style={{ fontSize: '0.8rem', padding: '2px 6px' }}>
                {typeof item === 'object' ? JSON.stringify(item) : String(item)}
              </span>
            ))}
          </div>
        );
      } else if (typeof moduleData === 'object' && moduleData !== null) {
        content = (
          <div style={{ overflowX: 'auto' }}>
            <table className="cyber-table" style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.85rem' }}>
              <tbody>
                {Object.entries(moduleData).map(([k, v]) => (
                  <tr key={k} style={{ borderBottom: '1px solid var(--panel-border)' }}>
                    <td style={{ padding: '8px', color: 'var(--text-secondary)', width: '35%' }}>{k}</td>
                    <td style={{ padding: '8px', fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>
                      {typeof v === 'object' ? JSON.stringify(v) : String(v)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        );
      } else {
        content = <div style={{ fontSize: '0.9rem', fontFamily: 'var(--font-mono)' }}>{String(moduleData)}</div>;
      }
  }

  return (
    <div>
      {content}
      
      <details style={{ marginTop: '1.2rem', borderTop: '1px dashed var(--panel-border)', paddingTop: '0.6rem' }}>
        <summary style={{ cursor: 'pointer', color: 'var(--text-secondary)', fontSize: '0.75rem', fontFamily: 'var(--font-mono)', userSelect: 'none' }}>
          📂 View Raw JSON Data ({moduleName})
        </summary>
        <div className="json-view" style={{ marginTop: '0.5rem', maxHeight: '300px', overflowY: 'auto' }}>
          <InteractiveJson data={moduleData} initExpanded={false} />
        </div>
      </details>
    </div>
  );
};

const ResultsPanel = ({ domain, setCurrentDomain }) => {
  const [activeDomain, setActiveDomain] = useState(domain || 'example.com');
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [modalState, setModalState] = useState({ isOpen: false, moduleName: '' });
  const [activeFilter, setActiveFilter] = useState('all');
  const [recentScans, setRecentScans] = useState([]);

  // Sync prop changes to activeDomain state
  useEffect(() => {
    if (domain && domain !== activeDomain) {
      setActiveDomain(domain);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [domain]);

  // Fetch recent scans once on mount
  useEffect(() => {
    const fetchRecent = async () => {
      try {
        const res = await fetch(getApiUrl('/api/recent-scans'));
        if (res.ok) {
          const json = await res.json();
          setRecentScans(json);
          // If activeDomain is default un-scanned example.com and we have past scans, auto-select the latest one
          if (activeDomain === 'example.com' && json.length > 0) {
            const latestDomain = json[0].domain;
            setActiveDomain(latestDomain);
            if (setCurrentDomain) {
              setCurrentDomain(latestDomain);
            }
          }
        }
      } catch (err) {
        console.error('Error fetching recent scans', err);
      }
    };
    fetchRecent();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    let interval;
    const fetchResults = async (showLoading = false) => {
      if (showLoading) {
        setLoading(true);
      }
      try {
        const res = await fetch(getApiUrl(`/api/status/${activeDomain}`));
        if (res.ok) {
          const json = await res.json();
          setData(json);
          setError(null);
          
          if (json.current_module === 'Finished') {
            setLoading(false);
            clearInterval(interval);
          } else {
            setLoading(false);
          }
        } else {
          setLoading(false);
          setData(null);
          if (res.status === 404) {
            setError(`No scan results found for ${activeDomain}. Run a scan to get started.`);
          } else {
            setError('Waiting for backend acknowledgment...');
          }
          clearInterval(interval);
        }
      } catch {
        setLoading(false);
        setData(null);
        setError('Cannot connect to API server.');
        clearInterval(interval);
      }
    };

    fetchResults(true);
    interval = setInterval(() => fetchResults(false), 2000);
    return () => clearInterval(interval);
  }, [activeDomain]);

  const handleDomainChange = (e) => {
    const val = e.target.value;
    if (val) {
      setActiveDomain(val);
      if (setCurrentDomain) {
        setCurrentDomain(val);
      }
    }
  };

  const openEducationModal = (moduleName) => {
    setModalState({ isOpen: true, moduleName });
  };

  const exportJSON = () => {
    if (!data || !data.results) return;
    const blob = new Blob([JSON.stringify(data.results, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${activeDomain}-results.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };



  const progressPercent = data && data.total ? Math.round((data.completed / data.total) * 100) : 0;
  const isFinished = data && data.current_module === 'Finished';

  const filterTabs = [
    { id: 'all', label: 'All', icon: '📋' },
    { id: 'vulnerabilities', label: 'Vulnerabilities', icon: '🔴' },
    { id: 'information', label: 'Information', icon: '🔵' },
    { id: 'errors', label: 'Errors', icon: '⚠️' },
  ];

  const filteredEntries = data && data.results
    ? Object.entries(data.results).filter(([moduleName, moduleData]) => {
        // Exclude Attack Path Planner since it has its own dedicated tab
        if (moduleName === 'Attack Path Planner') return false;

        if (activeFilter === 'all') return true;
        if (activeFilter === 'errors') return moduleData && moduleData.error;
        
        if (['critical', 'high', 'medium', 'low', 'info'].includes(activeFilter)) {
          const vulns = Array.isArray(moduleData)
            ? moduleData
            : Array.isArray(moduleData?.vulnerabilities)
              ? moduleData.vulnerabilities
              : Array.isArray(moduleData?.vulnerable_subdomains)
                ? moduleData.vulnerable_subdomains
                : [];
          return vulns.some(v => v && typeof v === 'object' && (v.severity || v.confidence || 'medium').toLowerCase() === activeFilter);
        }

        const cats = categorizeModule(moduleName, moduleData);
        return cats.includes(activeFilter);
      })
    : [];

  return (
    <div className="animate-fade-in" style={{ maxWidth: '1000px', margin: '0 auto' }}>
      <EducationModal 
        isOpen={modalState.isOpen} 
        moduleName={modalState.moduleName} 
        onClose={() => setModalState({ isOpen: false, moduleName: '' })} 
      />

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginBottom: '1rem', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h2 style={{ fontSize: '2rem', marginBottom: '0.5rem' }}>Analysis Results</h2>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <span style={{ color: 'var(--text-secondary)' }}>Target: </span>
            {recentScans.length > 0 ? (
              <select
                value={activeDomain}
                onChange={handleDomainChange}
                className="input-glass"
                style={{
                  padding: '6px 12px',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '0.9rem',
                  color: 'var(--accent-blue)',
                  border: '1px solid var(--panel-border)',
                  borderRadius: '6px',
                  background: 'rgba(0,0,0,0.5)',
                  cursor: 'pointer',
                  minWidth: '200px'
                }}
              >
                {recentScans.map(s => (
                  <option key={s.domain} value={s.domain} style={{ background: '#0b0f19', color: '#fff' }}>
                    {s.domain} {s.grade ? `[${s.grade}]` : ''}
                  </option>
                ))}
                {!recentScans.some(s => s.domain === activeDomain) && (
                  <option value={activeDomain} style={{ background: '#0b0f19', color: '#fff' }}>{activeDomain}</option>
                )}
              </select>
            ) : (
              <strong style={{ color: 'var(--text-primary)' }}>{activeDomain}</strong>
            )}
          </div>
        </div>
        
        <div style={{ display: 'flex', gap: '0.8rem', alignItems: 'center' }}>
          {data && isFinished && (
            <button
              className="btn-outline"
              onClick={exportJSON}
              style={{ padding: '0.5rem 1rem', fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '6px' }}
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                <polyline points="7 10 12 15 17 10"/>
                <line x1="12" y1="15" x2="12" y2="3"/>
              </svg>
              Export JSON
            </button>
          )}
          {data && (
            <div className="glass-panel" style={{ padding: '1rem', display: 'flex', gap: '2rem' }}>
              <div>
                <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Scope Modules</div>
                <div style={{ fontSize: '1.5rem', fontWeight: 'bold' }}>{data.total || '-'}</div>
              </div>
              <div>
                <div style={{ fontSize: '0.8rem', color: 'var(--accent-green)', textTransform: 'uppercase' }}>Executed</div>
                <div style={{ fontSize: '1.5rem', fontWeight: 'bold' }}>{data.completed || '0'}</div>
              </div>
            </div>
          )}
        </div>
      </div>

      {data && data.results && <SeverityBar results={data.results} activeFilter={activeFilter} onSelectSeverity={setActiveFilter} />}

      {data && !isFinished && (
        <div className="glass-panel" style={{ padding: '1.5rem', marginBottom: '2.5rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem', fontSize: '0.9rem' }}>
            <span style={{ color: 'var(--text-secondary)' }}>
              Status: <strong style={{ color: 'var(--accent-blue)' }}>{data.current_module}</strong>
            </span>
            <span>{progressPercent}%</span>
          </div>
          <div className="progress-container">
            <div className="progress-bar-fill" style={{ width: `${progressPercent}%` }}></div>
          </div>
        </div>
      )}

      {loading && !data && (
        <div className="glass-panel" style={{ padding: '3rem', textAlign: 'center', color: 'var(--text-secondary)' }}>
          <div className="status-indicator pending" style={{ width: '20px', height: '20px', margin: '0 auto 1rem auto' }}></div>
          <p>Initializing Scan Pipeline for {activeDomain}...</p>
        </div>
      )}

      {error && !data && !loading && (
        <div className="glass-panel" style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-secondary)', borderStyle: 'dashed' }}>
          <p>{error}</p>
        </div>
      )}

      {data && data.results && (
        <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1.5rem', borderBottom: '1px solid var(--panel-border)', paddingBottom: '0.5rem' }}>
          {filterTabs.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveFilter(tab.id)}
              style={{
                padding: '0.5rem 1rem',
                background: activeFilter === tab.id ? 'rgba(0, 242, 254, 0.1)' : 'transparent',
                border: activeFilter === tab.id ? '1px solid var(--accent-blue)' : '1px solid transparent',
                borderRadius: '6px 6px 0 0',
                color: activeFilter === tab.id ? 'var(--accent-blue)' : 'var(--text-secondary)',
                cursor: 'pointer',
                fontSize: '0.85rem',
                fontFamily: 'var(--font-sans)',
                transition: 'all 0.2s ease',
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
              }}
            >
              <span>{tab.icon}</span>
              {tab.label}
            </button>
          ))}
        </div>
      )}

      {filteredEntries.map(([moduleName, moduleData]) => (
        <div key={moduleName} style={{ marginBottom: '3rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingBottom: '0.5rem', borderBottom: '1px solid var(--panel-border)', marginBottom: '1.5rem' }}>
            <h3 style={{ fontSize: '1.2rem', display: 'flex', alignItems: 'center', gap: '10px', margin: 0 }}>
              {moduleName}
            </h3>
            <button 
              className="btn-outline" 
              style={{ padding: '0.3rem 0.8rem', fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '6px' }}
              onClick={() => openEducationModal(moduleName)}
              title="Learn how this module generated these results"
            >
              🎓 Learn More
            </button>
          </div>
          
          <div className="glass-panel" style={{ padding: '1.5rem', borderRadius: '12px' }}>
            <ModuleErrorBoundary moduleName={moduleName}>
              <ModuleResultRenderer moduleName={moduleName} moduleData={moduleData} activeFilter={activeFilter} />
            </ModuleErrorBoundary>
          </div>
        </div>
      ))}
    </div>
  );
};

export default ResultsPanel;
