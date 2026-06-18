import React, { useState, useEffect } from 'react';
import EducationModal from './EducationModal';
import InteractiveJson from './InteractiveJson';
import { getApiUrl } from '../config';

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
const SeverityBar = ({ results }) => {
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
    <div className="glass-panel" style={{ padding: '1rem 1.5rem', marginBottom: '1.5rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.6rem' }}>
        <span style={{ fontSize: '0.8rem', fontFamily: 'var(--font-cyber)', textTransform: 'uppercase', letterSpacing: '1px', color: 'var(--text-secondary)' }}>
          Severity Breakdown
        </span>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', color: 'var(--text-primary)' }}>
          {total} finding{total !== 1 ? 's' : ''}
        </span>
      </div>
      <div style={{ display: 'flex', height: '8px', borderRadius: '4px', overflow: 'hidden', marginBottom: '0.6rem' }}>
        {segments.map(seg => {
          const pct = total > 0 ? (counts[seg.key] / total) * 100 : 0;
          return pct > 0 ? (
            <div key={seg.key} style={{ width: `${pct}%`, background: seg.color, transition: 'width 0.5s ease' }} />
          ) : null;
        })}
      </div>
      <div style={{ display: 'flex', gap: '1.2rem', flexWrap: 'wrap' }}>
        {segments.map(seg => counts[seg.key] > 0 && (
          <div key={seg.key} style={{ display: 'flex', alignItems: 'center', gap: '5px', fontSize: '0.75rem' }}>
            <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: seg.color }} />
            <span style={{ color: 'var(--text-secondary)' }}>{seg.label}</span>
            <span style={{ fontFamily: 'var(--font-mono)', color: seg.color }}>{counts[seg.key]}</span>
          </div>
        ))}
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
              {audit.grade || 'N/A'} ({audit.score}/100)
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
                {audit.spf.record && <div style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', wordBreak: 'break-all', marginTop: '6px', opacity: 0.8, color: 'var(--text-secondary)' }}>{audit.spf.record}</div>}
              </div>
            )}
            {audit.dmarc && (
              <div style={{ padding: '10px', background: 'rgba(255,255,255,0.02)', borderRadius: '6px', border: '1px solid var(--panel-border)' }}>
                <strong style={{ display: 'block', fontSize: '0.7rem', color: 'var(--text-secondary)', marginBottom: '4px' }}>DMARC POLICY</strong>
                <span style={{ fontSize: '0.85rem', color: audit.dmarc.status === 'Found' ? 'var(--accent-green)' : 'var(--accent-red)' }}>
                  ● {audit.dmarc.status}
                </span>
                {audit.dmarc.record && <div style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', wordBreak: 'break-all', marginTop: '6px', opacity: 0.8, color: 'var(--text-secondary)' }}>{audit.dmarc.record}</div>}
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
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.2rem' }}>
      <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
        {data['Security Score'] != null && (
          <div className="glass-panel" style={{ padding: '10px 16px', borderRadius: '8px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span>🛡️ Domain Security:</span>
            <span style={{ fontWeight: 'bold', color: data['Security Score'] >= 75 ? 'var(--accent-green)' : 'var(--accent-orange)' }}>
              {data['Security Score']}/100
            </span>
          </div>
        )}
        {data['HTTP Status'] && (
          <div className="glass-panel" style={{ padding: '10px 16px', borderRadius: '8px' }}>
            <span>🌐 Status: </span>
            <span style={{ color: String(data['HTTP Status']).startsWith('2') ? 'var(--accent-green)' : 'var(--accent-orange)', fontWeight: 'bold' }}>
              {data['HTTP Status']}
            </span>
          </div>
        )}
      </div>

      <div className="glass-panel" style={{ padding: '1rem', overflowX: 'auto' }}>
        <table className="cyber-table" style={{ width: '100%', borderCollapse: 'collapse' }}>
          <tbody>
            {Object.entries(data).map(([key, value]) => {
              if (value == null || value === '') return null;
              if (Array.isArray(value)) {
                if (value.length === 0) return null;
                return (
                  <tr key={key} style={{ borderBottom: '1px solid var(--panel-border)' }}>
                    <td style={{ padding: '8px', color: 'var(--text-secondary)', fontSize: '0.85rem', width: '35%', verticalAlign: 'top' }}>{key}</td>
                    <td style={{ padding: '8px', fontSize: '0.85rem', fontFamily: 'var(--font-mono)' }}>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                        {value.map((val, idx) => (
                          <div key={idx} style={{ background: 'rgba(255,255,255,0.03)', padding: '2px 8px', borderRadius: '4px', border: '1px solid var(--panel-border)', wordBreak: 'break-all', color: 'var(--accent-blue)' }}>
                            {typeof val === 'object' ? JSON.stringify(val) : String(val)}
                          </div>
                        ))}
                      </div>
                    </td>
                  </tr>
                );
              }
              if (typeof value === 'object') {
                if (Object.keys(value).length === 0) return null;
                return (
                  <tr key={key} style={{ borderBottom: '1px solid var(--panel-border)' }}>
                    <td style={{ padding: '8px', color: 'var(--text-secondary)', fontSize: '0.85rem', width: '35%', verticalAlign: 'top' }}>{key}</td>
                    <td style={{ padding: '8px', fontSize: '0.85rem' }}>
                      <details style={{ width: '100%' }}>
                        <summary style={{ cursor: 'pointer', color: 'var(--accent-blue)', userSelect: 'none' }}>Show Details ({Object.keys(value).length} items)</summary>
                        <table style={{ width: '100%', borderCollapse: 'collapse', marginTop: '6px', background: 'rgba(0,0,0,0.2)' }}>
                          <tbody>
                            {Object.entries(value).map(([subK, subV]) => (
                              <tr key={subK} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                                <td style={{ padding: '4px 8px', color: 'var(--text-secondary)', fontSize: '0.75rem', width: '40%' }}>{subK}</td>
                                <td style={{ padding: '4px 8px', color: 'var(--text-primary)', fontSize: '0.75rem', fontFamily: 'var(--font-mono)', wordBreak: 'break-all' }}>
                                  {typeof subV === 'object' ? JSON.stringify(subV) : String(subV)}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </details>
                    </td>
                  </tr>
                );
              }
              return (
                <tr key={key} style={{ borderBottom: '1px solid var(--panel-border)' }}>
                  <td style={{ padding: '8px', color: 'var(--text-secondary)', fontSize: '0.85rem', width: '35%' }}>{key}</td>
                  <td style={{ padding: '8px', color: 'var(--text-primary)', fontSize: '0.85rem', fontFamily: 'var(--font-mono)', wordBreak: 'break-all' }}>
                    {String(value)}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};

const RenderWebTech = ({ data }) => {
  const score = data['Security Score'];
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {score != null && (
        <div className="glass-panel" style={{ padding: '10px 16px', borderRadius: '8px', display: 'flex', alignItems: 'center', gap: '8px', width: 'fit-content' }}>
          <span>⚙️ Technology Grade:</span>
          <span style={{ fontWeight: 'bold', color: score >= 80 ? 'var(--accent-green)' : 'var(--accent-orange)' }}>{score}/100</span>
        </div>
      )}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))', gap: '1rem' }}>
        {Object.entries(data).map(([key, val]) => {
          if (key === 'Security Score' || key === 'Technology Security Analysis') return null;
          const vals = Array.isArray(val) ? val : [val];
          if (vals.length === 0 || vals[0] === 'Not Detected') return null;
          return (
            <div key={key} className="glass-panel" style={{ padding: '1rem', borderRadius: '10px' }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', textTransform: 'uppercase', marginBottom: '8px' }}>{key.replace(/_/g, ' ')}</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                {vals.map((v, i) => (
                  <span key={i} className="badge badge-blue" style={{ fontSize: '0.8rem', padding: '3px 8px' }}>
                    {typeof v === 'object' ? JSON.stringify(v) : String(v)}
                  </span>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

const RenderSecurityAnalysis = ({ data }) => {
  const score = data.security_score;
  const grade = data.security_grade;
  const vulns = data.vulnerability_scan || data.vulnerabilities || [];
  
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
        {score != null && (
          <div className="glass-panel" style={{ padding: '12px 20px', borderRadius: '8px', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span>🛡️ SECURITY SCORE:</span>
            <span style={{ 
              fontWeight: 'bold', 
              fontSize: '1.2rem',
              color: score >= 80 ? 'var(--accent-green)' : score >= 60 ? 'var(--accent-orange)' : 'var(--accent-red)' 
            }}>
              {grade ? `${grade} (${score}/100)` : `${score}/100`}
            </span>
          </div>
        )}
        {data.waf_detection && (
          <div className="glass-panel" style={{ padding: '12px 20px', borderRadius: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span>WAF Protection: </span>
            <span className="badge badge-purple" style={{ fontSize: '0.85rem' }}>{data.waf_detection}</span>
          </div>
        )}
      </div>

      {data.security_headers && (
        <div className="glass-panel" style={{ padding: '1.25rem', borderRadius: '12px' }}>
          <h4 style={{ margin: '0 0 1rem', fontSize: '0.9rem', fontFamily: 'var(--font-cyber)' }}>HTTP SECURITY HEADERS</h4>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: '1rem' }}>
            {Object.entries(data.security_headers).map(([hdr, status]) => {
              const present = String(status).toLowerCase().includes('found') || String(status).toLowerCase() === 'present' || String(status).toLowerCase() === 'ok' || String(status).toLowerCase().includes('configured');
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
      )}

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

const RenderAdvancedContentScan = ({ data }) => {
  const secrets = data.secrets || [];
  const jsVulns = data.js_vulnerabilities || [];
  const ssrf = data.ssrf_vulnerabilities || [];
  const active = data.active_vulnerabilities || [];
  const chains = data.exploit_chains || [];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '2rem' }}>
      {secrets.length > 0 && (
        <div>
          <h4 style={{ margin: '0 0 0.75rem', fontSize: '0.9rem', fontFamily: 'var(--font-cyber)', color: 'var(--accent-red)' }}>🔑 LEAKED SECRETS & KEYS ({secrets.length})</h4>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            {secrets.map((s, idx) => (
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
          </div>
        </div>
      )}

      {jsVulns.length > 0 && (
        <div>
          <h4 style={{ margin: '0 0 0.75rem', fontSize: '0.9rem', fontFamily: 'var(--font-cyber)', color: 'var(--accent-orange)' }}>⚙️ JAVASCRIPT VULNERABILITIES ({jsVulns.length})</h4>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            {jsVulns.map((jv, idx) => (
              <div key={idx} className="glass-panel" style={{ padding: '1rem', borderLeft: '4px solid var(--accent-orange)' }}>
                <strong style={{ fontSize: '0.85rem', display: 'block', marginBottom: '4px' }}>{jv.type || 'JS Vulnerability'}</strong>
                <p style={{ margin: '0 0 6px', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>{jv.description || jv.detail}</p>
                <div style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', wordBreak: 'break-all', opacity: 0.8 }}>
                  File: {jv.source_url}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {chains.length > 0 && (
        <div>
          <h4 style={{ margin: '0 0 0.75rem', fontSize: '0.9rem', fontFamily: 'var(--font-cyber)', color: 'var(--accent-red)' }}>🕸️ AUTOMATED EXPLOIT CHAINS MAPPED ({chains.length})</h4>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            {chains.map((c, idx) => (
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
          </div>
        </div>
      )}

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
      if (pr.emails) pr.emails.forEach(e => emails.push({ val: e, source: pr.url }));
      if (pr.phones) pr.phones.forEach(p => phones.push({ val: p, source: pr.url }));
      if (pr.social_media) {
        Object.entries(pr.social_media).forEach(([platform, urls]) => {
          const urlList = Array.isArray(urls) ? urls : [urls];
          urlList.forEach(u => socials.push({ platform, val: u, source: pr.url }));
        });
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

const RenderSubdomainTakeover = ({ data }) => {
  const vulns = data.vulnerable_subdomains || [];
  
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

const RenderNmapScan = ({ data }) => {
  const ports = data.port_scan || [];
  const vulns = data.zero_day_vulnerabilities || [];
  
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
  const score = data['SEO Score'] || 80;
  const seoSections = Object.entries(data).filter(([k]) => k !== 'SEO Score');

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {score != null && (
        <div className="glass-panel" style={{ padding: '10px 16px', borderRadius: '8px', display: 'flex', alignItems: 'center', gap: '8px', width: 'fit-content' }}>
          <span>📊 SEO Score:</span>
          <span style={{ fontWeight: 'bold', color: score >= 80 ? 'var(--accent-green)' : 'var(--accent-orange)' }}>{score}/100</span>
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
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '1rem' }}>
        {Object.entries(data).map(([key, value]) => {
          if (key === 'GEO Score') return null;
          return (
            <div key={key} className="glass-panel" style={{ padding: '1rem', borderRadius: '10px' }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', textTransform: 'uppercase', marginBottom: '6px' }}>{key}</div>
              <div style={{ fontSize: '0.85rem', color: 'var(--text-primary)' }}>
                {typeof value === 'object' ? (
                  <div>
                    <div>Status: <span style={{ fontWeight: 'bold', color: value.status === 'Found' ? 'var(--accent-green)' : 'var(--text-secondary)' }}>{value.status}</span></div>
                    {value.files && value.files !== 'None' && <div style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', opacity: 0.8, marginTop: '4px' }}>Files: {value.files}</div>}
                    {value.endpoints && value.endpoints !== 'None' && <div style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', opacity: 0.8, marginTop: '4px' }}>Endpoints: {value.endpoints}</div>}
                  </div>
                ) : String(value)}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

const ModuleResultRenderer = ({ moduleName, moduleData }) => {
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
      content = <RenderSecurityAnalysis data={moduleData} />;
      break;
    case 'Advanced Content Scan':
      content = <RenderAdvancedContentScan data={moduleData} />;
      break;
    case 'Contact Spy':
      content = <RenderContactSpy data={moduleData} />;
      break;
    case 'Subdomain Takeover':
      content = <RenderSubdomainTakeover data={moduleData} />;
      break;
    case 'CloudFlare Bypass':
      content = <RenderCloudFlareBypass data={moduleData} />;
      break;
    case 'Nmap Zero Day Scan':
      content = <RenderNmapScan data={moduleData} />;
      break;
    case 'SEO Analysis':
      content = <RenderSeoAnalysis data={moduleData} />;
      break;
    case 'GEO Analysis':
      content = <RenderGeoAnalysis data={moduleData} />;
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

  useEffect(() => {
    if (domain && domain !== activeDomain) {
      setActiveDomain(domain);
    }
  }, [domain]);

  useEffect(() => {
    const fetchRecent = async () => {
      try {
        const res = await fetch(getApiUrl('/api/recent-scans'));
        if (res.ok) {
          const json = await res.json();
          setRecentScans(json);
        }
      } catch (err) {
        console.error('Error fetching recent scans', err);
      }
    };
    fetchRecent();
  }, [activeDomain]);

  useEffect(() => {
    let interval;
    const fetchResults = async () => {
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
          setError('Waiting for backend acknowledgment...');
        }
      } catch (err) {
        setError('Cannot connect to API server.');
      }
    };

    setLoading(true);
    fetchResults();
    interval = setInterval(fetchResults, 2000);
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

  if (loading && !data) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', flexDirection: 'column', gap: '1rem' }}>
        <div className="status-indicator pending" style={{ width: '20px', height: '20px' }}></div>
        <p style={{ color: 'var(--text-secondary)' }}>Initializing Scan Pipeline for {activeDomain}...</p>
      </div>
    );
  }

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
        if (activeFilter === 'all') return true;
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

      {data && data.results && <SeverityBar results={data.results} />}

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

      {error && !data && (
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
            <ModuleResultRenderer moduleName={moduleName} moduleData={moduleData} />
          </div>
        </div>
      ))}
    </div>
  );
};

export default ResultsPanel;
