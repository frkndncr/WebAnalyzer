import React, { useState, useEffect, useCallback, useRef } from 'react';
import { getApiUrl } from '../config';

/* ═══════════════════════════════════════════════════════════════════
   HELPERS & CONSTANTS
═══════════════════════════════════════════════════════════════════ */

const SEV_CONFIG = {
  CRITICAL: { color: '#ff0055', bg: 'rgba(255,0,85,0.12)', border: 'rgba(255,0,85,0.35)', label: 'CRITICAL', icon: '💀', rank: 4 },
  HIGH:     { color: '#ff9f1c', bg: 'rgba(255,159,28,0.12)', border: 'rgba(255,159,28,0.35)', label: 'HIGH',    icon: '⚠️', rank: 3 },
  MEDIUM:   { color: '#00f2fe', bg: 'rgba(0,242,254,0.08)',  border: 'rgba(0,242,254,0.3)',   label: 'MEDIUM',  icon: '🔶', rank: 2 },
  LOW:      { color: '#39ff14', bg: 'rgba(57,255,20,0.07)',  border: 'rgba(57,255,20,0.25)',  label: 'LOW',     icon: '🔵', rank: 1 },
  INFO:     { color: '#768390', bg: 'rgba(118,131,144,0.07)',border: 'rgba(118,131,144,0.2)', label: 'INFO',    icon: 'ℹ️', rank: 0 },
};
const sev = (s) => SEV_CONFIG[(s || 'INFO').toUpperCase()] || SEV_CONFIG.INFO;

const KILL_CHAIN_PHASES = [
  { id: 'recon',    label: 'Reconnaissance',   icon: '🔍', color: '#00f2fe', desc: 'Passive & active information gathering' },
  { id: 'weapon',   label: 'Weaponization',    icon: '⚗️',  color: '#ff9f1c', desc: 'Exploit construction & payload prep' },
  { id: 'delivery', label: 'Delivery',         icon: '🚀', color: '#ff9f1c', desc: 'Attack vector transmission' },
  { id: 'exploit',  label: 'Exploitation',     icon: '💥', color: '#ff0055', desc: 'Vulnerability trigger & code execution' },
  { id: 'install',  label: 'Installation',     icon: '⬇️',  color: '#ff0055', desc: 'Persistence mechanism deployment' },
  { id: 'c2',       label: 'C2',               icon: '📡', color: '#9b59b6', desc: 'Command & control channel setup' },
  { id: 'action',   label: 'Objectives',       icon: '🏆', color: '#9b59b6', desc: 'Data exfiltration & impact' },
];

const PHASE_MAP = {
  recon:    ['dns', 'subdomain', 'nmap', 'information_gathering', 'web_technologies', 'contact'],
  weapon:   ['xss', 'injection', 'ssrf', 'rce', 'sqli', 'js_vuln'],
  delivery: ['ssrf', 'redirect', 'cors', 'open_redirect'],
  exploit:  ['xss', 'sqli', 'rce', 'command', 'injection', 'ssrf', 'active'],
  install:  ['credential', 'secret', 'api_key', 'token', 'session', 'password', 'archive'],
  c2:       ['header', 'csp', 'clickjack', 'hsts', 'exposed'],
  action:   ['disclosure', 'leak', 'information', 'exfil', 'data', 'takeover'],
};

function classifyToPhase(cveId = '') {
  const id = cveId.toLowerCase();
  for (const [phase, keywords] of Object.entries(PHASE_MAP)) {
    if (keywords.some(k => id.includes(k))) return phase;
  }
  return 'exploit';
}

function buildRoadmap(intel) {
  if (!intel) return [];
  const steps = [];

  // Phase 1: Recon findings
  const mitreRecon = intel.mitre_techniques?.filter(t => t.detected > 0 && (t.id === 'TA0043' || t.id === 'TA0007')) || [];
  if (mitreRecon.length > 0) {
    steps.push({
      phase: 'recon', priority: 'INFO', id: 'step-recon',
      title: 'Surface Mapping Complete',
      description: `Reconnaissance techniques detected across ${mitreRecon.length} MITRE tactic categories. DNS records, subdomains, and technologies exposed.`,
      actions: [
        'Enumerate all open ports and services from scan',
        'Document exposed subdomains and validate each',
        'Map technology stack and software versions',
        'Review DNS zone for misconfigurations',
      ],
      mitre: mitreRecon.map(t => t.id),
      cves: [],
    });
  }

  // Phase 2: Group CVEs by severity, map to roadmap steps
  const critical = (intel.cves || []).filter(c => c.severity === 'CRITICAL');
  const high = (intel.cves || []).filter(c => c.severity === 'HIGH');
  const medium = (intel.cves || []).filter(c => c.severity === 'MEDIUM');
  const low = (intel.cves || []).filter(c => c.severity === 'LOW');

  if (critical.length > 0) {
    steps.push({
      phase: 'exploit', priority: 'CRITICAL', id: 'step-critical',
      title: `Critical Vulnerabilities — Immediate Exploitation Vector`,
      description: `${critical.length} critical severity findings enable direct system compromise without chaining.`,
      actions: critical.slice(0, 5).map(c =>
        `Exploit: ${c.id} — ${c.description?.slice(0, 80) || 'Direct attack vector available'}`
      ),
      mitre: ['TA0001', 'TA0002'],
      cves: critical,
    });
  }

  if (high.length > 0) {
    steps.push({
      phase: 'exploit', priority: 'HIGH', id: 'step-high',
      title: `High-Severity Attack Vectors`,
      description: `${high.length} high-risk findings that can be chained to escalate privileges or exfiltrate data.`,
      actions: high.slice(0, 5).map(c =>
        `Chain: ${c.id} — ${c.description?.slice(0, 80) || 'High-impact attack vector'}`
      ),
      mitre: ['TA0004', 'TA0006'],
      cves: high,
    });
  }

  // Phase 3: Credential / Secret exposure
  const credCves = (intel.cves || []).filter(c =>
    ['secret', 'credential', 'api_key', 'token', 'password', 'auth', 'historical'].some(k =>
      (c.id || '').toLowerCase().includes(k)
    )
  );
  if (credCves.length > 0) {
    steps.push({
      phase: 'install', priority: credCves.some(c => c.severity === 'CRITICAL') ? 'CRITICAL' : 'HIGH',
      id: 'step-creds',
      title: 'Credential & Secret Harvesting',
      description: `${credCves.length} credential/secret exposure(s) found. Enables persistent access without re-exploitation.`,
      actions: [
        'Harvest exposed API keys and rotate compromised credentials',
        'Test leaked credentials against login endpoints and admin panels',
        'Search historical archive snapshots for additional secret leakage',
        'Enumerate OAuth tokens and session identifiers',
      ],
      mitre: ['TA0006', 'TA0003'],
      cves: credCves,
    });
  }

  // Phase 4: IOC-based lateral movement
  const ipIocs = (intel.iocs || []).filter(i => i.type === 'IP Address');
  const domainIocs = (intel.iocs || []).filter(i => i.type === 'Domain');
  if (ipIocs.length > 0 || domainIocs.length > 0) {
    steps.push({
      phase: 'c2', priority: ipIocs.length > 3 ? 'HIGH' : 'MEDIUM', id: 'step-ioc',
      title: 'Infrastructure Pivot & Lateral Movement',
      description: `${ipIocs.length} open IP:Port endpoints and ${domainIocs.length} subdomain targets enable lateral movement.`,
      actions: [
        ...ipIocs.slice(0, 3).map(i => `Probe exposed service: ${i.value} (source: ${i.source})`),
        ...domainIocs.slice(0, 2).map(i => `Target vulnerable subdomain: ${i.value}`),
        'Enumerate internal network segments from compromised host',
      ],
      mitre: ['TA0008', 'TA0007'],
      cves: [],
    });
  }

  // Phase 5: Medium findings
  if (medium.length > 0) {
    steps.push({
      phase: 'weapon', priority: 'MEDIUM', id: 'step-medium',
      title: 'Security Misconfiguration Attack Surface',
      description: `${medium.length} medium-severity misconfigurations available for chaining into higher-impact attacks.`,
      actions: medium.slice(0, 4).map(c =>
        `Leverage: ${c.id} — ${c.description?.slice(0, 80) || 'Misconfiguration exploit opportunity'}`
      ),
      mitre: ['TA0005', 'TA0001'],
      cves: medium,
    });
  }

  // Phase 6: Exploit chains from Attack Path Planner
  const chains = intel.attack_path?.exploit_chains || [];
  if (chains.length > 0) {
    chains.forEach((chain, i) => {
      steps.push({
        phase: 'action',
        priority: (chain.severity || 'MEDIUM').toUpperCase(),
        id: `step-chain-${i}`,
        title: `Chain ${i + 1}: ${chain.name || 'Multi-Stage Exploit'}`,
        description: chain.impact || 'Chained exploit path for maximum impact.',
        actions: chain.steps || [],
        mitre: ['TA0040'],
        cves: [],
        isChain: true,
      });
    });
  }

  // Phase 7: Exfiltration / objectives
  const emailIocs = (intel.iocs || []).filter(i => i.type === 'Email');
  if (emailIocs.length > 0 || low.length > 0) {
    steps.push({
      phase: 'action', priority: 'LOW', id: 'step-action',
      title: 'Data Exfiltration Opportunities',
      description: `${emailIocs.length} email addresses and ${low.length} low-severity findings provide data leakage vectors.`,
      actions: [
        ...emailIocs.slice(0, 3).map(e => `Target contact: ${e.value}`),
        'Exfiltrate sensitive data through discovered endpoints',
        'Document all accessible PII and intellectual property',
      ],
      mitre: ['TA0010', 'TA0040'],
      cves: low,
    });
  }

  // Sort: CRITICAL first, then by phase order
  const phaseOrder = ['recon', 'weapon', 'delivery', 'exploit', 'install', 'c2', 'action'];
  steps.sort((a, b) => {
    const sevDiff = (sev(b.priority).rank || 0) - (sev(a.priority).rank || 0);
    if (sevDiff !== 0) return sevDiff;
    return phaseOrder.indexOf(a.phase) - phaseOrder.indexOf(b.phase);
  });

  return steps;
}

/* ═══════════════════════════════════════════════════════════════════
   SUB-COMPONENTS
═══════════════════════════════════════════════════════════════════ */

/** Animated pulsing threat ring */
const ThreatRing = ({ score, grade }) => {
  const color = score >= 7 ? '#ff0055' : score >= 4 ? '#ff9f1c' : '#39ff14';
  const pct = Math.min(100, score * 10);
  const r = 54, circ = 2 * Math.PI * r;
  const dash = (pct / 100) * circ;
  return (
    <div style={{ position: 'relative', width: 140, height: 140, flexShrink: 0 }}>
      <svg width="140" height="140" style={{ position: 'absolute', top: 0, left: 0 }}>
        <circle cx="70" cy="70" r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="10" />
        <circle
          cx="70" cy="70" r={r} fill="none"
          stroke={color} strokeWidth="10"
          strokeDasharray={`${dash} ${circ}`}
          strokeLinecap="round"
          transform="rotate(-90 70 70)"
          style={{ filter: `drop-shadow(0 0 8px ${color})`, transition: 'stroke-dasharray 1s ease' }}
        />
        {/* outer glow ring */}
        <circle cx="70" cy="70" r="66" fill="none" stroke={color} strokeWidth="1" opacity="0.15">
          <animate attributeName="r" values="66;70;66" dur="2.5s" repeatCount="indefinite" />
          <animate attributeName="opacity" values="0.15;0.05;0.15" dur="2.5s" repeatCount="indefinite" />
        </circle>
      </svg>
      <div style={{
        position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column',
        alignItems: 'center', justifyContent: 'center',
      }}>
        <div style={{ fontFamily: 'var(--font-cyber)', fontSize: 28, color, lineHeight: 1 }}>{score}</div>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-secondary)', marginTop: 2 }}>RISK</div>
        {grade && (
          <div style={{
            fontFamily: 'var(--font-cyber)', fontSize: 14, color,
            border: `1px solid ${color}`, borderRadius: 4, padding: '0 6px', marginTop: 4,
            background: `rgba(${score >= 7 ? '255,0,85' : score >= 4 ? '255,159,28' : '57,255,20'},0.1)`,
          }}>{grade}</div>
        )}
      </div>
    </div>
  );
};

/** MITRE heatmap row */
const MitreHeatmap = ({ techniques }) => {
  if (!techniques || techniques.length === 0) return null;
  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
      {techniques.map(t => {
        const active = t.detected > 0;
        const intensity = Math.min(t.detected, 5);
        const alpha = 0.1 + intensity * 0.15;
        return (
          <div key={t.id} title={`${t.id}: ${t.detected} technique(s) detected`} style={{
            padding: '6px 12px', borderRadius: 8, fontSize: 11,
            fontFamily: 'var(--font-mono)', cursor: 'default',
            background: active ? `rgba(255,159,28,${alpha})` : 'rgba(255,255,255,0.03)',
            border: `1px solid ${active ? `rgba(255,159,28,${0.3 + intensity * 0.1})` : 'rgba(255,255,255,0.08)'}`,
            color: active ? '#ff9f1c' : 'var(--text-secondary)',
            transition: 'all 0.2s',
            boxShadow: active ? `0 0 ${intensity * 4}px rgba(255,159,28,0.3)` : 'none',
          }}>
            <span style={{ opacity: 0.7, marginRight: 4, fontSize: 9 }}>{t.id}</span>
            {t.name}
            {active && <span style={{
              marginLeft: 6, background: 'rgba(255,159,28,0.25)', borderRadius: 4,
              padding: '1px 5px', fontSize: 9, fontWeight: 700,
            }}>{t.detected}</span>}
          </div>
        );
      })}
    </div>
  );
};

/** Roadmap step card */
const RoadmapStep = ({ step, index, isExpanded, onToggle }) => {
  const s = sev(step.priority);
  const phaseConf = KILL_CHAIN_PHASES.find(p => p.id === step.phase) || KILL_CHAIN_PHASES[0];
  return (
    <div
      onClick={onToggle}
      style={{
        borderRadius: 12, marginBottom: 14, cursor: 'pointer',
        border: `1px solid ${isExpanded ? s.border : 'rgba(255,255,255,0.07)'}`,
        background: isExpanded ? s.bg : 'rgba(13,17,23,0.5)',
        transition: 'all 0.25s ease',
        overflow: 'hidden',
        boxShadow: isExpanded ? `0 0 20px ${s.color}22` : 'none',
      }}
    >
      {/* Header row */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 14, padding: '14px 20px',
        borderLeft: `4px solid ${s.color}`,
      }}>
        {/* Step number */}
        <div style={{
          width: 32, height: 32, borderRadius: '50%', flexShrink: 0,
          background: `rgba(${s.color === '#ff0055' ? '255,0,85' : s.color === '#ff9f1c' ? '255,159,28' : '0,242,254'},0.12)`,
          border: `2px solid ${s.color}`,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontFamily: 'var(--font-cyber)', fontSize: 13, color: s.color,
          boxShadow: `0 0 12px ${s.color}44`,
        }}>{index + 1}</div>

        {/* Phase badge */}
        <div style={{
          fontSize: 10, padding: '3px 8px', borderRadius: 6, fontFamily: 'var(--font-mono)',
          background: `${phaseConf.color}18`, color: phaseConf.color,
          border: `1px solid ${phaseConf.color}44`, whiteSpace: 'nowrap', flexShrink: 0,
        }}>
          {phaseConf.icon} {phaseConf.label.toUpperCase()}
        </div>

        {/* Title */}
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{
            fontFamily: 'var(--font-cyber)', fontSize: 13, color: '#fff',
            letterSpacing: 0.5, marginBottom: 2,
            whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
          }}>{step.title}</div>
          {!isExpanded && (
            <div style={{
              fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-secondary)',
              whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
            }}>{step.description}</div>
          )}
        </div>

        {/* Severity badge */}
        <div style={{
          padding: '3px 10px', borderRadius: 6, fontSize: 10, fontWeight: 700,
          fontFamily: 'var(--font-mono)', background: s.bg, color: s.color,
          border: `1px solid ${s.border}`, flexShrink: 0,
        }}>{s.icon} {s.label}</div>

        {/* CVE count */}
        {step.cves.length > 0 && (
          <div style={{
            fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)',
            whiteSpace: 'nowrap', flexShrink: 0,
          }}>
            {step.cves.length} finding{step.cves.length > 1 ? 's' : ''}
          </div>
        )}

        {/* Chevron */}
        <div style={{
          fontSize: 12, color: 'var(--text-secondary)',
          transform: isExpanded ? 'rotate(180deg)' : 'rotate(0)',
          transition: 'transform 0.2s',
          flexShrink: 0,
        }}>▼</div>
      </div>

      {/* Expanded content */}
      {isExpanded && (
        <div style={{ padding: '0 20px 20px 20px', borderTop: `1px solid ${s.border}` }}>
          <p style={{
            fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-secondary)',
            lineHeight: 1.6, margin: '14px 0',
          }}>{step.description}</p>

          {/* MITRE tags */}
          {step.mitre.length > 0 && (
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 14 }}>
              {step.mitre.map(m => (
                <span key={m} style={{
                  fontSize: 10, padding: '2px 8px', borderRadius: 4,
                  background: 'rgba(155,89,182,0.12)', color: '#9b59b6',
                  border: '1px solid rgba(155,89,182,0.3)', fontFamily: 'var(--font-mono)',
                }}>{m}</span>
              ))}
            </div>
          )}

          {/* Action list */}
          {step.actions.length > 0 && (
            <div style={{ marginBottom: step.cves.length > 0 ? 14 : 0 }}>
              <div style={{
                fontFamily: 'var(--font-cyber)', fontSize: 10, color: 'var(--text-secondary)',
                letterSpacing: 1, marginBottom: 8, textTransform: 'uppercase',
              }}>Execution Steps</div>
              {step.actions.map((action, i) => (
                <div key={i} style={{
                  display: 'flex', gap: 10, alignItems: 'flex-start',
                  padding: '6px 0', borderBottom: '1px solid rgba(255,255,255,0.04)',
                }}>
                  <span style={{
                    color: s.color, fontSize: 10, marginTop: 2, flexShrink: 0,
                    fontFamily: 'var(--font-mono)', fontWeight: 700,
                  }}>{String(i + 1).padStart(2, '0')}.</span>
                  <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-primary)', lineHeight: 1.5 }}>
                    {action}
                  </span>
                </div>
              ))}
            </div>
          )}

          {/* CVE details */}
          {step.cves.length > 0 && (
            <div>
              <div style={{
                fontFamily: 'var(--font-cyber)', fontSize: 10, color: 'var(--text-secondary)',
                letterSpacing: 1, marginBottom: 8, textTransform: 'uppercase', marginTop: 4,
              }}>Associated Findings</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {step.cves.slice(0, 6).map((c, i) => {
                  const cs = sev(c.severity);
                  return (
                    <div key={i} style={{
                      display: 'flex', gap: 10, alignItems: 'flex-start',
                      padding: '8px 12px', borderRadius: 8,
                      background: cs.bg, border: `1px solid ${cs.border}`,
                    }}>
                      <span style={{ fontSize: 12, flexShrink: 0 }}>{cs.icon}</span>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{
                          fontFamily: 'var(--font-mono)', fontSize: 11, color: cs.color,
                          fontWeight: 700, marginBottom: 2,
                        }}>{c.id}</div>
                        <div style={{
                          fontFamily: 'var(--font-mono)', fontSize: 11,
                          color: 'var(--text-secondary)', lineHeight: 1.4,
                          wordBreak: 'break-word',
                        }}>{c.description?.slice(0, 140) || '—'}</div>
                      </div>
                      <div style={{
                        fontFamily: 'var(--font-mono)', fontSize: 10, flexShrink: 0,
                        color: cs.color, fontWeight: 700,
                      }}>CVSS {c.cvss}</div>
                    </div>
                  );
                })}
                {step.cves.length > 6 && (
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-secondary)', textAlign: 'center', padding: '4px 0' }}>
                    +{step.cves.length - 6} more findings...
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

/** IOC Table */
const IocTable = ({ iocs }) => {
  if (!iocs || iocs.length === 0) return (
    <div style={{ textAlign: 'center', padding: 30, color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', fontSize: 12 }}>
      No IOCs detected in scan data.
    </div>
  );
  const IOC_ICON = { 'IP Address': '🖥️', 'Domain': '🌐', 'Email': '📧', 'URL': '🔗', 'Hash': '#️⃣' };
  return (
    <div style={{ overflowX: 'auto' }}>
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
        <thead>
          <tr>
            {['Type', 'Value', 'Confidence', 'Source'].map(h => (
              <th key={h} style={{
                padding: '8px 12px', textAlign: 'left', fontFamily: 'var(--font-mono)',
                fontSize: 10, color: 'var(--text-secondary)', textTransform: 'uppercase',
                letterSpacing: 1, borderBottom: '1px solid var(--panel-border)',
                background: 'rgba(0,0,0,0.2)',
              }}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {iocs.map((ioc, i) => (
            <tr key={i}
              style={{ borderBottom: '1px solid rgba(255,255,255,0.04)', cursor: 'default' }}
              onMouseEnter={e => e.currentTarget.style.background = 'rgba(0,242,254,0.03)'}
              onMouseLeave={e => e.currentTarget.style.background = ''}
            >
              <td style={{ padding: '8px 12px', fontFamily: 'var(--font-mono)', color: 'var(--accent-blue)' }}>
                {IOC_ICON[ioc.type] || '🔹'} {ioc.type}
              </td>
              <td style={{ padding: '8px 12px', fontFamily: 'var(--font-mono)', color: 'var(--text-primary)', wordBreak: 'break-all' }}>
                {ioc.value}
              </td>
              <td style={{ padding: '8px 12px' }}>
                <div style={{
                  display: 'inline-flex', alignItems: 'center', gap: 6,
                  fontFamily: 'var(--font-mono)', fontSize: 11,
                  color: ioc.confidence >= 85 ? '#ff0055' : ioc.confidence >= 70 ? '#ff9f1c' : '#39ff14',
                }}>
                  <div style={{
                    width: 40, height: 4, borderRadius: 2,
                    background: 'rgba(255,255,255,0.1)', overflow: 'hidden',
                  }}>
                    <div style={{
                      width: `${ioc.confidence}%`, height: '100%', borderRadius: 2,
                      background: ioc.confidence >= 85 ? '#ff0055' : ioc.confidence >= 70 ? '#ff9f1c' : '#39ff14',
                    }} />
                  </div>
                  {ioc.confidence}%
                </div>
              </td>
              <td style={{ padding: '8px 12px', fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-secondary)' }}>
                {ioc.source}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

/** Kill chain timeline bar */
const KillChainTimeline = ({ intel }) => {
  const allCves = intel?.cves || [];
  const phaseHits = {};
  KILL_CHAIN_PHASES.forEach(p => { phaseHits[p.id] = []; });
  allCves.forEach(c => {
    const phase = classifyToPhase(c.id);
    if (phaseHits[phase]) phaseHits[phase].push(c);
  });
  // recon always active if we have data
  if (intel?.has_data) phaseHits['recon'].push({ id: 'recon-data' });

  return (
    <div style={{ display: 'flex', gap: 4, alignItems: 'stretch', flexWrap: 'wrap' }}>
      {KILL_CHAIN_PHASES.map((phase, i) => {
        const hits = phaseHits[phase.id] || [];
        const active = hits.length > 0;
        const maxSev = hits.reduce((m, c) => Math.max(m, sev(c.severity).rank || 0), 0);
        const color = maxSev >= 4 ? '#ff0055' : maxSev >= 3 ? '#ff9f1c' : phase.color;
        return (
          <div key={phase.id} title={`${phase.label}: ${hits.length} finding(s)`} style={{
            flex: 1, minWidth: 90,
            padding: '12px 10px', borderRadius: 10, textAlign: 'center',
            background: active ? `${color}12` : 'rgba(255,255,255,0.03)',
            border: `1px solid ${active ? `${color}44` : 'rgba(255,255,255,0.07)'}`,
            cursor: 'default', transition: 'all 0.3s',
            boxShadow: active ? `0 0 16px ${color}22` : 'none',
            position: 'relative',
          }}>
            {/* connector line */}
            {i < KILL_CHAIN_PHASES.length - 1 && (
              <div style={{
                position: 'absolute', right: -4, top: '50%', transform: 'translateY(-50%)',
                width: 8, height: 2,
                background: active ? color : 'rgba(255,255,255,0.1)',
                zIndex: 1,
              }} />
            )}
            <div style={{ fontSize: 20, marginBottom: 4 }}>{phase.icon}</div>
            <div style={{
              fontFamily: 'var(--font-cyber)', fontSize: 9, letterSpacing: 0.5,
              color: active ? color : 'var(--text-secondary)', textTransform: 'uppercase',
              marginBottom: 4,
            }}>{phase.label}</div>
            {active ? (
              <div style={{
                fontFamily: 'var(--font-mono)', fontSize: 10, color,
                background: `${color}18`, borderRadius: 4, padding: '1px 6px',
                display: 'inline-block', fontWeight: 700,
              }}>{hits.length}</div>
            ) : (
              <div style={{ fontSize: 10, color: 'rgba(255,255,255,0.2)' }}>—</div>
            )}
          </div>
        );
      })}
    </div>
  );
};

/** SVG Exploit Flowchart */
const ExploitFlowchart = ({ intel, onSelectNode, selectedNode }) => {
  const nodes = intel?.attack_path?.graph?.nodes || [];
  const edges = intel?.attack_path?.graph?.edges || [];

  if (nodes.length === 0) return (
    <div style={{
      textAlign: 'center', padding: '40px 20px',
      color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', fontSize: 12,
    }}>
      <div style={{ fontSize: 36, marginBottom: 12, opacity: 0.4 }}>🗺️</div>
      No attack graph data. Enable Attack Path Planner module in scan settings.
    </div>
  );

  const levels = { target: 0, recon: 1, technology: 1, vulnerability: 2, exploit: 3 };
  const columns = [[], [], [], []];
  nodes.forEach(n => {
    const lvl = levels[n.type] != null ? levels[n.type] : 2;
    columns[Math.min(lvl, 3)].push(n);
  });

  const W = 700, H = 440;
  const positions = {};
  columns.forEach((col, ci) => {
    const x = 80 + ci * 185;
    col.forEach((n, ni) => {
      positions[n.id] = { x, y: (H / (col.length + 1)) * (ni + 1) };
    });
  });

  return (
    <div style={{ background: 'rgba(8,12,20,0.7)', borderRadius: 12, padding: 10, border: '1px solid var(--panel-border)' }}>
      <svg viewBox={`0 0 ${W} ${H}`} style={{ width: '100%', maxHeight: 420 }}>
        <defs>
          <marker id="ap-arrow" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M 0 0 L 10 5 L 0 10 z" fill="rgba(0,242,254,0.6)" />
          </marker>
          <filter id="ap-glow">
            <feGaussianBlur stdDeviation="5" result="blur" />
            <feComposite in="SourceGraphic" in2="blur" operator="over" />
          </filter>
        </defs>

        {/* Edges */}
        {edges.map((edge, idx) => {
          const from = positions[edge.from], to = positions[edge.to];
          if (!from || !to) return null;
          const mid = { x: (from.x + to.x) / 2, y: (from.y + to.y) / 2 };
          return (
            <g key={`e-${idx}`}>
              <line x1={from.x} y1={from.y} x2={to.x} y2={to.y}
                stroke="rgba(0,242,254,0.25)" strokeWidth="2" markerEnd="url(#ap-arrow)" />
              <circle r="3.5" fill="#00f2fe" opacity="0.8" filter="url(#ap-glow)">
                <animateMotion dur={`${2.2 + idx * 0.6}s`} repeatCount="indefinite"
                  path={`M ${from.x} ${from.y} L ${to.x} ${to.y}`} />
              </circle>
              <text x={mid.x} y={mid.y - 7}
                fill="rgba(118,131,144,0.6)" fontSize="8"
                fontFamily="var(--font-mono)" textAnchor="middle">{edge.label}</text>
            </g>
          );
        })}

        {/* Nodes */}
        {nodes.map(node => {
          const pos = positions[node.id];
          if (!pos) return null;
          const sel = selectedNode?.id === node.id;
          const ns = sev(node.severity);
          const nodeColor = ns.color !== '#768390' ? ns.color : node.type === 'target' ? '#00f2fe' : '#39ff14';
          const emoji = node.type === 'target' ? '🎯' : node.type === 'recon' ? '🔍' : node.type === 'technology' ? '⚙️' : ns.rank >= 4 ? '💀' : '⚠️';
          return (
            <g key={node.id} onClick={() => onSelectNode(sel ? null : node)} style={{ cursor: 'pointer' }}>
              {sel && (
                <circle cx={pos.x} cy={pos.y} r="26" fill="none"
                  stroke={nodeColor} strokeWidth="2" strokeDasharray="4 3"
                  opacity="0.5" filter="url(#ap-glow)">
                  <animateTransform attributeName="transform" type="rotate"
                    from={`0 ${pos.x} ${pos.y}`} to={`360 ${pos.x} ${pos.y}`} dur="4s" repeatCount="indefinite" />
                </circle>
              )}
              <circle cx={pos.x} cy={pos.y} r={sel ? 18 : 14}
                fill="#0d1117" stroke={nodeColor} strokeWidth={sel ? 3 : 2}
                filter={sel ? 'url(#ap-glow)' : 'none'}
                style={{ transition: 'r 0.2s' }} />
              <text x={pos.x} y={pos.y + 5} fontSize="12" textAnchor="middle" style={{ pointerEvents: 'none' }}>
                {emoji}
              </text>
              <text x={pos.x} y={pos.y + 32} fill={sel ? '#fff' : 'var(--text-secondary)'}
                fontSize="8.5" fontFamily="var(--font-cyber)" textAnchor="middle"
                fontWeight={sel ? 'bold' : 'normal'}>
                {node.label?.length > 18 ? node.label.slice(0, 16) + '…' : node.label}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
};

/* ═══════════════════════════════════════════════════════════════════
   MAIN COMPONENT
═══════════════════════════════════════════════════════════════════ */

const VIEWS = [
  { id: 'roadmap',   icon: '🗺️', label: 'Attack Roadmap'   },
  { id: 'flowchart', icon: '🔗', label: 'Exploit Graph'    },
  { id: 'iocs',      icon: '📋', label: 'IOC Database'     },
  { id: 'mitre',     icon: '🧩', label: 'MITRE ATT&CK'     },
];

const AttackPathPage = ({ domain, setCurrentDomain }) => {
  const [domainInput, setDomainInput] = useState(domain || '');
  const [recentDomains, setRecentDomains] = useState([]);
  const [intel, setIntel] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [activeView, setActiveView] = useState('roadmap');
  const [expandedSteps, setExpandedSteps] = useState({});
  const [selectedNode, setSelectedNode] = useState(null);

  /* ── fetch recent scans ── */
  useEffect(() => {
    (async () => {
      try {
        const res = await fetch(getApiUrl('/api/recent-scans'));
        if (!res.ok) return;
        const data = await res.json();
        const list = Array.isArray(data) ? data : (data.scans || data.domains || []);
        const domains = list.map(s => (typeof s === 'string' ? s : s.domain || s.target || '')).filter(Boolean);
        setRecentDomains([...new Set(domains)].slice(0, 15));
      } catch (_) {}
    })();
  }, []);

  /* ── load intel ── */
  const loadIntel = useCallback(async (target, isPolling = false, force = false) => {
    if (!target?.trim()) return;
    const clean = target.trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    if (!isPolling) {
      setLoading(true);
      setError('');
      setIntel(null);
      setSelectedNode(null);
      setExpandedSteps({});
    }
    try {
      const url = getApiUrl('/api/threat-intel/' + encodeURIComponent(clean) + (force ? '?force=true' : ''));
      const res = await fetch(url);
      if (!res.ok) throw new Error(`Server responded ${res.status}`);
      const data = await res.json();
      setIntel(data);
      if (setCurrentDomain) setCurrentDomain(clean);

      if (data.is_scanning) {
        setLoading(true);
        setTimeout(() => loadIntel(clean, true, false), 3000);
      } else {
        setLoading(false);
      }
    } catch (e) {
      if (!isPolling) {
        setError(e.message || 'Failed to load threat intelligence');
        setLoading(false);
      } else {
        setTimeout(() => loadIntel(clean, true, false), 5000);
      }
    }
  }, [setCurrentDomain]);

  /* ── auto-fetch on domain prop change ── */
  useEffect(() => {
    if (domain) {
      setDomainInput(domain);
      loadIntel(domain, false, false);
    }
  }, [domain, loadIntel]);

  const roadmap = buildRoadmap(intel);
  const hasData = intel?.has_data;

  const totalFindings = intel ? (intel.cves?.length || 0) : 0;
  const criticalCount = intel?.cves?.filter(c => c.severity === 'CRITICAL').length || 0;
  const highCount = intel?.cves?.filter(c => c.severity === 'HIGH').length || 0;
  const iocCount = intel?.iocs?.length || 0;
  const riskScore = intel?.risk_score || 0;

  const toggleStep = (id) => setExpandedSteps(prev => ({ ...prev, [id]: !prev[id] }));

  return (
    <div className="animate-fade-in" style={{ maxWidth: 1260, margin: '0 auto', padding: '0 4px' }}>
      <style>{`
        @keyframes ap-spin { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }
        @keyframes ap-pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
        @keyframes ap-scanline { 0%{top:-2px} 100%{top:100%} }
      `}</style>

      {/* ── HEADER ── */}
      <div style={{ marginBottom: 28 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginBottom: 8 }}>
          <h1 style={{ margin: 0, fontFamily: 'var(--font-cyber)', fontSize: 28, letterSpacing: 2 }}>
            <span className="text-gradient">ATTACK_PLANNER</span>
          </h1>
          <span style={{
            fontSize: 10, padding: '4px 14px', borderRadius: 4,
            background: 'rgba(255,0,85,0.12)', color: '#ff0055',
            border: '1px solid rgba(255,0,85,0.4)', fontFamily: 'var(--font-mono)',
            fontWeight: 700, letterSpacing: 2, boxShadow: '0 0 12px rgba(255,0,85,0.25)',
          }}>🗺️ THREAT MODEL</span>
        </div>
        <p style={{ margin: 0, fontFamily: 'var(--font-mono)', fontSize: 13, color: 'var(--text-secondary)' }}>
          Automated Attack Path Planner — Aggregates CVEs, IOCs, Secrets & Exploit Chains into a Prioritized Roadmap
        </p>
      </div>

      {/* ── DOMAIN INPUT ── */}
      <form onSubmit={e => { e.preventDefault(); loadIntel(domainInput, false, true); }}
        className="glass-panel" style={{ padding: '18px 20px', borderRadius: 14, marginBottom: 20 }}>
        <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
          <div style={{ flex: 1, minWidth: 240, position: 'relative' }}>
            <input className="input-glass" type="text"
              placeholder="Enter target domain (e.g. example.com)"
              value={domainInput}
              onChange={e => setDomainInput(e.target.value)}
              style={{ width: '100%', paddingLeft: 40, fontFamily: 'var(--font-mono)', fontSize: 14, boxSizing: 'border-box' }}
            />
            <span style={{ position: 'absolute', left: 13, top: '50%', transform: 'translateY(-50%)', fontSize: 16, pointerEvents: 'none' }}>🎯</span>
          </div>
          {recentDomains.length > 0 && (
            <select className="input-glass" value="" onChange={e => { setDomainInput(e.target.value); loadIntel(e.target.value, false, false); }}
              style={{ fontFamily: 'var(--font-mono)', fontSize: 12, minWidth: 180, background: 'rgba(13,17,23,0.6)', color: 'var(--text-secondary)', cursor: 'pointer' }}>
              <option value="">📂 Recent Scans...</option>
              {recentDomains.map(d => (
                <option key={d} value={d} style={{ background: '#0d1117', color: '#f0f6fc' }}>{d}</option>
              ))}
            </select>
          )}
          <button type="submit" className="btn-primary" disabled={loading || !domainInput.trim()}
            style={{ fontFamily: 'var(--font-cyber)', letterSpacing: 2, padding: '12px 28px', fontSize: 12, display: 'flex', alignItems: 'center', gap: 8, whiteSpace: 'nowrap' }}>
            {loading ? (
              <><span style={{ display: 'inline-block', animation: 'ap-spin 1s linear infinite' }}>⟳</span>ANALYZING...</>
            ) : <>⚡ ANALYZE THREATS</>}
          </button>
        </div>

        {/* Quick domain chips */}
        {recentDomains.length > 0 && (
          <div style={{ marginTop: 12, display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-secondary)' }}>Quick:</span>
            {recentDomains.slice(0, 8).map(d => (
              <button key={d} type="button" className="btn-outline" onClick={() => { setDomainInput(d); loadIntel(d, false, false); }}
                style={{ fontFamily: 'var(--font-mono)', fontSize: 10, padding: '3px 10px', borderRadius: 20 }}>
                {d}
              </button>
            ))}
          </div>
        )}
      </form>

      {/* ── ERROR ── */}
      {error && !loading && (
        <div className="glass-panel" style={{ padding: '16px 20px', marginBottom: 20, borderLeft: '3px solid #ff0055', background: 'rgba(255,0,85,0.04)' }}>
          <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
            <span style={{ fontSize: 18 }}>⚠️</span>
            <div>
              <div style={{ fontFamily: 'var(--font-cyber)', fontSize: 11, color: '#ff0055', marginBottom: 2, letterSpacing: 1 }}>CONNECTION ERROR</div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-secondary)' }}>{error}</div>
            </div>
          </div>
        </div>
      )}

      {/* ── LOADING ── */}
      {loading && (
        <div className="glass-panel animate-fade-in" style={{ padding: '60px 20px', textAlign: 'center', marginBottom: 20 }}>
          <div style={{ marginBottom: 20, position: 'relative', width: 80, height: 80, margin: '0 auto 20px' }}>
            <svg width="80" height="80" style={{ animation: 'ap-spin 2s linear infinite' }}>
              <circle cx="40" cy="40" r="32" fill="none" stroke="rgba(0,242,254,0.1)" strokeWidth="6" />
              <path d="M40,8 A32,32 0 0,1 72,40" fill="none" stroke="#00f2fe" strokeWidth="6" strokeLinecap="round" />
            </svg>
            <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 24 }}>🗺️</div>
          </div>
          <div style={{ fontFamily: 'var(--font-cyber)', fontSize: 14, color: 'var(--accent-blue)', letterSpacing: 3, marginBottom: 8 }}>
            {intel?.is_scanning ? 'AUTO-TRIGGERED SECURITY SCAN IN PROGRESS' : 'CONSTRUCTING ATTACK MAP'}
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-secondary)', marginBottom: 20 }}>
            {intel?.is_scanning ? (
              <>
                Running module: <span style={{ color: 'var(--accent-orange)' }}>{intel?.scan_progress?.current_module}</span> ({intel?.scan_progress?.completed}/{intel?.scan_progress?.total})
              </>
            ) : (
              'Aggregating CVEs · Mapping exploit chains · Modeling kill chain...'
            )}
          </div>
          <div style={{ maxWidth: 360, margin: '0 auto', height: 3, borderRadius: 3, background: 'rgba(0,242,254,0.1)', overflow: 'hidden' }}>
            <div style={{
              height: '100%', width: '35%', borderRadius: 3,
              background: 'linear-gradient(90deg, var(--accent-blue), var(--accent-purple))',
              animation: 'ap-scanline 1.1s ease-in-out infinite',
            }} />
          </div>
        </div>
      )}

      {/* ── INITIAL / EMPTY STATE ── */}
      {!intel && !loading && !error && (
        <div className="glass-panel" style={{ padding: '60px 20px', textAlign: 'center' }}>
          <div style={{ fontSize: 56, marginBottom: 16, opacity: 0.6 }}>🗺️</div>
          <div style={{ fontFamily: 'var(--font-cyber)', fontSize: 18, color: 'var(--text-primary)', letterSpacing: 3, marginBottom: 10 }}>
            ATTACK MAP READY
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 13, color: 'var(--text-secondary)', maxWidth: 540, margin: '0 auto', lineHeight: 1.7 }}>
            Enter a domain and click <strong style={{ color: 'var(--accent-blue)' }}>ANALYZE THREATS</strong> to generate a full attack roadmap — CVEs, IOCs, MITRE techniques, exploit chains, and a prioritized attack execution plan.
          </div>
        </div>
      )}

      {/* ── NO DATA ── */}
      {intel && !hasData && !loading && (
        <div className="glass-panel animate-fade-in" style={{ padding: '50px 20px', textAlign: 'center', borderLeft: '3px solid var(--accent-blue)' }}>
          <div style={{ fontSize: 42, marginBottom: 14 }}>🔎</div>
          <div style={{ fontFamily: 'var(--font-cyber)', fontSize: 16, color: 'var(--text-primary)', letterSpacing: 2, marginBottom: 10 }}>
            NO SCAN DATA AVAILABLE
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 13, color: 'var(--text-secondary)', maxWidth: 500, margin: '0 auto' }}>
            No scan results found for <strong style={{ color: 'var(--accent-green)' }}>{intel.domain}</strong>.
            Run a full audit scan first to generate attack path data.
          </div>
        </div>
      )}

      {/* ── MAIN DATA DISPLAY ── */}
      {intel && hasData && !loading && (
        <div className="animate-fade-in">

          {/* ── STATS RIBBON ── */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: 12, marginBottom: 20 }}>
            {[
              { label: 'Total Findings', value: totalFindings, icon: '🔍', color: 'var(--accent-blue)' },
              { label: 'Critical',       value: criticalCount,  icon: '💀', color: '#ff0055' },
              { label: 'High',           value: highCount,      icon: '⚠️', color: '#ff9f1c' },
              { label: 'IOC Count',      value: iocCount,       icon: '📋', color: 'var(--accent-purple)' },
              { label: 'Risk Score',     value: `${riskScore}/10`, icon: '🎯', color: riskScore >= 7 ? '#ff0055' : riskScore >= 4 ? '#ff9f1c' : '#39ff14' },
              { label: 'Roadmap Steps',  value: roadmap.length, icon: '🗺️', color: 'var(--accent-green)' },
            ].map((s, i) => (
              <div key={i} className="glass-panel" style={{
                padding: '14px 16px', borderRadius: 12, textAlign: 'center',
                borderTop: `2px solid ${s.color}`,
              }}>
                <div style={{ fontSize: 20, marginBottom: 4 }}>{s.icon}</div>
                <div style={{ fontFamily: 'var(--font-cyber)', fontSize: 22, color: s.color, letterSpacing: 1 }}>{s.value}</div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: 1, marginTop: 2 }}>{s.label}</div>
              </div>
            ))}
          </div>

          {/* ── THREAT OVERVIEW ROW ── */}
          <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: 16, marginBottom: 20 }}>
            {/* Risk ring */}
            <div className="glass-panel" style={{ padding: 20, borderRadius: 14, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <ThreatRing score={riskScore} grade={intel.security_grade} />
            </div>
            {/* Kill chain timeline */}
            <div className="glass-panel" style={{ padding: 20, borderRadius: 14 }}>
              <div style={{ fontFamily: 'var(--font-cyber)', fontSize: 12, letterSpacing: 1, color: 'var(--text-secondary)', marginBottom: 14, textTransform: 'uppercase' }}>
                🔗 Cyber Kill Chain — Coverage
              </div>
              <KillChainTimeline intel={intel} />
            </div>
          </div>

          {/* ── VIEW TABS ── */}
          <div style={{ display: 'flex', gap: 6, marginBottom: 20, flexWrap: 'wrap', borderBottom: '1px solid var(--panel-border)', paddingBottom: 8 }}>
            {VIEWS.map(v => (
              <button key={v.id}
                className={`btn-outline${activeView === v.id ? ' active' : ''}`}
                onClick={() => setActiveView(v.id)}
                style={{
                  fontFamily: 'var(--font-mono)', fontSize: 12, padding: '9px 20px', borderRadius: 8,
                  display: 'flex', alignItems: 'center', gap: 6,
                  ...(activeView === v.id ? {
                    background: 'rgba(0,242,254,0.1)', borderColor: 'rgba(0,242,254,0.4)',
                    color: 'var(--accent-blue)', boxShadow: '0 0 12px rgba(0,242,254,0.2)',
                  } : {}),
                }}>
                {v.icon} {v.label}
              </button>
            ))}
          </div>

          {/* ── ROADMAP VIEW ── */}
          {activeView === 'roadmap' && (
            <div className="animate-fade-in">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
                <div style={{ fontFamily: 'var(--font-cyber)', fontSize: 14, letterSpacing: 1, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
                  🗺️ Prioritized Attack Execution Roadmap — {roadmap.length} steps
                </div>
                <div style={{ display: 'flex', gap: 8 }}>
                  <button className="btn-outline" onClick={() => {
                    const all = {};
                    roadmap.forEach(s => { all[s.id] = true; });
                    setExpandedSteps(all);
                  }} style={{ fontSize: 11, fontFamily: 'var(--font-mono)', padding: '5px 14px' }}>
                    Expand All
                  </button>
                  <button className="btn-outline" onClick={() => setExpandedSteps({})}
                    style={{ fontSize: 11, fontFamily: 'var(--font-mono)', padding: '5px 14px' }}>
                    Collapse All
                  </button>
                </div>
              </div>

              {roadmap.length === 0 ? (
                <div className="glass-panel" style={{ padding: 40, textAlign: 'center', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', fontSize: 13 }}>
                  No attack vectors could be mapped from the available scan data.
                </div>
              ) : (
                roadmap.map((step, i) => (
                  <RoadmapStep key={step.id} step={step} index={i}
                    isExpanded={!!expandedSteps[step.id]}
                    onToggle={() => toggleStep(step.id)} />
                ))
              )}
            </div>
          )}

          {/* ── FLOWCHART VIEW ── */}
          {activeView === 'flowchart' && (
            <div className="animate-fade-in" style={{ display: 'grid', gridTemplateColumns: '1fr 340px', gap: 20, alignItems: 'start' }}>
              {/* Graph */}
              <div className="glass-panel" style={{ padding: 20, borderRadius: 14 }}>
                <div style={{ fontFamily: 'var(--font-cyber)', fontSize: 12, letterSpacing: 1, color: 'var(--text-secondary)', marginBottom: 14, textTransform: 'uppercase' }}>
                  🔗 Exploit Graph — {intel?.attack_path?.graph?.nodes?.length || 0} Nodes
                </div>
                <ExploitFlowchart intel={intel} selectedNode={selectedNode} onSelectNode={setSelectedNode} />
              </div>

              {/* Side panel */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                {/* Selected node */}
                <div className="glass-panel" style={{
                  padding: 20, borderRadius: 14, minHeight: 180,
                  borderLeft: selectedNode
                    ? `3px solid ${sev(selectedNode.severity).color}`
                    : '1px solid var(--panel-border)',
                }}>
                  <div style={{ fontFamily: 'var(--font-cyber)', fontSize: 10, letterSpacing: 1, color: 'var(--text-secondary)', marginBottom: 14, textTransform: 'uppercase' }}>
                    📦 Node Inspector
                  </div>
                  {selectedNode ? (
                    <div className="animate-fade-in">
                      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
                        <span style={{ fontSize: 22 }}>
                          {selectedNode.type === 'target' ? '🎯' : selectedNode.type === 'recon' ? '🔎' : '⚠️'}
                        </span>
                        <div style={{ fontFamily: 'var(--font-cyber)', fontSize: 14, color: '#fff', fontWeight: 700 }}>
                          {selectedNode.label}
                        </div>
                      </div>
                      <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
                        <span style={{
                          fontSize: 10, padding: '2px 10px', borderRadius: 4, fontWeight: 700,
                          fontFamily: 'var(--font-mono)', ...(() => {
                            const s = sev(selectedNode.severity);
                            return { background: s.bg, color: s.color, border: `1px solid ${s.border}` };
                          })(),
                        }}>{(selectedNode.severity || 'INFO').toUpperCase()}</span>
                        <span style={{ fontSize: 10, padding: '2px 8px', borderRadius: 4, fontFamily: 'var(--font-mono)', background: 'rgba(255,255,255,0.06)', color: 'var(--text-secondary)' }}>
                          {selectedNode.type}
                        </span>
                      </div>
                      <p style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.5, margin: 0 }}>
                        {selectedNode.description || '—'}
                      </p>
                      {selectedNode.mitigation && (
                        <div style={{ marginTop: 12, padding: '10px 12px', borderRadius: 8, background: 'rgba(57,255,20,0.06)', border: '1px solid rgba(57,255,20,0.2)' }}>
                          <div style={{ fontFamily: 'var(--font-cyber)', fontSize: 9, color: '#39ff14', letterSpacing: 1, marginBottom: 4 }}>MITIGATION</div>
                          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-primary)', lineHeight: 1.5 }}>
                            {selectedNode.mitigation}
                          </div>
                        </div>
                      )}
                    </div>
                  ) : (
                    <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-secondary)', textAlign: 'center', padding: '20px 0' }}>
                      ⚡ Click any node to inspect
                    </div>
                  )}
                </div>

                {/* Exploit chains */}
                <div className="glass-panel" style={{ padding: 20, borderRadius: 14 }}>
                  <div style={{ fontFamily: 'var(--font-cyber)', fontSize: 10, letterSpacing: 1, color: 'var(--text-secondary)', marginBottom: 14, textTransform: 'uppercase' }}>
                    🔗 Exploit Chains
                  </div>
                  {(intel?.attack_path?.exploit_chains || []).length > 0 ? (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                      {intel.attack_path.exploit_chains.map((chain, i) => {
                        const cs = sev(chain.severity);
                        return (
                          <div key={i} style={{
                            padding: '12px 14px', borderRadius: 10,
                            background: cs.bg, border: `1px solid ${cs.border}`,
                            borderLeft: `3px solid ${cs.color}`,
                          }}>
                            <div style={{ fontFamily: 'var(--font-cyber)', fontSize: 12, color: '#fff', marginBottom: 4 }}>
                              {chain.name}
                            </div>
                            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: cs.color, marginBottom: 8 }}>
                              IMPACT: {chain.impact}
                            </div>
                            {(chain.steps || []).map((step, si) => (
                              <div key={si} style={{ display: 'flex', gap: 8, alignItems: 'flex-start', marginBottom: 4 }}>
                                <span style={{ color: cs.color, fontSize: 10, fontFamily: 'var(--font-mono)', flexShrink: 0, marginTop: 1 }}>
                                  {si + 1}.
                                </span>
                                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-secondary)', lineHeight: 1.4 }}>
                                  {step}
                                </span>
                              </div>
                            ))}
                          </div>
                        );
                      })}
                    </div>
                  ) : (
                    <div style={{ textAlign: 'center', padding: '20px 0', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', fontSize: 12 }}>
                      No exploit chains in scan data.<br />
                      <span style={{ fontSize: 10 }}>Enable Attack Path Planner module.</span>
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* ── IOC VIEW ── */}
          {activeView === 'iocs' && (
            <div className="animate-fade-in">
              <div style={{ display: 'flex', gap: 12, marginBottom: 16, flexWrap: 'wrap' }}>
                {['IP Address', 'Domain', 'Email', 'URL'].map(type => {
                  const count = (intel?.iocs || []).filter(i => i.type === type).length;
                  return (
                    <div key={type} className="glass-panel" style={{ padding: '10px 18px', borderRadius: 10, textAlign: 'center', minWidth: 100 }}>
                      <div style={{ fontFamily: 'var(--font-cyber)', fontSize: 18, color: 'var(--accent-blue)' }}>{count}</div>
                      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>{type}</div>
                    </div>
                  );
                })}
              </div>
              <div className="glass-panel" style={{ padding: 0, borderRadius: 14, overflow: 'hidden' }}>
                <div style={{ padding: '14px 20px', borderBottom: '1px solid var(--panel-border)' }}>
                  <div style={{ fontFamily: 'var(--font-cyber)', fontSize: 12, letterSpacing: 1, color: 'var(--text-secondary)', textTransform: 'uppercase' }}>
                    📋 Indicators of Compromise — {iocCount} total
                  </div>
                </div>
                <div style={{ padding: '0 4px' }}>
                  <IocTable iocs={intel?.iocs} />
                </div>
              </div>
            </div>
          )}

          {/* ── MITRE VIEW ── */}
          {activeView === 'mitre' && (
            <div className="animate-fade-in">
              <div className="glass-panel" style={{ padding: 24, borderRadius: 14, marginBottom: 16 }}>
                <div style={{ fontFamily: 'var(--font-cyber)', fontSize: 12, letterSpacing: 1, color: 'var(--text-secondary)', marginBottom: 18, textTransform: 'uppercase' }}>
                  🧩 MITRE ATT&CK Coverage Matrix
                </div>
                <MitreHeatmap techniques={intel?.mitre_techniques} />
              </div>

              {/* CVE Summary by severity */}
              <div className="glass-panel" style={{ padding: 24, borderRadius: 14 }}>
                <div style={{ fontFamily: 'var(--font-cyber)', fontSize: 12, letterSpacing: 1, color: 'var(--text-secondary)', marginBottom: 18, textTransform: 'uppercase' }}>
                  📊 Full Finding Inventory — {totalFindings} total
                </div>
                {totalFindings === 0 ? (
                  <div style={{ textAlign: 'center', padding: 30, color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', fontSize: 12 }}>
                    No CVE findings in scan data.
                  </div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                    {/* Severity bar */}
                    <div style={{ display: 'flex', height: 10, borderRadius: 5, overflow: 'hidden', marginBottom: 12 }}>
                      {[['CRITICAL', '#ff0055'], ['HIGH', '#ff9f1c'], ['MEDIUM', '#00f2fe'], ['LOW', '#39ff14']].map(([sv, color]) => {
                        const cnt = (intel?.cves || []).filter(c => c.severity === sv).length;
                        const pct = totalFindings > 0 ? (cnt / totalFindings) * 100 : 0;
                        return pct > 0 ? (
                          <div key={sv} title={`${sv}: ${cnt}`} style={{
                            width: `${pct}%`, background: color,
                            transition: 'width 0.5s',
                          }} />
                        ) : null;
                      })}
                    </div>

                    {(intel?.cves || []).map((c, i) => {
                      const cs = sev(c.severity);
                      return (
                        <div key={i} style={{
                          display: 'flex', gap: 12, alignItems: 'flex-start',
                          padding: '10px 14px', borderRadius: 10,
                          background: 'rgba(255,255,255,0.02)', border: '1px solid rgba(255,255,255,0.06)',
                          borderLeft: `3px solid ${cs.color}`,
                        }}>
                          <div style={{ flexShrink: 0, width: 22, height: 22, borderRadius: 4,
                            background: cs.bg, border: `1px solid ${cs.border}`,
                            display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 11 }}>
                            {cs.icon}
                          </div>
                          <div style={{ flex: 1, minWidth: 0 }}>
                            <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 3 }}>
                              <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: cs.color, fontWeight: 700 }}>{c.id}</span>
                              <span style={{
                                fontSize: 10, padding: '1px 7px', borderRadius: 4,
                                background: cs.bg, color: cs.color, border: `1px solid ${cs.border}`,
                                fontFamily: 'var(--font-mono)',
                              }}>{cs.label}</span>
                              <span style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', marginLeft: 'auto' }}>
                                CVSS {c.cvss}
                              </span>
                            </div>
                            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-secondary)', lineHeight: 1.5, wordBreak: 'break-word' }}>
                              {c.description?.slice(0, 160) || '—'}
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>
          )}

        </div>
      )}
    </div>
  );
};

export default AttackPathPage;
