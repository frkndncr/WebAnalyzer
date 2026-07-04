import React, { useState, useEffect, useRef } from 'react';
import { getApiUrl } from '../config';

/* ── SVG Threat Gauge Component ── */
const ThreatGauge = ({ score, maxScore = 100 }) => {
  const radius = 70;
  const stroke = 10;
  const circumference = 2 * Math.PI * radius;
  const percent = Math.min(score / maxScore, 1);
  const offset = circumference - percent * circumference;

  const getColor = (s) => {
    if (s >= 75) return 'var(--accent-red)';
    if (s >= 50) return 'var(--accent-orange)';
    if (s >= 25) return 'var(--accent-blue)';
    return 'var(--accent-green)';
  };

  const getLabel = (s) => {
    if (s >= 75) return 'CRITICAL';
    if (s >= 50) return 'HIGH';
    if (s >= 25) return 'MEDIUM';
    return 'LOW';
  };

  return (
    <div className="threat-gauge-container" style={{ width: '180px', height: '180px' }}>
      <svg width="180" height="180" viewBox="0 0 180 180">
        <circle cx="90" cy="90" r={radius} fill="none" stroke="rgba(255,255,255,0.04)" strokeWidth={stroke} />
        <circle cx="90" cy="90" r={radius} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth={stroke}
          strokeDasharray={`${circumference * 0.25} ${circumference * 0.75}`}
          transform="rotate(-90 90 90)" />
        <circle cx="90" cy="90" r={radius} fill="none"
          stroke={getColor(score)} strokeWidth={stroke} strokeLinecap="round"
          strokeDasharray={circumference} strokeDashoffset={offset}
          transform="rotate(-90 90 90)"
          style={{ transition: 'stroke-dashoffset 1.5s ease-out, stroke 0.5s', filter: `drop-shadow(0 0 6px ${getColor(score)})` }}
        />
      </svg>
      <div className="threat-gauge-value">
        <div className="score" style={{ color: getColor(score), textShadow: `0 0 15px ${getColor(score)}` }}>{score}</div>
        <div className="label">{getLabel(score)}</div>
      </div>
    </div>
  );
};

/* ── Mini Donut Chart ── */
const DonutChart = ({ data, size = 120 }) => {
  const total = data.reduce((s, d) => s + d.value, 0) || 1;
  const radius = 42;
  const circumference = 2 * Math.PI * radius;
  let cumulative = 0;

  return (
    <svg width={size} height={size} viewBox="0 0 120 120">
      <circle cx="60" cy="60" r={radius} fill="none" stroke="rgba(255,255,255,0.04)" strokeWidth="14" />
      {data.map((d, i) => {
        const pct = d.value / total;
        const dashLen = pct * circumference;
        const dashOff = cumulative * circumference;
        cumulative += pct;
        return (
          <circle key={i} cx="60" cy="60" r={radius} fill="none"
            stroke={d.color} strokeWidth="14" strokeLinecap="butt"
            strokeDasharray={`${dashLen} ${circumference - dashLen}`}
            strokeDashoffset={-dashOff}
            transform="rotate(-90 60 60)"
            style={{ transition: 'all 1s ease-out', filter: `drop-shadow(0 0 3px ${d.color})` }}
          />
        );
      })}
      <text x="60" y="56" textAnchor="middle" fill="var(--text-primary)" fontSize="18" fontFamily="var(--font-cyber)" fontWeight="900">{total}</text>
      <text x="60" y="72" textAnchor="middle" fill="var(--text-secondary)" fontSize="8" fontFamily="var(--font-mono)">FINDINGS</text>
    </svg>
  );
};

/* ── SVG Security Trend Chart ── */
const SecurityTrendChart = ({ trendData }) => {
  if (trendData.length < 2) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '140px', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', fontSize: '0.8rem', border: '1px dashed var(--panel-border)', borderRadius: '6px' }}>
        Awaiting more scan logs to build trend...
      </div>
    );
  }

  const maxVal = Math.max(...trendData.map(d => d.vulns), 5);
  const width = 500;
  const height = 135;
  const paddingX = 35;
  const paddingY = 20;

  const points = trendData.map((d, i) => {
    const x = paddingX + (i / (trendData.length - 1)) * (width - paddingX * 2);
    const y = height - paddingY - (d.vulns / maxVal) * (height - paddingY * 2);
    return { x, y, ...d };
  });

  const linePath = points.map((p, i) => `${i === 0 ? 'M' : 'L'} ${p.x} ${p.y}`).join(' ');
  const areaPath = `${linePath} L ${points[points.length - 1].x} ${height - paddingY} L ${points[0].x} ${height - paddingY} Z`;

  return (
    <div style={{ position: 'relative', width: '100%' }}>
      <svg viewBox={`0 0 ${width} ${height}`} style={{ width: '100%', height: 'auto', display: 'block' }}>
        {/* Grid lines */}
        {[0, 0.5, 1].map((ratio, idx) => {
          const y = paddingY + ratio * (height - paddingY * 2);
          return (
            <line key={idx} x1={paddingX} y1={y} x2={width - paddingX} y2={y} stroke="rgba(255,255,255,0.03)" strokeWidth="1" strokeDasharray="3 3" />
          );
        })}

        {/* Shaded Area */}
        <path d={areaPath} fill="url(#trendGrad)" opacity="0.12" />

        {/* Glow Line */}
        <path d={linePath} fill="none" stroke="var(--accent-red)" strokeWidth="3" strokeLinecap="round" style={{ filter: 'drop-shadow(0 0 4px var(--accent-red))' }} />

        {/* Data points */}
        {points.map((p, idx) => (
          <g key={idx}>
            <circle cx={p.x} cy={p.y} r="4.5" fill="#0d1117" stroke="var(--accent-red)" strokeWidth="3" style={{ filter: 'drop-shadow(0 0 3px var(--accent-red))' }} />
            {/* Tooltip or small text label */}
            <text x={p.x} y={p.y - 10} textAnchor="middle" fill="var(--text-secondary)" fontSize="8.5" fontFamily="var(--font-mono)">
              {p.vulns}
            </text>
          </g>
        ))}

        {/* Gradients */}
        <defs>
          <linearGradient id="trendGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="var(--accent-red)" />
            <stop offset="100%" stopColor="var(--accent-red)" stopOpacity="0" />
          </linearGradient>
        </defs>
      </svg>
      {/* X Axis Labels */}
      <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0 10px', marginTop: '6px' }}>
        {trendData.map((d, idx) => (
          <span key={idx} style={{ fontSize: '0.62rem', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', maxWidth: '55px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', textAlign: 'center' }} title={d.domain}>
            {d.domain.split('.')[0]}
          </span>
        ))}
      </div>
    </div>
  );
};

const DashboardOverview = ({ setActiveTab, setCurrentDomain }) => {
  const [stats, setStats] = useState({ total_jobs: 0, total_domains: 0, total_vulnerabilities: 0, status: 'connecting...' });
  const [vulnStats, setVulnStats] = useState({ critical: 0, high: 0, medium: 0, low: 0, total: 0 });
  const [recentScans, setRecentScans] = useState([]);
  const [systemHealth, setSystemHealth] = useState(null);
  const [activeScansDetail, setActiveScansDetail] = useState([]);
  const [recentAlerts, setRecentAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [bottomTab, setBottomTab] = useState('logs');
  const feedRef = useRef(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [statsR, recentR, vulnR, healthR, activeScansR, alertsR] = await Promise.allSettled([
          fetch(getApiUrl('/api/stats')),
          fetch(getApiUrl('/api/recent-scans')),
          fetch(getApiUrl('/api/vulnerability-stats')),
          fetch(getApiUrl('/api/system-health')),
          fetch(getApiUrl('/api/active-scans')),
          fetch(getApiUrl('/api/recent-alerts')),
        ]);
        if (statsR.status === 'fulfilled' && statsR.value.ok) setStats(await statsR.value.json());
        if (recentR.status === 'fulfilled' && recentR.value.ok) setRecentScans(await recentR.value.json());
        if (vulnR.status === 'fulfilled' && vulnR.value.ok) setVulnStats(await vulnR.value.json());
        if (healthR.status === 'fulfilled' && healthR.value.ok) setSystemHealth(await healthR.value.json());
        if (activeScansR.status === 'fulfilled' && activeScansR.value.ok) setActiveScansDetail(await activeScansR.value.json());
        if (alertsR.status === 'fulfilled' && alertsR.value.ok) setRecentAlerts(await alertsR.value.json());
      } catch (err) {
        console.error('Dashboard fetch error', err);
      } finally {
        setLoading(false);
      }
    };

    fetchData();

    // Poll active scans and health metrics every 4 seconds to keep progress updated
    const pollInterval = setInterval(async () => {
      try {
        const [healthRes, activeRes] = await Promise.all([
          fetch(getApiUrl('/api/system-health')),
          fetch(getApiUrl('/api/active-scans'))
        ]);
        if (healthRes.ok) setSystemHealth(await healthRes.json());
        if (activeRes.ok) setActiveScansDetail(await activeRes.json());
      } catch (e) {
        console.warn('Dashboard polling failed', e);
      }
    }, 4000);

    return () => clearInterval(pollInterval);
  }, []);

  useEffect(() => {
    if (feedRef.current) feedRef.current.scrollTop = feedRef.current.scrollHeight;
  }, [recentAlerts]);

  const viewScan = (domain) => {
    setCurrentDomain(domain);
    setActiveTab('results');
  };

  const getGradeColor = (grade) => {
    if (!grade) return 'var(--text-secondary)';
    const g = grade.toUpperCase();
    if (g.startsWith('A')) return 'var(--accent-green)';
    if (g.startsWith('B') || g.startsWith('C')) return 'var(--accent-blue)';
    if (g.startsWith('D')) return 'var(--accent-orange)';
    return 'var(--accent-red)';
  };

  const threatScore = Math.min(Math.round((vulnStats.critical * 25 + vulnStats.high * 15 + vulnStats.medium * 5 + vulnStats.low * 1)), 100);

  // Chronological vulnerability trend data
  const trendData = [...recentScans]
    .reverse()
    .slice(-8)
    .map(s => ({
      domain: s.domain,
      vulns: s.vulnerabilities || 0,
      score: s.score || 0
    }));

  // Top vulnerable targets sorted by vulnerability count
  const topTargets = [...recentScans]
    .sort((a, b) => (b.vulnerabilities || 0) - (a.vulnerabilities || 0))
    .slice(0, 10);

  return (
    <div className="animate-fade-in" style={{ maxWidth: '1200px', margin: '0 auto' }}>
      {/* ── Header ── */}
      <div style={{ marginBottom: '2rem', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end' }}>
        <div>
          <h2 style={{ fontSize: '1.8rem', marginBottom: '0.3rem', display: 'flex', alignItems: 'center', gap: '12px' }}>
            <span className="text-gradient">OPERATIONS_CENTER</span>
            <span className="badge badge-blue">LIVE</span>
          </h2>
          <p style={{ color: 'var(--text-secondary)', fontSize: '0.85rem', fontFamily: 'var(--font-mono)' }}>
            WebAnalyzer Central Intelligence & Security Monitoring Console
          </p>
        </div>
        <div style={{ display: 'flex', gap: '0.8rem' }}>
          <button className="btn-primary" onClick={() => setActiveTab('new_scan')}>⚡ NEW SCAN</button>
          <button className="btn-outline" onClick={() => setActiveTab('threat_intel')}>🛡️ THREAT INTEL</button>
        </div>
      </div>

      {/* ── Top Stats Row ── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem', marginBottom: '2rem' }} className="stagger-children">
        {[
          { label: 'DOMAINS_SCANNED', value: stats.total_domains, color: 'var(--accent-blue)', icon: '🌐' },
          { label: 'VULNERABILITIES', value: vulnStats.total || stats.total_vulnerabilities, color: 'var(--accent-red)', icon: '⚠️' },
          { label: 'CRITICAL_FINDINGS', value: vulnStats.critical, color: 'var(--accent-red)', icon: '🔴' },
          { label: 'HIGH_RISK', value: vulnStats.high, color: 'var(--accent-orange)', icon: '🟠' },
          { label: 'ACTIVE_SCANS', value: activeScansDetail.length, color: 'var(--accent-green)', icon: '📡' },
          { label: 'DB_STATUS', value: stats.status === 'connected' ? 'ONLINE' : 'LOCAL', color: stats.status === 'connected' ? 'var(--accent-green)' : 'var(--accent-orange)', icon: '💾' },
        ].map((s, i) => (
          <div key={i} className="glass-panel stat-card animate-fade-in" style={{ borderLeft: `3px solid ${s.color}` }}>
            <div className="stat-label">{s.icon} {s.label}</div>
            <div className="stat-value" style={{ color: s.color, textShadow: `0 0 10px ${s.color}40` }}>
              {s.value}
            </div>
          </div>
        ))}
      </div>

      {/* ── Grid Row 1: Threat Assessment & Live Event Feed ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem', marginBottom: '1.5rem' }}>
        {/* Left: Threat Gauge + Vuln Distribution */}
        <div className="glass-panel" style={{ padding: '1.5rem' }}>
          <h3 style={{ fontSize: '0.9rem', marginBottom: '1.5rem', display: 'flex', alignItems: 'center', gap: '8px', fontFamily: 'var(--font-cyber)' }}>
            🎯 THREAT_ASSESSMENT
          </h3>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-around' }}>
            <ThreatGauge score={threatScore} />
            <div>
              <DonutChart data={[
                { value: vulnStats.critical || 0, color: 'var(--accent-red)' },
                { value: vulnStats.high || 0, color: 'var(--accent-orange)' },
                { value: vulnStats.medium || 0, color: 'var(--accent-blue)' },
                { value: vulnStats.low || 0, color: 'var(--text-secondary)' },
              ]} />
              <div style={{ display: 'flex', flexDirection: 'column', gap: '4px', marginTop: '0.8rem' }}>
                {[
                  { label: 'Critical', color: 'var(--accent-red)', val: vulnStats.critical },
                  { label: 'High', color: 'var(--accent-orange)', val: vulnStats.high },
                  { label: 'Medium', color: 'var(--accent-blue)', val: vulnStats.medium },
                  { label: 'Low', color: 'var(--text-secondary)', val: vulnStats.low },
                ].map((item, i) => (
                  <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.72rem', fontFamily: 'var(--font-mono)' }}>
                    <div style={{ width: '8px', height: '8px', borderRadius: '2px', background: item.color, boxShadow: `0 0 4px ${item.color}` }} />
                    <span style={{ color: 'var(--text-secondary)' }}>{item.label}</span>
                    <span style={{ marginLeft: 'auto', fontWeight: 700, color: item.color }}>{item.val}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Right: Live Event Feed (Real Alerts Terminal) */}
        <div className="glass-panel" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column' }}>
          <h3 style={{ fontSize: '0.9rem', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '8px', fontFamily: 'var(--font-cyber)' }}>
            <span className="status-indicator active" style={{ width: '8px', height: '8px' }}></span>
            LIVE_SECURITY_EVENT_FEED
          </h3>
          <div className="terminal-feed" ref={feedRef} style={{ flex: 1, maxHeight: '200px', overflowY: 'auto' }}>
            {recentAlerts.map((alert, i) => (
              <div key={i} className="terminal-line" style={{ display: 'flex', gap: '8px', fontSize: '0.75rem', marginBottom: '4px', flexWrap: 'wrap' }}>
                <span className="terminal-time" style={{ color: 'var(--text-secondary)' }}>[{new Date().toISOString().slice(11, 19)}]</span>
                <span style={{
                  color: alert.severity === 'CRITICAL' ? 'var(--accent-red)' : alert.severity === 'HIGH' ? 'var(--accent-orange)' : 'var(--accent-blue)',
                  fontWeight: 'bold', minWidth: '75px'
                }}>[{alert.severity}]</span>
                <span style={{ color: 'var(--accent-blue)', fontWeight: 'bold' }}>{alert.domain}</span>
                <span className="terminal-message" style={{ color: 'var(--text-primary)' }}>{alert.title} · {alert.description}</span>
              </div>
            ))}
            {recentAlerts.length === 0 && (
              <div style={{ color: 'var(--text-secondary)', fontStyle: 'italic', padding: '20px 10px', fontSize: '0.8rem', fontFamily: 'var(--font-mono)' }}>
                No security alerts found in logs database. Scan targets to populate alerts feed.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ── Grid Row 2: Trend Timeline & Active Scan Details ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem', marginBottom: '2rem' }}>
        {/* Left: Trend Timeline */}
        <div className="glass-panel" style={{ padding: '1.5rem' }}>
          <h3 style={{ fontSize: '0.9rem', marginBottom: '1.2rem', display: 'flex', alignItems: 'center', gap: '8px', fontFamily: 'var(--font-cyber)' }}>
            📈 VULNERABILITY_TRENDS
          </h3>
          <SecurityTrendChart trendData={trendData} />
        </div>

        {/* Right: Active Scans Engine Details */}
        <div className="glass-panel" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column' }}>
          <h3 style={{ fontSize: '0.9rem', marginBottom: '1.2rem', display: 'flex', alignItems: 'center', gap: '8px', fontFamily: 'var(--font-cyber)' }}>
            📡 ACTIVE_SCAN_ENGINE_DETAILS
          </h3>
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '0.8rem', maxHeight: '180px', overflowY: 'auto' }}>
            {activeScansDetail.map((scan) => {
              const percent = Math.round((scan.completed / scan.total) * 100);
              return (
                <div key={scan.domain} style={{ padding: '0.8rem', background: 'rgba(0, 242, 254, 0.03)', border: '1px solid rgba(0, 242, 254, 0.12)', borderRadius: '6px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px', fontSize: '0.8rem', fontFamily: 'var(--font-mono)' }}>
                    <span style={{ color: 'var(--text-primary)', fontWeight: 'bold' }}>🛰️ {scan.domain}</span>
                    <span style={{ color: 'var(--accent-blue)', fontWeight: 'bold' }}>{percent}%</span>
                  </div>
                  <div style={{ width: '100%', height: '5px', background: 'rgba(255,255,255,0.06)', borderRadius: '3px', overflow: 'hidden', marginBottom: '6px' }}>
                    <div style={{ width: `${percent}%`, height: '100%', background: 'linear-gradient(90deg, var(--accent-blue), var(--accent-purple))', transition: 'width 0.5s ease-out' }}></div>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.68rem', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
                    <span>Running: <strong style={{ color: 'var(--accent-orange)' }}>{scan.current_module}</strong></span>
                    <span>{scan.completed}/{scan.total} modules</span>
                  </div>
                </div>
              );
            })}
            {activeScansDetail.length === 0 && (
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', flex: 1, padding: '1rem', border: '1px dashed var(--panel-border)', borderRadius: '8px', textAlign: 'center' }}>
                <div style={{ fontSize: '2rem', marginBottom: '0.6rem', animation: 'ap-pulse 2s infinite' }}>🛰️</div>
                <div style={{ fontFamily: 'var(--font-cyber)', fontSize: '0.8rem', color: 'var(--accent-green)', letterSpacing: '2px', marginBottom: '3px' }}>SCAN_ENGINE_STANDBY</div>
                <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.7rem', color: 'var(--text-secondary)', maxWidth: '280px' }}>
                  No active scans running in background. Engine is idle.
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ── Bottom Row: Logs/Risks Tab & System Health ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '1.5rem' }}>
        {/* Left: Tabbed Logs / Vulnerable Targets list */}
        <div className="glass-panel" style={{ padding: '1.5rem' }}>
          <div style={{ display: 'flex', gap: '1rem', borderBottom: '1px solid var(--panel-border)', paddingBottom: '10px', marginBottom: '1.2rem' }}>
            <button
              className={`btn-outline ${bottomTab === 'logs' ? 'active' : ''}`}
              onClick={() => setBottomTab('logs')}
              style={{
                fontFamily: 'var(--font-cyber)', fontSize: '0.75rem', padding: '5px 15px', borderRadius: '4px',
                background: bottomTab === 'logs' ? 'rgba(0, 242, 254, 0.08)' : 'transparent',
                borderColor: bottomTab === 'logs' ? 'var(--accent-blue)' : 'var(--panel-border)',
                color: bottomTab === 'logs' ? 'var(--accent-blue)' : 'var(--text-secondary)',
                cursor: 'pointer'
              }}
            >
              📡 RECENT_ANALYSIS_LOGS
            </button>
            <button
              className={`btn-outline ${bottomTab === 'risks' ? 'active' : ''}`}
              onClick={() => setBottomTab('risks')}
              style={{
                fontFamily: 'var(--font-cyber)', fontSize: '0.75rem', padding: '5px 15px', borderRadius: '4px',
                background: bottomTab === 'risks' ? 'rgba(255, 0, 85, 0.08)' : 'transparent',
                borderColor: bottomTab === 'risks' ? 'var(--accent-red)' : 'var(--panel-border)',
                color: bottomTab === 'risks' ? 'var(--accent-red)' : 'var(--text-secondary)',
                cursor: 'pointer'
              }}
            >
              💀 TOP_RISK_TARGETS
            </button>
          </div>

          {loading ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}>
              <div className="status-indicator pending" style={{ margin: 0 }}></div>
              Loading scans registry...
            </div>
          ) : bottomTab === 'logs' ? (
            recentScans.length === 0 ? (
              <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-secondary)', border: '1px dashed var(--panel-border)', borderRadius: '8px', fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}>
                No scan logs found. Launch a new scan to populate the database.
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem', maxHeight: '280px', overflowY: 'auto', paddingRight: '4px' }}>
                {recentScans.slice(0, 10).map((scan, idx) => (
                  <div key={scan.domain} style={{
                    display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                    padding: '0.7rem 1rem', background: 'rgba(5, 7, 10, 0.5)',
                    border: '1px solid var(--panel-border)', borderRadius: '8px',
                    transition: 'all 0.2s', cursor: 'pointer',
                    animationDelay: `${idx * 50}ms`,
                  }}
                  className="animate-fade-in"
                  onClick={() => viewScan(scan.domain)}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                      <div style={{
                        width: '32px', height: '32px', borderRadius: '8px',
                        background: `rgba(0, 242, 254, 0.08)`, border: '1px solid rgba(0, 242, 254, 0.15)',
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                        fontSize: '0.8rem', fontFamily: 'var(--font-cyber)', color: 'var(--accent-blue)',
                      }}>
                        {(idx + 1).toString().padStart(2, '0')}
                      </div>
                      <div>
                        <strong style={{ display: 'block', fontSize: '0.88rem', color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>{scan.domain}</strong>
                        <span style={{ fontSize: '0.68rem', color: 'var(--text-secondary)' }}>
                          {new Date(scan.scan_date).toLocaleString()}
                        </span>
                      </div>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                      {scan.vulnerabilities > 0 && (
                        <span className="badge badge-red" style={{ fontSize: '0.65rem' }}>
                          {scan.vulnerabilities} VULNS
                        </span>
                      )}
                      {scan.grade && (
                        <span style={{
                          fontFamily: 'var(--font-cyber)', fontSize: '0.85rem', fontWeight: 'bold',
                          color: getGradeColor(scan.grade), border: `1px solid ${getGradeColor(scan.grade)}`,
                          padding: '2px 10px', borderRadius: '6px', background: 'rgba(255, 255, 255, 0.02)',
                          textShadow: `0 0 5px ${getGradeColor(scan.grade)}`,
                        }}>
                          {scan.grade}
                        </span>
                      )}
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--text-secondary)" strokeWidth="2"><path d="M9 18l6-6-6-6"/></svg>
                    </div>
                  </div>
                ))}
              </div>
            )
          ) : (
            topTargets.length === 0 ? (
              <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-secondary)', border: '1px dashed var(--panel-border)', borderRadius: '8px', fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}>
                No targets mapped. Run a scan to build risk indices.
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem', maxHeight: '280px', overflowY: 'auto', paddingRight: '4px' }}>
                {topTargets.map((scan, idx) => (
                  <div key={scan.domain} style={{
                    display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                    padding: '0.7rem 1rem', background: 'rgba(5, 7, 10, 0.5)',
                    border: '1px solid var(--panel-border)', borderRadius: '8px',
                    transition: 'all 0.2s', cursor: 'pointer',
                  }}
                  className="animate-fade-in"
                  onClick={() => viewScan(scan.domain)}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                      <div style={{
                        width: '32px', height: '32px', borderRadius: '8px',
                        background: `rgba(255, 0, 85, 0.08)`, border: '1px solid rgba(255, 0, 85, 0.15)',
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                        fontSize: '0.8rem', fontFamily: 'var(--font-cyber)', color: 'var(--accent-red)',
                      }}>
                        🎯
                      </div>
                      <div>
                        <strong style={{ display: 'block', fontSize: '0.88rem', color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>{scan.domain}</strong>
                        <span style={{ fontSize: '0.68rem', color: 'var(--text-secondary)' }}>
                          Risk Score: <strong style={{ color: 'var(--accent-orange)' }}>{scan.score || 0}/100</strong>
                        </span>
                      </div>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                      <span className="badge badge-red" style={{ fontSize: '0.65rem', background: 'rgba(255,0,85,0.15)', color: '#ff0055', border: '1px solid rgba(255,0,85,0.3)' }}>
                        {scan.vulnerabilities || 0} SEVERE CRITICALS
                      </span>
                      {scan.grade && (
                        <span style={{
                          fontFamily: 'var(--font-cyber)', fontSize: '0.85rem', fontWeight: 'bold',
                          color: getGradeColor(scan.grade), border: `1px solid ${getGradeColor(scan.grade)}`,
                          padding: '2px 10px', borderRadius: '6px', background: 'rgba(255, 255, 255, 0.02)',
                          textShadow: `0 0 5px ${getGradeColor(scan.grade)}`,
                        }}>
                          {scan.grade}
                        </span>
                      )}
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--text-secondary)" strokeWidth="2"><path d="M9 18l6-6-6-6"/></svg>
                    </div>
                  </div>
                ))}
              </div>
            )
          )}
        </div>

        {/* Right: System Health Monitor */}
        <div className="glass-panel" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column' }}>
          <h3 style={{ fontSize: '0.9rem', marginBottom: '1.2rem', display: 'flex', alignItems: 'center', gap: '8px', fontFamily: 'var(--font-cyber)' }}>
            ⚙️ SYSTEM_HEALTH
          </h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.7rem', flex: 1 }}>
            {[
              { label: 'API Server', status: systemHealth ? 'ONLINE' : 'OFFLINE', ok: !!systemHealth },
              { label: 'Database', status: stats.status === 'connected' ? 'CONNECTED' : 'STANDALONE', ok: stats.status === 'connected' },
              { label: 'Scan Engine', status: 'READY', ok: true },
              { label: 'Pattern DB', status: '40+ RULES', ok: true },
              { label: 'Nuclei CVE', status: '10K+ TEMPLATES', ok: true },
            ].map((item, i) => (
              <div key={i} style={{
                display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                padding: '0.6rem 0.8rem', background: 'rgba(5, 7, 10, 0.4)',
                borderRadius: '6px', border: '1px solid var(--panel-border)',
                fontSize: '0.75rem', fontFamily: 'var(--font-mono)',
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <div className={`status-indicator ${item.ok ? 'active' : 'error'}`} style={{ width: '7px', height: '7px', margin: 0 }} />
                  <span style={{ color: 'var(--text-secondary)' }}>{item.label}</span>
                </div>
                <span style={{ color: item.ok ? 'var(--accent-green)' : 'var(--accent-red)', fontWeight: 600, fontSize: '0.68rem' }}>
                  {item.status}
                </span>
              </div>
            ))}
          </div>

          {systemHealth && (
            <div style={{ marginTop: '1rem', padding: '0.8rem', background: 'rgba(0,242,254,0.03)', borderRadius: '6px', border: '1px solid rgba(0,242,254,0.08)', fontSize: '0.7rem', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
              <div>Python: {systemHealth.python_version}</div>
              <div>Platform: {systemHealth.platform}</div>
              <div>Version: {systemHealth.version}</div>
            </div>
          )}

          <div style={{ marginTop: 'auto', paddingTop: '1rem', display: 'flex', gap: '0.5rem' }}>
            <button className="btn-primary" style={{ flex: 1, fontSize: '0.7rem', padding: '0.5rem' }} onClick={() => setActiveTab('new_scan')}>
              🚀 LAUNCH SCAN
            </button>
            <button className="btn-outline" style={{ flex: 1, fontSize: '0.7rem', padding: '0.5rem' }} onClick={() => setActiveTab('advanced_scanner')}>
              🔬 DEEP SCAN
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default DashboardOverview;
