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

/* ── Live Terminal Feed ── */
const FEED_MESSAGES = [
  '> SYSTEM_BOOT: WebAnalyzer core initialized...',
  '> DNS_RESOLVER: Upstream resolvers connected',
  '> PATTERN_DB: 40+ secret patterns loaded',
  '> WAF_DETECT: 9 WAF signatures active',
  '> CRAWL_ENGINE: ThreadPool(15) standing by',
  '> SSL_CHECK: Certificate validator online',
  '> EXPLOIT_DB: Attack chain builder ready',
  '> NMAP_CORE: Port scanner interface ready',
  '> NUCLEI: 10K+ CVE templates loaded',
  '> HEADLESS: Playwright chromium ready',
];

const DashboardOverview = ({ setActiveTab, setCurrentDomain }) => {
  const [stats, setStats] = useState({ total_jobs: 0, total_domains: 0, total_vulnerabilities: 0, status: 'connecting...' });
  const [vulnStats, setVulnStats] = useState({ critical: 0, high: 0, medium: 0, low: 0, total: 0 });
  const [recentScans, setRecentScans] = useState([]);
  const [systemHealth, setSystemHealth] = useState(null);
  const [loading, setLoading] = useState(true);
  const [feedLines, setFeedLines] = useState([]);
  const feedRef = useRef(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [statsR, recentR, vulnR, healthR] = await Promise.allSettled([
          fetch(getApiUrl('/api/stats')),
          fetch(getApiUrl('/api/recent-scans')),
          fetch(getApiUrl('/api/vulnerability-stats')),
          fetch(getApiUrl('/api/system-health')),
        ]);
        if (statsR.status === 'fulfilled' && statsR.value.ok) setStats(await statsR.value.json());
        if (recentR.status === 'fulfilled' && recentR.value.ok) setRecentScans(await recentR.value.json());
        if (vulnR.status === 'fulfilled' && vulnR.value.ok) setVulnStats(await vulnR.value.json());
        if (healthR.status === 'fulfilled' && healthR.value.ok) setSystemHealth(await healthR.value.json());
      } catch (err) {
        console.error('Dashboard fetch error', err);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  // Simulated live terminal feed
  useEffect(() => {
    let idx = 0;
    const interval = setInterval(() => {
      if (idx < FEED_MESSAGES.length) {
        setFeedLines(prev => [...prev, { time: new Date().toISOString().slice(11, 19), msg: FEED_MESSAGES[idx] }]);
        idx++;
      }
    }, 800);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    if (feedRef.current) feedRef.current.scrollTop = feedRef.current.scrollHeight;
  }, [feedLines]);

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
          { label: 'ACTIVE_SCANS', value: systemHealth?.active_scans || 0, color: 'var(--accent-green)', icon: '📡' },
          { label: 'DB_STATUS', value: stats.status === 'connected' ? 'ONLINE' : 'LOCAL', color: stats.status === 'connected' ? 'var(--accent-green)' : 'var(--accent-orange)', icon: '💾' },
        ].map((s, i) => (
          <div key={i} className="glass-panel stat-card animate-fade-in" style={{ borderLeft: `3px solid ${s.color}` }}>
            <div className="stat-label">{s.icon} {s.label}</div>
            <div className="stat-value" style={{ color: s.color, textShadow: `0 0 10px ${s.color}40` }}>
              {typeof s.value === 'number' ? s.value : s.value}
            </div>
          </div>
        ))}
      </div>

      {/* ── Main Content Grid ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem', marginBottom: '2rem' }}>

        {/* ── Left: Threat Gauge + Vuln Distribution ── */}
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

        {/* ── Right: Live Terminal Feed ── */}
        <div className="glass-panel" style={{ padding: '1.5rem' }}>
          <h3 style={{ fontSize: '0.9rem', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '8px', fontFamily: 'var(--font-cyber)' }}>
            <span className="status-indicator active" style={{ width: '8px', height: '8px' }}></span>
            LIVE_SYSTEM_FEED
          </h3>
          <div className="terminal-feed" ref={feedRef}>
            {feedLines.map((line, i) => (
              <div key={i} className="terminal-line">
                <span className="terminal-time">[{line.time}]</span>
                <span className="terminal-prefix">$</span>
                <span className="terminal-message">{line.msg}</span>
              </div>
            ))}
            {feedLines.length === 0 && (
              <div style={{ color: 'var(--text-secondary)', fontStyle: 'italic' }}>Initializing system feed...</div>
            )}
          </div>
        </div>
      </div>

      {/* ── Bottom Row ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '1.5rem' }}>

        {/* ── Recent Scans Timeline ── */}
        <div className="glass-panel" style={{ padding: '1.5rem' }}>
          <h3 style={{ fontSize: '0.9rem', marginBottom: '1.2rem', display: 'flex', alignItems: 'center', gap: '8px', fontFamily: 'var(--font-cyber)' }}>
            📡 RECENT_ANALYSIS_LOGS
          </h3>
          {loading ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}>
              <div className="status-indicator pending" style={{ margin: 0 }}></div>
              Loading scan history...
            </div>
          ) : recentScans.length === 0 ? (
            <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-secondary)', border: '1px dashed var(--panel-border)', borderRadius: '8px', fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}>
              No scan logs found. Launch a new scan to populate the database.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem', maxHeight: '320px', overflowY: 'auto', paddingRight: '4px' }}>
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
          )}
        </div>

        {/* ── System Health Monitor ── */}
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
