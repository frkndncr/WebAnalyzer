import React, { useState, useEffect } from 'react';
import { getApiUrl } from '../config';

const DashboardOverview = ({ setActiveTab, setCurrentDomain }) => {
  const [stats, setStats] = useState({ total_jobs: 0, total_domains: 0, total_vulnerabilities: 0, status: 'connecting...' });
  const [recentScans, setRecentScans] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const statsResp = await fetch(getApiUrl('/api/stats'));
        if (statsResp.ok) {
          const statsData = await statsResp.json();
          setStats(statsData);
        }
        
        const recentResp = await fetch(getApiUrl('/api/recent-scans'));
        if (recentResp.ok) {
          const recentData = await recentResp.json();
          setRecentScans(recentData);
        }
      } catch (err) {
        console.error("Error fetching dashboard statistics", err);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

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

  return (
    <div className="animate-fade-in" style={{ maxWidth: '1100px', margin: '0 auto' }}>
      {/* Title block */}
      <div style={{ marginBottom: '2.5rem' }}>
        <h2 style={{ fontSize: '2.2rem', marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '15px' }}>
          <span className="text-gradient">OPERATIONS_CENTER</span>
          <span style={{ fontSize: '0.8rem', padding: '3px 10px', borderRadius: '4px', background: 'rgba(0, 242, 254, 0.15)', color: 'var(--accent-blue)', fontFamily: 'var(--font-mono)' }}>SYS_ACTIVE</span>
        </h2>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', fontFamily: 'var(--font-mono)' }}>WebAnalyzer Central Intelligence & Security Monitoring Console</p>
      </div>

      {/* Stats row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1.5rem', marginBottom: '2.5rem' }}>
        <div className="glass-panel" style={{ padding: '1.5rem', borderLeft: '4px solid var(--accent-blue)' }}>
          <span style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-secondary)', textTransform: 'uppercase', fontFamily: 'var(--font-mono)', letterSpacing: '1px' }}>TOTAL_DOMAINS_SCANNED</span>
          <span style={{ display: 'block', fontSize: '2.5rem', fontWeight: '900', color: 'var(--text-primary)', marginTop: '0.5rem', fontFamily: 'var(--font-cyber)', textShadow: '0 0 10px rgba(0, 242, 254, 0.3)' }}>
            {stats.total_domains}
          </span>
        </div>

        <div className="glass-panel" style={{ padding: '1.5rem', borderLeft: '4px solid var(--accent-red)' }}>
          <span style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-secondary)', textTransform: 'uppercase', fontFamily: 'var(--font-mono)', letterSpacing: '1px' }}>CRITICAL_VULNERABILITIES</span>
          <span style={{ display: 'block', fontSize: '2.5rem', fontWeight: '900', color: 'var(--accent-red)', marginTop: '0.5rem', fontFamily: 'var(--font-cyber)', textShadow: '0 0 10px rgba(255, 0, 85, 0.3)' }}>
            {stats.total_vulnerabilities}
          </span>
        </div>

        <div className="glass-panel" style={{ padding: '1.5rem', borderLeft: '4px solid var(--accent-purple)' }}>
          <span style={{ display: 'block', fontSize: '0.78rem', color: 'var(--text-secondary)', textTransform: 'uppercase', fontFamily: 'var(--font-mono)', letterSpacing: '1px' }}>GATEWAY_DB_STATUS</span>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginTop: '1.2rem' }}>
            <span className={`status-indicator ${stats.status === 'connected' ? 'active' : 'pending'}`} style={{ width: '12px', height: '12px', marginRight: 0 }}></span>
            <span style={{ fontSize: '1.2rem', fontWeight: '700', textTransform: 'uppercase', fontFamily: 'var(--font-mono)', color: stats.status === 'connected' ? 'var(--accent-green)' : 'var(--accent-orange)' }}>
              {stats.status}
            </span>
          </div>
        </div>
      </div>

      {/* Main Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(450px, 1fr))', gap: '2rem' }}>
        {/* Recent Scans Box */}
        <div className="glass-panel" style={{ padding: '2rem' }}>
          <h3 style={{ fontSize: '1.2rem', marginBottom: '1.5rem', display: 'flex', alignItems: 'center', gap: '10px', fontFamily: 'var(--font-cyber)' }}>
            🛰️ RECENT_ANALYSIS_LOGS
          </h3>
          
          {loading ? (
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.9rem', fontFamily: 'var(--font-mono)' }}>Loading operational log queue...</p>
          ) : recentScans.length === 0 ? (
            <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-secondary)', border: '1px dashed var(--panel-border)', borderRadius: '8px' }}>
              No scan logs found. Start a new scan to populate the database.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', maxHeight: '420px', overflowY: 'auto', paddingRight: '5px' }}>
              {recentScans.map((scan) => (
                <div key={scan.domain} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0.8rem 1rem', background: 'rgba(5, 7, 10, 0.5)', border: '1px solid var(--panel-border)', borderRadius: '6px', transition: 'all 0.2s ease' }} className="recent-scan-item">
                  <div>
                    <strong style={{ display: 'block', fontSize: '0.95rem', color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>{scan.domain}</strong>
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                      {new Date(scan.scan_date).toLocaleString()}
                    </span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
                    {scan.grade && (
                      <span style={{ 
                        fontFamily: 'var(--font-cyber)', 
                        fontSize: '0.9rem', 
                        fontWeight: 'bold', 
                        color: getGradeColor(scan.grade),
                        border: `1px solid ${getGradeColor(scan.grade)}`,
                        padding: '2px 8px',
                        borderRadius: '4px',
                        background: 'rgba(255, 255, 255, 0.02)',
                        textShadow: `0 0 5px ${getGradeColor(scan.grade)}`
                      }}>
                        {scan.grade}
                      </span>
                    )}
                    <button className="btn-primary" style={{ padding: '0.35rem 0.8rem', fontSize: '0.75rem' }} onClick={() => viewScan(scan.domain)}>
                      LOAD_DATA
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* System Operations Console */}
        <div className="glass-panel" style={{ padding: '2rem', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <h3 style={{ fontSize: '1.2rem', marginBottom: '1.2rem', display: 'flex', alignItems: 'center', gap: '10px', fontFamily: 'var(--font-cyber)' }}>
              📟 SECURITY_TELEMETRY
            </h3>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.88rem', lineHeight: '1.6', marginBottom: '1.5rem' }}>
              WebAnalyzer security scanner actively checks SPF/DMARC records, CORS configuration reflection, exposed backups and environment keys, open ports, and JavaScript endpoints.
            </p>
            
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.8rem', fontFamily: 'var(--font-mono)', fontSize: '0.82rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0.5rem 0', borderBottom: '1px solid rgba(0,242,254,0.08)' }}>
                <span style={{ color: 'var(--text-secondary)' }}>Threat Level:</span>
                <span style={{ color: 'var(--accent-red)', fontWeight: 'bold' }}>HIGH_RECON_ACTIVITY</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0.5rem 0', borderBottom: '1px solid rgba(0,242,254,0.08)' }}>
                <span style={{ color: 'var(--text-secondary)' }}>Deduplication Status:</span>
                <span style={{ color: 'var(--accent-green)' }}>ACTIVE (O(1) OrderedDict)</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0.5rem 0', borderBottom: '1px solid rgba(0,242,254,0.08)' }}>
                <span style={{ color: 'var(--text-secondary)' }}>Connection Pool limit:</span>
                <span style={{ color: 'var(--accent-blue)' }}>20 Connections max</span>
              </div>
            </div>
          </div>

          <div style={{ marginTop: '2rem', display: 'flex', gap: '1rem' }}>
            <button className="btn-primary" style={{ flex: 1 }} onClick={() => setActiveTab('new_scan')}>
              LAUNCH_NEW_SCAN
            </button>
            <button className="btn-outline" style={{ flex: 1 }} onClick={() => setActiveTab('advanced_scanner')}>
              ADVANCED_SCANNER
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default DashboardOverview;
