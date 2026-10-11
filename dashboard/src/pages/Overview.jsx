import React, { useEffect, useState } from 'react';
import { apiRequest } from '../api/client';
import { usePolling } from '../hooks/useApi';
import { Stat, Badge, Empty, Icon } from '../components/ui';
import { timeAgo, severityClass, extractScore, scoreSeverity } from '../lib/analysis';

const SEV_ROWS = [
  ['critical', 'Critical'], ['high', 'High'], ['medium', 'Medium'],
  ['low', 'Low'], ['info', 'Info'],
];

export default function Overview({ onOpenDomain }) {
  const [stats, setStats] = useState(null);
  const [vuln, setVuln] = useState(null);
  const [recent, setRecent] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [active, setActive] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const controller = new AbortController();
    const { signal } = controller;
    const load = async () => {
      const [s, v, r, a, ac] = await Promise.allSettled([
        apiRequest('/api/stats', { signal }),
        apiRequest('/api/vulnerability-stats', { signal }),
        apiRequest('/api/recent-scans', { signal }),
        apiRequest('/api/recent-alerts', { signal }),
        apiRequest('/api/active-scans', { signal }),
      ]);
      if (signal.aborted) return;
      if (s.status === 'fulfilled') setStats(s.value);
      if (v.status === 'fulfilled') setVuln(v.value);
      if (r.status === 'fulfilled') setRecent(Array.isArray(r.value) ? r.value : []);
      if (a.status === 'fulfilled') setAlerts(Array.isArray(a.value) ? a.value : []);
      if (ac.status === 'fulfilled') setActive(Array.isArray(ac.value) ? ac.value : []);
      setLoading(false);
    };
    load().catch(() => setLoading(false));
    return () => controller.abort();
  }, []);

  usePolling(async (signal) => {
    const [ac, s] = await Promise.allSettled([
      apiRequest('/api/active-scans', { signal }),
      apiRequest('/api/stats', { signal }),
    ]);
    if (signal.aborted) return;
    if (ac.status === 'fulfilled') setActive(Array.isArray(ac.value) ? ac.value : []);
    if (s.status === 'fulfilled') setStats(s.value);
  }, 6000);

  if (loading) return <Empty title="Loading overview…" />;

  const vulnTotal = vuln?.total ?? 0;

  return (
    <div className="fade">
      <div className="grid cols-4">
        <Stat label="Domains scanned" value={stats?.total_domains ?? 0} />
        <Stat label="Vulnerabilities" value={vulnTotal} accent={vulnTotal > 0 ? 'high' : 'ok'} />
        <Stat label="Active scans" value={active.length} accent={active.length ? 'low' : undefined} />
        <Stat label="Scan jobs" value={stats?.total_jobs ?? 0} />
      </div>

      {active.length > 0 && (
        <div className="card mt">
          <div className="card-title">In progress</div>
          {active.map((a) => (
            <div className="row" key={a.domain}>
              <div className="flex"><Icon name="scan" size={15} /><span className="dom">{a.domain}</span></div>
              <span className="meta">{a.current_module} · {a.completed}/{a.total}</span>
            </div>
          ))}
        </div>
      )}

      <div className="grid cols-2 mt" style={{ alignItems: 'start' }}>
        <div className="card">
          <div className="card-title">Recent scans</div>
          {recent.length === 0 ? <div className="muted">No scans yet.</div> : recent.slice(0, 8).map((r) => {
            const { score, grade } = extractScore(r.score);
            return (
              <div className="row linklike" key={r.domain + r.scan_date} onClick={() => onOpenDomain(r.domain)}>
                <div>
                  <div className="dom">{r.domain}</div>
                  <div className="meta">{timeAgo(r.scan_date)}</div>
                </div>
                <div className="flex">
                  {r.vulnerabilities > 0 && <Badge sev="high">{r.vulnerabilities} vuln</Badge>}
                  {score != null && <Badge sev={scoreSeverity(score)}>{grade || score}</Badge>}
                </div>
              </div>
            );
          })}
        </div>

        <div className="grid" style={{ gap: 16 }}>
          <div className="card">
            <div className="card-title">Severity breakdown</div>
            {SEV_ROWS.map(([k, label]) => (
              <div className="row" key={k}>
                <span className="flex"><Badge sev={k}>{label}</Badge></span>
                <b className="dom">{vuln?.[k] ?? 0}</b>
              </div>
            ))}
          </div>

          <div className="card">
            <div className="card-title">Recent alerts</div>
            {alerts.length === 0 ? <div className="muted">No alerts.</div> : alerts.slice(0, 6).map((a, i) => (
              <div className="row linklike" key={i} onClick={() => onOpenDomain(a.domain)}>
                <div style={{ minWidth: 0 }}>
                  <div className="dom" style={{ fontFamily: 'var(--font)', fontWeight: 600 }}>{a.title}</div>
                  <div className="meta">{a.domain} · {a.module}</div>
                </div>
                <Badge sev={severityClass(a.severity)}>{a.severity}</Badge>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
