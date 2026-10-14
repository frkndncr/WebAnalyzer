import React, { useEffect, useRef, useState } from 'react';
import { apiRequest } from '../api/client';
import { usePolling } from '../hooks/useApi';
import { Stat, Badge, Empty, Icon, ScoreRing } from '../components/ui';
import { timeAgo, severityClass, extractScore, scoreSeverity } from '../lib/analysis';

const SEV_ROWS = [
  ['critical', 'Critical'], ['high', 'High'], ['medium', 'Medium'],
  ['low', 'Low'], ['info', 'Info'],
];

const asList = (v) => (Array.isArray(v) ? v : []);

export default function Overview({ onOpenDomain, onNewScan }) {
  const [stats, setStats] = useState(null);
  const [vuln, setVuln] = useState(null);
  const [recent, setRecent] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [active, setActive] = useState([]);
  const [loading, setLoading] = useState(true);
  const [failed, setFailed] = useState(false);
  const [version, setVersion] = useState(0);
  const lastActive = useRef(0);

  // Load everything once, and again whenever a running scan finishes.
  useEffect(() => {
    const controller = new AbortController();
    const { signal } = controller;
    (async () => {
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
      if (r.status === 'fulfilled') setRecent(asList(r.value));
      if (a.status === 'fulfilled') setAlerts(asList(a.value));
      if (ac.status === 'fulfilled') setActive(asList(ac.value));
      setFailed([s, v, r, a, ac].every((x) => x.status === 'rejected'));
      setLoading(false);
    })();
    return () => controller.abort();
  }, [version]);

  // Only the cheap endpoint is polled; full data is refreshed when a scan completes.
  usePolling(async (signal) => {
    const list = asList(await apiRequest('/api/active-scans', { signal }));
    if (signal.aborted) return;
    setActive(list);
    if (lastActive.current > 0 && list.length === 0) setVersion((n) => n + 1);
    lastActive.current = list.length;
  }, 5000);

  if (loading) return <Empty title="Loading overview…" />;
  if (failed) return <Empty title="Cannot reach the API"><div>Check that the backend is running and try again.</div></Empty>;

  const avg = stats?.average_score;
  const findingsTotal = vuln?.total ?? stats?.total_vulnerabilities ?? 0;

  const sevTotal = SEV_ROWS.reduce((n, [k]) => n + (vuln?.[k] ?? 0), 0);
  const avgNumber = typeof avg === 'number' ? Math.round(avg) : null;

  return (
    <div className="fade">
      <section className="hero">
        <div className="hero-copy">
          <span className="eyebrow"><Icon name="shield" size={14} /> Open-source attack-surface scanner</span>
          <h2>Know what an attacker can see.</h2>
          <p>
            Subdomains, DNS, technologies, exposed files and vulnerabilities for any domain you own,
            scored and ranked in one place.
          </p>
          <div className="flex wrap">
            <button className="btn primary" onClick={onNewScan}><Icon name="scan" size={16} /> Start a scan</button>
            <a className="btn" href="https://github.com/frkndncr/WebAnalyzer" target="_blank" rel="noreferrer">
              <Icon name="github" size={16} /> Star on GitHub
            </a>
          </div>
        </div>
        <div className="hero-ring">
          <ScoreRing value={avgNumber} sev={avgNumber != null ? scoreSeverity(avgNumber) : 'info'} size={150} />
          <div className="muted">Average security score</div>
        </div>
      </section>

      <div className="grid cols-4 mt">
        <Stat icon="globe" label="Domains scanned" value={stats?.total_domains ?? 0} />
        <Stat icon="bug" label="Total findings" value={findingsTotal} accent={findingsTotal > 0 ? 'high' : 'ok'} />
        <Stat icon="shield" label="Average score" value={avg ?? '—'} suffix={avg != null ? '/ 100' : undefined} accent={avg != null ? scoreSeverity(avg) : undefined} />
        <Stat icon="clock" label="Scans running" value={active.length} accent={active.length ? 'low' : undefined} />
      </div>

      {active.length > 0 && (
        <div className="card mt">
          <div className="card-title">In progress</div>
          {active.map((a) => (
            <div className="row linklike" key={a.domain} onClick={() => onOpenDomain(a.domain)}>
              <div className="flex"><Icon name="scan" size={15} /><span className="dom">{a.domain}</span></div>
              <span className="meta">{a.current_module} · {a.completed}/{a.total}</span>
            </div>
          ))}
        </div>
      )}

      <div className="grid cols-2 mt" style={{ alignItems: 'start' }}>
        <div className="card">
          <div className="card-title">Recent scans</div>
          {recent.length === 0 ? <div className="muted">No scans yet — start one from New Scan.</div> : recent.slice(0, 8).map((r) => {
            const { score, grade } = extractScore(r.score);
            return (
              <div className="row linklike" key={r.domain} onClick={() => onOpenDomain(r.domain)}>
                <div className="flex" style={{ minWidth: 0 }}>
                  <span className="avatar" aria-hidden="true">{(r.domain || '?')[0].toUpperCase()}</span>
                  <div style={{ minWidth: 0 }}>
                    <div className="dom">{r.domain}</div>
                    <div className="meta">{timeAgo(r.scan_date)}</div>
                  </div>
                </div>
                <div className="flex">
                  {r.vulnerabilities > 0 && <Badge sev="high">{r.vulnerabilities} finding{r.vulnerabilities === 1 ? '' : 's'}</Badge>}
                  {score != null && <Badge sev={scoreSeverity(score)}>{grade ? `${grade} · ${score}` : score}</Badge>}
                </div>
              </div>
            );
          })}
        </div>

        <div className="grid" style={{ gap: 16 }}>
          <div className="card">
            <div className="card-title">Findings by severity</div>
            <div className="sevbar-stack" role="img" aria-label="Share of findings by severity">
              {sevTotal > 0 && SEV_ROWS.map(([k]) => (vuln?.[k] ?? 0) > 0 && (
                <i key={k} style={{ width: `${((vuln[k] ?? 0) / sevTotal) * 100}%`, background: `var(--${k})` }} />
              ))}
            </div>
            {SEV_ROWS.map(([k, label]) => {
              const n = vuln?.[k] ?? 0;
              return (
                <div className="sevrow" key={k}>
                  <span className="flex"><Badge sev={k}>{label}</Badge></span>
                  <div className="meter"><i style={{ width: `${sevTotal ? (n / sevTotal) * 100 : 0}%`, background: `var(--${k})` }} /></div>
                  <b className="dom">{n}</b>
                </div>
              );
            })}
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
