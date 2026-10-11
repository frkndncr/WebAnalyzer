import React from 'react';
import { useResource } from '../hooks/useApi';
import DomainBar from '../components/DomainBar';
import { Empty, Spinner, Badge } from '../components/ui';
import ScanGate from '../components/ScanGate';
import { severityClass, isReady } from '../lib/analysis';

function MapSvg({ domain, subs }) {
  const W = 800, H = 420, cx = 400, cy = 210, R = 150;
  const nodes = subs.slice(0, 16);
  const n = nodes.length || 1;
  const label = (s) => {
    const base = s.endsWith('.' + domain) ? s.slice(0, -(domain.length + 1)) : s.split('.')[0];
    return base.length > 16 ? base.slice(0, 15) + '…' : base;
  };
  return (
    <svg className="nodemap" viewBox={`0 0 ${W} ${H}`} style={{ height: 'auto', display: 'block' }}>
      {nodes.map((s, i) => {
        const a = (i / n) * 2 * Math.PI - Math.PI / 2;
        const x = cx + R * Math.cos(a), y = cy + R * Math.sin(a);
        const right = Math.cos(a) >= 0;
        return (
          <g key={i}>
            <line className="edge" x1={cx} y1={cy} x2={x} y2={y} />
            <circle className="leaf" cx={x} cy={y} r={5} />
            <text x={x + (right ? 9 : -9)} y={y + 3.5} textAnchor={right ? 'start' : 'end'} fontSize="10">{label(s)}</text>
          </g>
        );
      })}
      <circle className="center" cx={cx} cy={cy} r={11} />
      <text x={cx} y={cy - 20} textAnchor="middle" fontSize="12.5" fill="var(--text)">{domain}</text>
      {subs.length > 16 && <text x={cx} y={H - 14} textAnchor="middle" fontSize="11">+{subs.length - 16} more subdomains</text>}
    </svg>
  );
}

function techList(tech) {
  if (!tech || typeof tech !== 'object') return [];
  const out = [];
  for (const [, v] of Object.entries(tech)) {
    const vals = Array.isArray(v) ? v : [v];
    vals.filter((x) => x && x !== 'Not Detected' && x !== 'Unknown').forEach((x) => out.push(`${x}`));
  }
  return [...new Set(out)];
}

export default function NetworkMap({ domain, setDomain }) {
  const path = domain ? `/api/network-map/${encodeURIComponent(domain)}` : '';
  const { data, loading, error, reload } = useResource(path);

  const body = () => {
    if (!domain) return <Empty title="No domain selected"><div>Load a domain to map its attack surface.</div></Empty>;
    if (loading) return <Empty title={<span><Spinner /> Mapping {domain}…</span>} />;
    if (error) return <Empty title={domain}><div className="muted">{error?.status === 404 ? 'No map data yet — run a scan first.' : 'Could not load the network map.'}</div></Empty>;
    if (!isReady(data)) return <ScanGate domain={domain} data={data} reload={reload} />;

    const subs = Array.isArray(data.subdomains) ? data.subdomains : [];
    const techs = techList(data.technologies);
    const ports = Array.isArray(data.ports) ? data.ports : [];
    const phishing = Array.isArray(data.phishing_domains) ? data.phishing_domains : [];

    return (
      <div className="fade">
        <div className="grid cols-4" style={{ marginBottom: 16 }}>
          <div className="stat"><div className="label">Subdomains</div><div className="value">{subs.length}</div></div>
          <div className="stat"><div className="label">Technologies</div><div className="value">{techs.length}</div></div>
          <div className="stat"><div className="label">Open ports</div><div className="value">{ports.length}</div></div>
          <div className="stat"><div className="label">Look-alikes</div><div className="value" style={phishing.length ? { color: 'var(--high)' } : undefined}>{phishing.length}</div></div>
        </div>

        <MapSvg domain={data.domain} subs={subs} />

        <div className="grid cols-2 mt" style={{ alignItems: 'start' }}>
          <div className="card">
            <div className="card-title">Technologies</div>
            {techs.length === 0 ? <div className="muted">None detected.</div> : <div>{techs.map((t, i) => <span className="chip" key={i}>{t}</span>)}</div>}
            <div className="card-title" style={{ marginTop: 18 }}>Open ports</div>
            {ports.length === 0 ? <div className="muted">No open ports reported.</div> : <div>{ports.map((p, i) => <span className="chip" key={i}>{typeof p === 'object' ? (p.port || JSON.stringify(p)) : p}</span>)}</div>}
          </div>

          <div className="card">
            <div className="card-title">Phishing look-alikes ({phishing.length})</div>
            {phishing.length === 0 ? <div className="muted">No active look-alike domains found.</div> : phishing.slice(0, 12).map((p, i) => (
              <div className="row" key={i}>
                <div>
                  <div className="dom">{p.domain}</div>
                  <div className="meta">{(p.ips || []).join(', ') || '—'}</div>
                </div>
                <Badge sev={severityClass(p.severity)}>{p.status || p.severity}</Badge>
              </div>
            ))}
          </div>
        </div>

        {subs.length > 0 && (
          <div className="card mt">
            <div className="card-title">All subdomains ({subs.length})</div>
            <div>{subs.map((s, i) => <span className="chip" key={i}>{s}</span>)}</div>
          </div>
        )}
      </div>
    );
  };

  return (
    <div>
      <DomainBar initial={domain} onSubmit={setDomain} placeholder="Domain to map…" />
      {body()}
    </div>
  );
}
