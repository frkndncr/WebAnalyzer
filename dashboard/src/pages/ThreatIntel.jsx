import React from 'react';
import { useResource } from '../hooks/useApi';
import DomainBar from '../components/DomainBar';
import { ScoreRing, Empty, Spinner, Badge } from '../components/ui';
import { scoreSeverity, severityClass } from '../lib/analysis';

const levelSev = (v) => (v >= 7 ? 'critical' : v >= 4 ? 'high' : v >= 2 ? 'medium' : 'low');

function Meter({ label, value, max = 10 }) {
  const v = Number(value) || 0;
  const sev = levelSev(v);
  return (
    <div className="metric">
      <div className="top"><span className="muted">{label}</span><b>{v}/{max}</b></div>
      <div className="meter"><i style={{ width: `${Math.min(v / max, 1) * 100}%`, background: `var(--${sev})` }} /></div>
    </div>
  );
}

export default function ThreatIntel({ domain, setDomain }) {
  const path = domain ? `/api/threat-intel/${encodeURIComponent(domain)}` : '';
  const { data, loading, error } = useResource(path);

  const body = () => {
    if (!domain) return <Empty title="No domain selected"><div>Load a domain above to see its threat profile.</div></Empty>;
    if (loading) return <Empty title={<span><Spinner /> Analyzing {domain}…</span>} />;
    if (error) return <Empty title={domain}><div className="muted">{error?.status === 404 ? 'No threat data yet — run a scan first.' : 'Could not load threat intel.'}</div></Empty>;
    if (!data) return null;

    const sev = scoreSeverity(data.risk_score);
    const mitre = Array.isArray(data.mitre_techniques) ? data.mitre_techniques : [];
    const iocs = Array.isArray(data.iocs) ? data.iocs : [];
    const cves = Array.isArray(data.cves) ? data.cves : [];
    const secrets = Array.isArray(data.archive_secrets) ? data.archive_secrets : [];
    const detected = mitre.filter((m) => m.detected > 0).length;

    return (
      <div className="fade">
        <div className="card" style={{ marginBottom: 16 }}>
          <div className="ring-wrap">
            <ScoreRing value={data.risk_score} grade={data.security_grade} sev={sev} />
            <div style={{ flex: 1, minWidth: 220 }}>
              <h2 style={{ fontSize: 20 }}>{data.domain}</h2>
              <div className="muted" style={{ marginBottom: 12 }}>
                {detected} ATT&CK tactic{detected === 1 ? '' : 's'} with activity · {iocs.length} IOCs · {cves.length} CVEs
              </div>
              <Meter label="Attack surface" value={data.attack_surface} />
              <Meter label="Vulnerability density" value={data.vuln_density} />
              <Meter label="Exposure level" value={data.exposure_level} />
            </div>
          </div>
        </div>

        <div className="card" style={{ marginBottom: 16 }}>
          <div className="card-title">MITRE ATT&CK tactics</div>
          <div className="mitre-grid">
            {mitre.map((m) => (
              <div className={`mitre ${m.detected > 0 ? 'hit' : ''}`} key={m.id}>
                <div className="id">{m.id}</div>
                <div className="nm">{m.name}</div>
                <div className="ct">{m.detected}</div>
              </div>
            ))}
          </div>
        </div>

        <div className="grid cols-2" style={{ alignItems: 'start' }}>
          <div className="card">
            <div className="card-title">Indicators of compromise ({iocs.length})</div>
            {iocs.length === 0 ? <div className="muted">No IOCs detected.</div> : iocs.slice(0, 20).map((io, i) => (
              <div className="row" key={i}>
                <span className="dom">{io.value || io.indicator || JSON.stringify(io)}</span>
                {io.severity && <Badge sev={severityClass(io.severity)}>{io.severity}</Badge>}
              </div>
            ))}
          </div>
          <div className="card">
            <div className="card-title">CVEs ({cves.length}) · Archive secrets ({secrets.length})</div>
            {cves.length === 0 && secrets.length === 0 ? <div className="muted">No CVEs or leaked secrets found.</div> : (
              <>
                {cves.slice(0, 12).map((c, i) => (
                  <div className="row" key={`c${i}`}>
                    <span className="dom">{c.id || c.cve || JSON.stringify(c)}</span>
                    {c.severity && <Badge sev={severityClass(c.severity)}>{c.severity}</Badge>}
                  </div>
                ))}
                {secrets.slice(0, 8).map((s, i) => (
                  <div className="row" key={`s${i}`}>
                    <span className="dom">{s.type || s.secret_type || 'Secret'}</span>
                    <Badge sev="critical">leak</Badge>
                  </div>
                ))}
              </>
            )}
          </div>
        </div>
      </div>
    );
  };

  return (
    <div>
      <DomainBar initial={domain} onSubmit={setDomain} placeholder="Domain to profile…" />
      {body()}
    </div>
  );
}
