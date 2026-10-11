import React from 'react';
import { useResource } from '../hooks/useApi';
import DomainBar from '../components/DomainBar';
import { Empty, Spinner, Badge, Icon } from '../components/ui';
import ScanGate from '../components/ScanGate';
import { severityClass, isReady } from '../lib/analysis';

export default function AttackPath({ domain, setDomain }) {
  const path = domain ? `/api/threat-intel/${encodeURIComponent(domain)}` : '';
  const { data, loading, error, reload } = useResource(path);

  const body = () => {
    if (!domain) return <Empty title="No domain selected"><div>Load a domain to generate its exploit roadmap.</div></Empty>;
    if (loading) return <Empty title={<span><Spinner /> Planning paths for {domain}…</span>} />;
    if (error) return <Empty title={domain}><div className="muted">{error?.status === 404 ? 'No path data yet — run a scan first.' : 'Could not load attack paths.'}</div></Empty>;

    if (!isReady(data)) return <ScanGate domain={domain} data={data} reload={reload} />;

    const ap = data?.attack_path || {};
    const chains = Array.isArray(ap.exploit_chains) ? ap.exploit_chains : [];
    const nodes = Array.isArray(ap.graph?.nodes) ? ap.graph.nodes : [];
    if (chains.length === 0 && nodes.length === 0) {
      return <Empty title={domain}><div className="muted">No exploit chains were derived for this target.</div></Empty>;
    }

    return (
      <div className="fade">
        {chains.length > 0 && (
          <div style={{ marginBottom: 8 }}>
            <div className="card-title" style={{ marginBottom: 14 }}>Exploit chains ({chains.length})</div>
            {chains.map((chain, ci) => (
              <div className="chain" key={ci}>
                <h4><Icon name="route" size={17} style={{ color: 'var(--accent)' }} /> {chain.name || `Chain ${ci + 1}`}</h4>
                <div className="steps">
                  {(chain.steps || []).map((step, si) => (
                    <div className="step" key={si}>
                      <div className="box"><span className="n">{si + 1}</span>{String(step)}</div>
                      {si < chain.steps.length - 1 && <span className="arrow"><Icon name="caret" size={16} /></span>}
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}

        {nodes.length > 0 && (
          <div className="card mt">
            <div className="card-title">Graph nodes ({nodes.length})</div>
            {nodes.map((nd, i) => {
              const sev = severityClass(nd.severity);
              return (
                <div className="pathnode" key={nd.id || i}>
                  <span className="sevbar" style={{ background: `var(--${sev})` }} />
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div className="flex" style={{ gap: 8 }}>
                      <b>{nd.label || nd.id}</b>
                      {nd.type && <span className="chip" style={{ marginTop: 0 }}>{nd.type}</span>}
                    </div>
                    {nd.description && <div className="meta" style={{ marginTop: 3 }}>{nd.description}</div>}
                  </div>
                  <Badge sev={sev}>{nd.severity || 'info'}</Badge>
                </div>
              );
            })}
          </div>
        )}
      </div>
    );
  };

  return (
    <div>
      <DomainBar initial={domain} onSubmit={setDomain} placeholder="Domain to plan…" />
      {body()}
    </div>
  );
}
