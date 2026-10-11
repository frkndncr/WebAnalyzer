import React from 'react';
import { Icon, Badge } from './ui';
import { MODULES, severityClass } from '../lib/analysis';

const isPrimitive = (v) => v === null || v === undefined || ['string', 'number', 'boolean'].includes(typeof v);

const GROUP_ICON = { recon: 'globe', security: 'shield', offensive: 'bug' };
const MODULE_META = Object.fromEntries(MODULES.map((m) => [m.name, m]));

/* ---- recursive value renderer --------------------------------------------- */

function Val({ v }) {
  if (v === null || v === undefined || v === '') return <span className="val null">—</span>;
  if (typeof v === 'boolean') return <span className={`val bool-${v}`}>{v ? 'Yes' : 'No'}</span>;
  if (typeof v === 'number') return <span className="val num">{v}</span>;
  if (typeof v === 'string') return <span className="val str">{v}</span>;
  if (Array.isArray(v)) return <ArrayVal items={v} />;
  if (typeof v === 'object') return <ObjectVal obj={v} />;
  return <span className="val str">{String(v)}</span>;
}

function ArrayVal({ items }) {
  if (items.length === 0) return <span className="muted">none</span>;
  if (items.every(isPrimitive)) {
    return <div>{items.map((it, i) => <span className="chip" key={i}>{it === null ? '—' : String(it)}</span>)}</div>;
  }
  return (
    <div>
      {items.map((it, i) => (
        <div className="arr-card" key={i}><Val v={it} /></div>
      ))}
    </div>
  );
}

function ObjectVal({ obj }) {
  const entries = Object.entries(obj);
  if (entries.length === 0) return <span className="muted">—</span>;
  return (
    <div className="tree">
      {entries.map(([k, v]) => (
        <div className="node" key={k}>
          {isPrimitive(v) ? (
            <span><span className="key">{k}</span><Val v={v} /></span>
          ) : (
            <>
              <div className="key">{k}</div>
              <div className="nest"><Val v={v} /></div>
            </>
          )}
        </div>
      ))}
    </div>
  );
}

/* ---- per-module summary signal (count + severity for the header) ---------- */

function moduleSignal(data) {
  if (!data || typeof data !== 'object') return null;
  if (data.error) return { label: 'error', sev: 'info' };

  const buckets = [
    ['vulnerabilities', 'high'], ['vulnerable_subdomains', 'critical'],
    ['phishing_domains', 'high'], ['secrets', 'critical'],
    ['js_vulnerabilities', 'high'], ['active_vulnerabilities', 'high'],
    ['ssrf_vulnerabilities', 'high'], ['open_ports', 'medium'],
  ];
  for (const [key, sev] of buckets) {
    const arr = data[key] ?? data?.port_scan?.[key];
    if (Array.isArray(arr) && arr.length > 0) {
      return { label: `${arr.length} ${key.replace(/_/g, ' ')}`, sev };
    }
  }
  if (Array.isArray(data) && data.length) return { label: `${data.length} items`, sev: 'info' };
  return null;
}

/* ---- module card ---------------------------------------------------------- */

function ModuleCard({ name, data, defaultOpen }) {
  const meta = MODULE_META[name];
  const sig = moduleSignal(data);
  return (
    <details className="module fade" open={defaultOpen}>
      <summary>
        <Icon name={GROUP_ICON[meta?.group] || 'results'} className="ico" />
        <span>{name}</span>
        {sig && <Badge sev={data?.error ? 'info' : severityClass(sig.sev)}>{sig.label}</Badge>}
        <Icon name="caret" size={16} className="caret" />
      </summary>
      <div className="body"><Val v={data} /></div>
    </details>
  );
}

/** Render a results object ({ moduleName: data }) as ordered module cards. */
export default function ResultRenderer({ results }) {
  if (!results || typeof results !== 'object' || Object.keys(results).length === 0) {
    return <div className="muted">No module output yet.</div>;
  }
  const order = MODULES.map((m) => m.name);
  const keys = Object.keys(results).sort((a, b) => {
    const ia = order.indexOf(a), ib = order.indexOf(b);
    return (ia === -1 ? 99 : ia) - (ib === -1 ? 99 : ib);
  });
  return (
    <div className="grid" style={{ gap: 12 }}>
      {keys.map((k, i) => <ModuleCard key={k} name={k} data={results[k]} defaultOpen={i < 2} />)}
    </div>
  );
}
