import React from 'react';
import { Icon, Badge } from './ui';
import { MODULES, severityClass, localize } from '../lib/analysis';
import { moduleStatus } from '../lib/findings';

const isPrimitive = (v) => v === null || v === undefined || ['string', 'number', 'boolean'].includes(typeof v);
const isUrl = (s) => /^https?:\/\/\S+$/i.test(s);

const GROUP_ICON = { recon: 'globe', security: 'shield', offensive: 'bug' };
const MODULE_META = Object.fromEntries(MODULES.map((m) => [m.name, m]));

/* ---- recursive value renderer --------------------------------------------- */

function Val({ v }) {
  if (v === null || v === undefined || v === '') return <span className="val null">—</span>;
  if (typeof v === 'boolean') return <span className={`val bool-${v}`}>{v ? 'Yes' : 'No'}</span>;
  if (typeof v === 'number') return <span className="val num">{v}</span>;
  if (typeof v === 'string') {
    const s = localize(v);
    return isUrl(s)
      ? <a className="val" href={s} target="_blank" rel="noreferrer">{s}</a>
      : <span className="val str">{s}</span>;
  }
  if (Array.isArray(v)) return <ArrayVal items={v} />;
  if (typeof v === 'object') return <ObjectVal obj={v} />;
  return <span className="val str">{String(v)}</span>;
}

function ArrayVal({ items }) {
  if (items.length === 0) return <span className="muted">none</span>;
  if (items.every(isPrimitive)) {
    return <div>{items.map((it, i) => <span className="chip" key={i}>{it === null ? '—' : localize(String(it))}</span>)}</div>;
  }
  return <div>{items.map((it, i) => <div className="arr-card" key={i}><Val v={it} /></div>)}</div>;
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

/* ---- per-module signal shown in the card header ---------------------------- */

const COUNTED = [
  ['vulnerabilities', 'high'], ['vulnerable_subdomains', 'critical'], ['phishing_domains', 'high'],
  ['secrets', 'critical'], ['js_vulnerabilities', 'high'], ['active_vulnerabilities', 'high'],
  ['ssrf_vulnerabilities', 'high'],
];

function moduleSignal(data) {
  if (!data || typeof data !== 'object') return null;
  for (const [key, sev] of COUNTED) {
    const arr = data[key] ?? data?.vulnerability_scan?.[key];
    if (Array.isArray(arr) && arr.length > 0) return { label: `${arr.length} ${key.replace(/_/g, ' ')}`, sev };
  }
  if (Array.isArray(data) && data.length) return { label: `${data.length} items`, sev: 'info' };
  return null;
}

/* ---- module card ---------------------------------------------------------- */

function ModuleCard({ name, data, open, onToggle }) {
  const meta = MODULE_META[name];
  const status = moduleStatus(data);
  const sig = status === 'ok' ? moduleSignal(data) : null;
  return (
    <details className="module fade" open={open} onToggle={(e) => onToggle(name, e.currentTarget.open)}>
      <summary>
        <Icon name={GROUP_ICON[meta?.group] || 'results'} className="ico" />
        <span>{name}</span>
        <span className="modrow-meta">
          {status === 'error' && <Badge sev="critical">failed</Badge>}
          {status === 'empty' && <Badge sev="info">no data</Badge>}
          {sig && <Badge sev={severityClass(sig.sev)}>{sig.label}</Badge>}
          <Icon name="caret" size={16} className="caret" />
        </span>
      </summary>
      <div className="body">
        {status === 'error' ? <div className="muted">{String(data.error)}</div>
          : status === 'empty' ? <div className="muted">This module returned no data.</div>
            : <Val v={data} />}
      </div>
    </details>
  );
}

/** Ordered list of module cards. `openMap` controls which cards are expanded. */
export default function ResultRenderer({ results, names, openMap, onToggle }) {
  const keys = names || Object.keys(results || {});
  if (keys.length === 0) return <div className="muted">No module output yet.</div>;
  return (
    <div className="grid" style={{ gap: 12 }}>
      {keys.map((k) => <ModuleCard key={k} name={k} data={results[k]} open={Boolean(openMap[k])} onToggle={onToggle} />)}
    </div>
  );
}
