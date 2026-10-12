import React, { useMemo, useState } from 'react';
import ResultRenderer from '../ResultRenderer';
import { useCatalogue } from '../../context/catalogue';
import { moduleStatus } from '../../lib/findings';

export default function ModulesTab({ results, onCopy }) {
  const { names: ORDER } = useCatalogue();
  const [query, setQuery] = useState('');
  const [openMap, setOpenMap] = useState({});

  const names = useMemo(() => {
    const q = query.trim().toLowerCase();
    return Object.keys(results || {})
      .filter((n) => !q || n.toLowerCase().includes(q))
      .sort((a, b) => {
        const ia = ORDER.indexOf(a), ib = ORDER.indexOf(b);
        return (ia === -1 ? 99 : ia) - (ib === -1 ? 99 : ib);
      });
  }, [results, query, ORDER]);

  const toggle = (name, open) => setOpenMap((m) => (m[name] === open ? m : { ...m, [name]: open }));
  const setAll = (open) => setOpenMap(Object.fromEntries(names.map((n) => [n, open])));
  const failed = Object.values(results || {}).filter((d) => moduleStatus(d) === 'error').length;

  return (
    <div className="fade">
      <div className="toolbar">
        <input
          className="input"
          placeholder="Filter modules…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          aria-label="Filter modules"
        />
        <span className="muted">
          {names.length} module{names.length === 1 ? '' : 's'}{failed > 0 ? ` · ${failed} failed` : ''}
        </span>
        <span className="grow">
          <button type="button" className="btn ghost sm" onClick={() => setAll(true)}>Expand all</button>
          <button type="button" className="btn ghost sm" onClick={() => setAll(false)}>Collapse all</button>
          <button type="button" className="btn sm" onClick={() => onCopy(JSON.stringify(results, null, 2))}>Copy JSON</button>
        </span>
      </div>
      <ResultRenderer results={results} names={names} openMap={openMap} onToggle={toggle} />
    </div>
  );
}
