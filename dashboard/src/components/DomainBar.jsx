import React, { useEffect, useState } from 'react';
import { Icon } from './ui';
import { cleanDomain } from '../lib/analysis';
import { apiRequest } from '../api/client';

/** Shared domain lookup bar. Suggests recently scanned domains as you type. */
export default function DomainBar({ initial = '', onSubmit, placeholder = 'Enter a domain…', children }) {
  const [v, setV] = useState(initial);
  const [recent, setRecent] = useState([]);

  useEffect(() => {
    const controller = new AbortController();
    apiRequest('/api/recent-scans', { signal: controller.signal })
      .then((rows) => {
        if (Array.isArray(rows)) setRecent([...new Set(rows.map((r) => r.domain).filter(Boolean))]);
      })
      .catch(() => { /* suggestions are optional */ });
    return () => controller.abort();
  }, []);

  return (
    <form
      className="flex wrap"
      style={{ marginBottom: 20 }}
      onSubmit={(e) => { e.preventDefault(); const d = cleanDomain(v); if (d) onSubmit(d); }}
    >
      <input
        className="input"
        placeholder={placeholder}
        value={v}
        onChange={(e) => setV(e.target.value)}
        list="recent-domains"
        style={{ maxWidth: 420 }}
        aria-label="Domain"
      />
      <datalist id="recent-domains">
        {recent.map((d) => <option key={d} value={d} />)}
      </datalist>
      <button className="btn" type="submit"><Icon name="search" size={16} /> Load</button>
      {children && <div className="flex" style={{ marginLeft: 'auto', gap: 8 }}>{children}</div>}
    </form>
  );
}
