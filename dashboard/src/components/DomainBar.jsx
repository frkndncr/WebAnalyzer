import React, { useState } from 'react';
import { Icon } from './ui';
import { cleanDomain } from '../lib/analysis';

/** Shared domain lookup bar used by Results and the analysis pages. */
export default function DomainBar({ initial = '', onSubmit, placeholder = 'Enter a domain…', children }) {
  const [v, setV] = useState(initial);
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
        style={{ maxWidth: 420 }}
      />
      <button className="btn" type="submit"><Icon name="search" size={16} /> Load</button>
      {children && <div className="flex" style={{ marginLeft: 'auto', gap: 8 }}>{children}</div>}
    </form>
  );
}
