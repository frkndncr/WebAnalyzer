import React from 'react';

/* Minimal inline icon set (stroke-based, inherits currentColor). */
const PATHS = {
  overview: 'M3 3h7v7H3zM14 3h7v7h-7zM14 14h7v7h-7zM3 14h7v7H3z',
  scan: 'M3 7V5a2 2 0 0 1 2-2h2M17 3h2a2 2 0 0 1 2 2v2M21 17v2a2 2 0 0 1-2 2h-2M7 21H5a2 2 0 0 1-2-2v-2M12 8v8M8 12h8',
  results: 'M4 6h16M4 12h16M4 18h10',
  shield: 'M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6z',
  alert: 'M12 9v4M12 17h.01M10.3 3.9 2.4 18a2 2 0 0 0 1.7 3h15.8a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z',
  external: 'M14 3h7v7M21 3l-9 9M19 14v5a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2h5',
  caret: 'M9 6l6 6-6 6',
  check: 'M20 6L9 17l-5-5',
  search: 'M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16zM21 21l-4.3-4.3',
  clock: 'M12 7v5l3 2M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18z',
  globe: 'M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM3 12h18M12 3c2.5 2.7 2.5 15.3 0 18M12 3c-2.5 2.7-2.5 15.3 0 18',
  bug: 'M8 2l1.5 2.5M16 2l-1.5 2.5M12 7a4 4 0 0 0-4 4v3a4 4 0 0 0 8 0v-3a4 4 0 0 0-4-4zM3 13h3M18 13h3M4 8l3 2M20 8l-3 2M4 18l3-2M20 18l-3-2',
  target: 'M12 3v3M12 18v3M3 12h3M18 12h3M12 17a5 5 0 1 0 0-10 5 5 0 0 0 0 10zM12 14a2 2 0 1 0 0-4 2 2 0 0 0 0 4z',
  network: 'M9 3L3 6v15l6-3 6 3 6-3V3l-6 3-6-3zM9 3v15M15 6v15',
  route: 'M6 20a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM18 10a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM8.5 17H15a2 2 0 0 0 2-2v-1.5',
  github: 'M9 19c-4 1.4-4-2.5-6-3m12 5v-3.5c0-1 .1-1.4-.5-2 2.8-.3 5.5-1.4 5.5-6a4.6 4.6 0 0 0-1.3-3.2 4.3 4.3 0 0 0-.1-3.2s-1-.3-3.4 1.3a11.5 11.5 0 0 0-6 0C6.3 2.6 5.3 3 5.3 3a4.3 4.3 0 0 0-.1 3.2A4.6 4.6 0 0 0 3.9 9.4c0 4.6 2.7 5.7 5.5 6-.6.6-.6 1.2-.5 2V21',
  instagram: 'M7 2h10a5 5 0 0 1 5 5v10a5 5 0 0 1-5 5H7a5 5 0 0 1-5-5V7a5 5 0 0 1 5-5zM16 11.4a4 4 0 1 1-7.9 1.2 4 4 0 0 1 7.9-1.2zM17.5 6.5h.01',
  linkedin: 'M16 8a6 6 0 0 1 6 6v7h-4v-7a2 2 0 0 0-4 0v7h-4v-7a6 6 0 0 1 6-6zM2 9h4v12H2zM4 6a2 2 0 1 0 0-4 2 2 0 0 0 0 4z',
  mail: 'M4 4h16a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2zM22 6l-10 7L2 6',
  scale: 'M12 3v18M4 21h16M7 7h10M6 7l-3 7a3 3 0 0 0 6 0zM18 7l-3 7a3 3 0 0 0 6 0z',
};

export function Icon({ name, size = 18, className = '', style }) {
  const d = PATHS[name] || PATHS.results;
  return (
    <svg className={className} style={style} width={size} height={size} viewBox="0 0 24 24"
      fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      {d.split('M').filter(Boolean).map((seg, i) => <path key={i} d={'M' + seg} />)}
    </svg>
  );
}

export function Badge({ sev, children }) {
  return <span className={`badge ${sev}`}>{children}</span>;
}

export function Stat({ label, value, suffix, accent, icon }) {
  return (
    <div className="stat" style={accent ? { '--tone': `var(--${accent})` } : undefined}>
      {icon && <span className="stat-ico"><Icon name={icon} size={17} /></span>}
      <div className="label">{label}</div>
      <div className="value" style={accent ? { color: `var(--${accent})` } : undefined}>
        {value}{suffix ? <small> {suffix}</small> : null}
      </div>
    </div>
  );
}

export function Spinner() {
  return <span className="spinner" aria-label="loading" />;
}

export function Empty({ title, children }) {
  return (
    <div className="empty">
      <div className="big">{title}</div>
      {children}
    </div>
  );
}

const SEV_COLOR = {
  ok: 'var(--ok)', medium: 'var(--medium)', high: 'var(--high)',
  critical: 'var(--critical)', info: 'var(--info)', low: 'var(--low)',
};

/** Circular score gauge. `sev` picks the color; `value` is 0–100 (or null). */
export function ScoreRing({ value, grade, sev = 'info', size = 112 }) {
  const r = 46;
  const c = 2 * Math.PI * r;
  const pct = typeof value === 'number' ? Math.max(0, Math.min(value, 100)) / 100 : 0;
  const color = SEV_COLOR[sev] || SEV_COLOR.info;
  return (
    <div className="ring" style={{ width: size, height: size }}>
      <svg width={size} height={size} viewBox="0 0 112 112">
        <circle cx="56" cy="56" r={r} fill="none" stroke="var(--surface-2)" strokeWidth="9" />
        <circle cx="56" cy="56" r={r} fill="none" stroke={color} strokeWidth="9" strokeLinecap="round"
          strokeDasharray={c} strokeDashoffset={c - pct * c} transform="rotate(-90 56 56)"
          style={{ transition: 'stroke-dashoffset 0.6s ease, stroke 0.3s' }} />
      </svg>
      <div className="num">
        <b style={{ color }}>{value == null ? '—' : value}</b>
        <s>{grade ? `GRADE ${grade}` : 'SCORE'}</s>
      </div>
    </div>
  );
}
