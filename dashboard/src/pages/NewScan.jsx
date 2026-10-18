import React, { useState } from 'react';
import { apiPost, ApiError } from '../api/client';
import { cleanDomain } from '../lib/analysis';
import { useCatalogue } from '../context/catalogue';
import VerifyPanel from '../components/VerifyPanel';
import { Icon } from '../components/ui';

const PRESET_BTNS = [
  { id: 'quick', label: 'Quick' },
  { id: 'standard', label: 'Standard' },
  { id: 'full', label: 'Full' },
];

export default function NewScan({ onLaunched }) {
  const { modules, presets, activeNames } = useCatalogue();
  const [domain, setDomain] = useState('');
  const [selected, setSelected] = useState(() => new Set(presets.standard));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  const toggle = (name) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name); else next.add(name);
      return next;
    });
  };
  const applyPreset = (id) => setSelected(new Set(presets[id]));

  const launch = async (e) => {
    e.preventDefault();
    setError(null);
    const d = cleanDomain(domain);
    if (!d) { setError('Enter a domain to scan.'); return; }
    if (selected.size === 0) { setError('Select at least one module.'); return; }

    setBusy(true);
    try {
      await apiPost('/api/scan', { domain: d, modules: [...selected] });
      onLaunched(d);
    } catch (err) {
      if (err instanceof ApiError && err.detail?.code === 'verification_required') {
        setError('Only active modules were selected. Verify ownership below, or add a passive module such as DNS Records.');
      } else if (err instanceof ApiError && err.status === 403) {
        setError('That target is not allowed on this instance (internal/private addresses are blocked).');
      } else if (err instanceof ApiError && err.status === 429) {
        setError('Rate limit reached — please wait a moment and try again.');
      } else {
        setError('Could not reach the API. Is the backend running on port 8000?');
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="fade" onSubmit={launch}>
      <div className="card">
        <div className="card-title">Target</div>
        <input
          className="input"
          placeholder="example.com"
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          autoFocus
          style={{ fontSize: 16 }}
        />
        <div className="flex wrap mt">
          {PRESET_BTNS.map((p) => (
            <button type="button" key={p.id} className="btn sm" onClick={() => applyPreset(p.id)}>
              {p.label} <span className="muted">· {p.id === 'full' ? 'all ' : ''}{presets[p.id].length}{p.id === 'full' ? '' : ' modules'}</span>
            </button>
          ))}
          <span className="muted" style={{ marginLeft: 'auto' }}>{selected.size} selected</span>
        </div>
      </div>

      <div className="card mt">
        <div className="card-title">
          Modules
          <span className="flex" style={{ gap: 6 }}>
            <button type="button" className="btn ghost sm" onClick={() => setSelected(new Set(presets.full))}>All</button>
            <button type="button" className="btn ghost sm" onClick={() => setSelected(new Set())}>None</button>
          </span>
        </div>
        <div className="mod-grid">
          {modules.map((m) => {
            const on = selected.has(m.name);
            return (
              <div key={m.name} className={`mod ${on ? 'on' : ''}`} onClick={() => toggle(m.name)}>
                <span className="box">{on ? '✓' : ''}</span>
                <div>
                  <div className="nm">{m.name}</div>
                  <div className="ds">{m.description}</div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {cleanDomain(domain) && activeNames.some((n) => selected.has(n)) && (
        <VerifyPanel key={cleanDomain(domain)} domain={cleanDomain(domain)} />
      )}

      {error && <div className="toast err">{error}</div>}

      <div className="flex between mt">
        <span className="muted">
          Only scan assets you own or are authorized to test.
        </span>
        <button type="submit" className="btn primary" disabled={busy}>
          {busy ? <>Launching…</> : <>Launch scan <Icon name="scan" size={16} /></>}
        </button>
      </div>
    </form>
  );
}
