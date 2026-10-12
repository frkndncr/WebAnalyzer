import React, { useState } from 'react';
import { apiPost, ApiError } from '../api/client';
import { PRESETS, dbProblem } from '../lib/analysis';
import { useHealth } from '../context/health';
import { Empty, Spinner } from './ui';
import VerifyPanel from './VerifyPanel';

/**
 * Shown by the analysis pages instead of an empty (all-zero) view. While a scan
 * is running it shows real progress; with no data it offers a one-click scan.
 * Scans start through POST /api/scan, which enforces the demo guards.
 */
export default function ScanGate({ domain, data, reload }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const dbDown = Boolean(dbProblem(useHealth()));

  const start = async () => {
    setBusy(true);
    setError(null);
    try {
      await apiPost('/api/scan', { domain, modules: PRESETS.full });
      reload();
    } catch (err) {
      if (err instanceof ApiError && err.status === 403) setError('That target is not allowed on this instance.');
      else if (err instanceof ApiError && err.status === 429) setError('Rate limit reached — try again in a few minutes.');
      else setError('Could not start the scan. Is the API reachable?');
    } finally {
      setBusy(false);
    }
  };

  if (data?.is_scanning) {
    const p = data.scan_progress || {};
    const pct = p.total ? Math.min((p.completed / p.total) * 100, 100) : 0;
    return (
      <div className="card fade" style={{ maxWidth: 560 }}>
        <div className="flex" style={{ marginBottom: 12 }}>
          <Spinner /> <b>Scanning {domain}…</b>
        </div>
        <div className="bar"><i style={{ width: `${pct}%` }} /></div>
        <div className="flex between mt" style={{ fontSize: 12.5 }}>
          <span className="muted">{p.current_module || 'Starting…'}</span>
          <span className="muted">{p.completed ?? 0}/{p.total ?? 16} modules</span>
        </div>
        <div className="muted mt" style={{ fontSize: 12.5 }}>
          This page fills in automatically when the scan finishes.
        </div>
      </div>
    );
  }

  return (
    <Empty title={dbDown ? 'Saved results are unavailable' : `No data for ${domain} yet`}>
      <div style={{ marginBottom: 14 }}>
        {dbDown
          ? 'The database is offline, so earlier scans of this domain cannot be loaded. You can still run a new scan.'
          : 'This domain has not been scanned. Run a full scan to populate this view.'}
      </div>
      <button className="btn primary" type="button" disabled={busy} onClick={start}>
        {busy ? 'Starting…' : `Scan ${domain}`}
      </button>
      {error && <div className="muted" style={{ marginTop: 12, color: 'var(--critical)' }}>{error}</div>}
      <div style={{ maxWidth: 560, margin: '18px auto 0', textAlign: 'left' }}><VerifyPanel domain={domain} compact /></div>
    </Empty>
  );
}
