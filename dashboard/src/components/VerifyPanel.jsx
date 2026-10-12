import React, { useState } from 'react';
import { apiGet } from '../api/client';
import { useHealth } from '../context/health';
import { ACTIVE_MODULE_NAMES } from '../lib/analysis';
import { Badge, Spinner } from './ui';

/**
 * Domain ownership check for the public demo. The intrusive modules only run on
 * domains the owner has proven control of by publishing a DNS TXT record.
 * Renders nothing on self-hosted instances (the backend reports demo_mode).
 */
export default function VerifyPanel({ domain, compact = false }) {
  const demo = Boolean(useHealth()?.demo_mode);
  const [info, setInfo] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [copied, setCopied] = useState(null);

  if (!demo || !domain) return null;

  const check = async () => {
    setBusy(true);
    setError(null);
    try {
      setInfo(await apiGet(`/api/verify/${encodeURIComponent(domain)}`));
    } catch (err) {
      if (err.status === 429) setError('Too many checks — wait a few minutes and try again.');
      else if (err.status === 403) setError('That target is not allowed on this instance.');
      else setError('Could not check right now. Try again in a moment.');
    } finally {
      setBusy(false);
    }
  };

  const copy = async (key, text) => {
    try { await navigator.clipboard.writeText(text); setCopied(key); setTimeout(() => setCopied(null), 1500); } catch { /* clipboard unavailable */ }
  };

  const record = info?.record;
  return (
    <div className="verify">
      <div className="verify-head">
        <div>
          <b>Active modules need ownership verification</b>
          {!compact && (
            <div className="muted" style={{ marginTop: 3 }}>
              {ACTIVE_MODULE_NAMES.join(', ')} send intrusive traffic, so on this public demo they only run on
              domains you control. Everything else works without verification.
            </div>
          )}
        </div>
        {info?.verified
          ? <Badge sev="ok">verified</Badge>
          : <button type="button" className="btn sm" onClick={check} disabled={busy}>
              {busy ? <Spinner /> : null} {info ? 'Check again' : 'Verify ownership'}
            </button>}
      </div>

      {info?.verified && <div className="muted" style={{ marginTop: 10 }}>Ownership of {info.domain} is verified — all modules are available.</div>}

      {info && !info.verified && record && (
        <div style={{ marginTop: 12 }}>
          <div className="muted" style={{ marginBottom: 8 }}>
            Add this DNS record at your DNS provider, wait for it to propagate, then press “Check again”.
          </div>
          {[['Type', record.type, 'type'], ['Name', record.name, 'name'], ['Value', record.value, 'value']].map(([label, value, key]) => (
            <div className="record" key={key}>
              <span className="muted">{label}</span>
              <code>{value}</code>
              <button type="button" className="btn ghost sm" onClick={() => copy(key, value)}>{copied === key ? 'Copied' : 'Copy'}</button>
            </div>
          ))}
        </div>
      )}

      {error && <div className="muted" style={{ marginTop: 10, color: 'var(--critical)' }}>{error}</div>}
    </div>
  );
}
