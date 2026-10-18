import React, { useState } from 'react';
import { ScoreRing, Spinner, Icon } from '../ui';
import { SEVERITIES } from '../../lib/findings';
import { getApiUrl } from '../../config';

const LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };

export default function ResultsHeader({
  domain, score, grade, penalty, sev, status, moduleTotal, moduleOk, counts, totalFindings,
  onSeverity, onRescan, onCopyLink, busy,
}) {
  const scanning = status && status.current_module && status.current_module !== 'Finished';
  const enc = encodeURIComponent(domain);
  const [client, setClient] = useState('');
  const [author, setAuthor] = useState('');
  const params = new URLSearchParams();
  if (client.trim()) params.set('client', client.trim());
  if (author.trim()) params.set('author', author.trim());
  const reportUrl = getApiUrl(`/api/report/${enc}${params.toString() ? `?${params}` : ''}`);

  return (
    <div className="card">
      <div className="res-head">
        <ScoreRing value={score} grade={grade} sev={sev} />
        <div className="info">
          <h2>{domain}</h2>
          <div className="muted" style={{ marginTop: 3 }}>
            {scanning
              ? 'Scan in progress — results appear as each module finishes.'
              : `${moduleOk} of ${moduleTotal} modules completed · ${totalFindings} finding${totalFindings === 1 ? '' : 's'}`}
          </div>
          {!scanning && penalty > 0 && (
            <div className="muted" style={{ marginTop: 3, fontSize: 12 }} title="Findings from modules other than Security Analysis lower the score">
              Score includes −{penalty} for findings from other modules.
            </div>
          )}

          {scanning && (
            <div style={{ maxWidth: 460, marginTop: 12 }}>
              <div className="flex between" style={{ fontSize: 12, marginBottom: 6 }}>
                <span className="flex"><Spinner /> {status.current_module}</span>
                <span className="muted">{status.completed}/{status.total}</span>
              </div>
              <div className="bar"><i style={{ width: `${status.total ? (status.completed / status.total) * 100 : 0}%` }} /></div>
            </div>
          )}

          <div className="sevchips">
            {SEVERITIES.map((s) => (
              <button
                key={s}
                type="button"
                className={`sevchip ${counts[s] ? '' : 'zero'}`}
                onClick={() => onSeverity(s)}
                title={`Show ${LABEL[s].toLowerCase()} findings`}
              >
                <i style={{ background: `var(--${s})` }} />
                {LABEL[s]} <b>{counts[s] || 0}</b>
              </button>
            ))}
          </div>
        </div>

        <div className="res-actions">
          <details className="report-menu">
            <summary className="btn sm"><Icon name="external" size={15} /> Report</summary>
            <div className="report-pop">
              <label>Client name<input className="input" value={client} onChange={(e) => setClient(e.target.value)} placeholder="Acme Corp" maxLength={120} /></label>
              <label>Prepared by<input className="input" value={author} onChange={(e) => setAuthor(e.target.value)} placeholder="Your team" maxLength={120} /></label>
              <a className="btn sm primary" href={reportUrl} target="_blank" rel="noreferrer">Open report</a>
              <span className="muted" style={{ fontSize: 11.5 }}>Opens a printable page: choose Save as PDF.</span>
            </div>
          </details>
          <a className="btn sm" href={getApiUrl(`/api/export/${enc}/json`)} target="_blank" rel="noreferrer">JSON</a>
          <a className="btn sm" href={getApiUrl(`/api/export/${enc}/csv`)} target="_blank" rel="noreferrer">CSV</a>
          <button className="btn sm" type="button" onClick={onCopyLink}>Copy link</button>
          <button className="btn sm primary" type="button" onClick={onRescan} disabled={busy || scanning}>
            {busy ? 'Starting…' : 'Re-scan'}
          </button>
        </div>
      </div>
    </div>
  );
}
