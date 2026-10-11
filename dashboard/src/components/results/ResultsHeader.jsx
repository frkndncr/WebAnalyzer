import React from 'react';
import { ScoreRing, Spinner, Icon } from '../ui';
import { SEVERITIES } from '../../lib/findings';
import { getApiUrl } from '../../config';

const LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };

export default function ResultsHeader({
  domain, score, grade, sev, status, moduleTotal, moduleOk, counts, totalFindings,
  onSeverity, onRescan, onCopyLink, busy,
}) {
  const scanning = status && status.current_module && status.current_module !== 'Finished';
  const enc = encodeURIComponent(domain);

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
          <a className="btn sm" href={getApiUrl(`/api/report/${enc}`)} target="_blank" rel="noreferrer">
            <Icon name="external" size={15} /> Report
          </a>
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
