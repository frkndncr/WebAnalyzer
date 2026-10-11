import React, { useMemo, useState } from 'react';
import { Badge, Empty } from '../ui';
import { SEVERITIES, countBySeverity, filterFindings, groupFindings, findingsToText } from '../../lib/findings';

const INSTANCE_PAGE = 8;

function FindingGroup({ group }) {
  const [shown, setShown] = useState(INSTANCE_PAGE);
  const first = group.items[0];
  const many = group.items.length > 1;

  return (
    <details className="finding" style={{ borderLeftColor: `var(--${group.severity})` }}>
      <summary>
        <Badge sev={group.severity}>{group.severity}</Badge>
        <span className="ttl">{group.title}<span className="mod">{group.module}</span></span>
        {many && <span className="times">×{group.items.length}</span>}
      </summary>

      <div className="fbody">
        {first.description && (<><div className="lbl">What it means</div><div>{first.description}</div></>)}
        {first.recommendation && (<><div className="lbl">How to fix</div><div>{first.recommendation}</div></>)}

        <div className="lbl">{many ? `Where (${group.items.length})` : 'Where'}</div>
        {group.items.slice(0, shown).map((it) => (
          <div className="instance" key={it.id}>
            {it.location ? <div className="loc">{it.location}</div> : <div className="muted">No location reported.</div>}
            {it.evidence && <pre className="code">{it.evidence.length > 400 ? `${it.evidence.slice(0, 400)}…` : it.evidence}</pre>}
          </div>
        ))}
        {group.items.length > shown && (
          <button type="button" className="btn ghost sm" onClick={() => setShown((n) => n + INSTANCE_PAGE)}>
            Show {Math.min(INSTANCE_PAGE, group.items.length - shown)} more
          </button>
        )}
      </div>
    </details>
  );
}

export default function FindingsTab({ domain, findings, severity, setSeverity, onCopy }) {
  const [query, setQuery] = useState('');
  const counts = useMemo(() => countBySeverity(findings), [findings]);
  const groups = useMemo(
    () => groupFindings(filterFindings(findings, { severity, query })),
    [findings, severity, query],
  );

  return (
    <div className="fade">
      <div className="toolbar">
        <input
          className="input"
          placeholder="Search findings…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          aria-label="Search findings"
        />
        <button type="button" className={`sevchip ${severity === 'all' ? 'active' : ''}`} onClick={() => setSeverity('all')}>
          All <b>{findings.length}</b>
        </button>
        {SEVERITIES.map((s) => (
          <button
            key={s}
            type="button"
            className={`sevchip ${severity === s ? 'active' : ''} ${counts[s] ? '' : 'zero'}`}
            onClick={() => setSeverity(severity === s ? 'all' : s)}
          >
            <i style={{ background: `var(--${s})` }} />
            {s[0].toUpperCase() + s.slice(1)} <b>{counts[s] || 0}</b>
          </button>
        ))}
        <span className="grow">
          <button
            type="button"
            className="btn sm"
            disabled={groups.length === 0}
            onClick={() => onCopy(findingsToText(domain, groups))}
          >
            Copy as text
          </button>
        </span>
      </div>

      {groups.length === 0 ? (
        <Empty title={findings.length === 0 ? 'No findings' : 'Nothing matches your filters'}>
          <div>{findings.length === 0 ? 'This scan did not report any issues.' : 'Try a different severity or search term.'}</div>
        </Empty>
      ) : groups.map((g) => <FindingGroup key={g.key} group={g} />)}
    </div>
  );
}
