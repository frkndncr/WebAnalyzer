import React from 'react';
import { Badge } from '../ui';
import { scoreSeverity } from '../../lib/analysis';
import { groupFindings, parseRecommendations, scoreBreakdown, extractFacts } from '../../lib/findings';

export default function SummaryTab({ results, findings, onViewFindings }) {
  const breakdown = scoreBreakdown(results);
  const facts = extractFacts(results);
  const top = groupFindings(findings).slice(0, 5);
  const recos = parseRecommendations(results?.['Security Analysis']?.recommendations).slice(0, 6);

  return (
    <div className="fade grid cols-2" style={{ alignItems: 'start' }}>
      <div className="grid" style={{ gap: 16 }}>
        <div className="card">
          <div className="card-title">
            Top issues
            {findings.length > 0 && (
              <button className="btn ghost sm" type="button" onClick={onViewFindings}>View all {findings.length} →</button>
            )}
          </div>
          {top.length === 0 ? (
            <div className="muted">No findings were detected for this scan.</div>
          ) : top.map((g) => (
            <div className="issue" key={g.key}>
              <div style={{ minWidth: 0 }}>
                <div className="t">{g.title}{g.items.length > 1 ? ` ×${g.items.length}` : ''}</div>
                <div className="m">{g.module}</div>
              </div>
              <Badge sev={g.severity}>{g.severity}</Badge>
            </div>
          ))}
        </div>

        <div className="card">
          <div className="card-title">What to fix first</div>
          {recos.length === 0 ? (
            <div className="muted">Run the Security Analysis module to get prioritized recommendations.</div>
          ) : recos.map((r, i) => (
            <div className="reco" key={i}>
              <Badge sev={r.severity}>{r.severity}</Badge>
              <span>{r.text}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="grid" style={{ gap: 16 }}>
        {breakdown.length > 0 && (
          <div className="card">
            <div className="card-title">Score breakdown</div>
            {breakdown.map((b) => (
              <div className="metric" key={b.key}>
                <div className="top"><span className="muted">{b.label}</span><b>{b.value}/100</b></div>
                <div className="meter">
                  <i style={{ width: `${Math.max(0, Math.min(b.value, 100))}%`, background: `var(--${scoreSeverity(b.value)})` }} />
                </div>
              </div>
            ))}
          </div>
        )}

        <div className="card">
          <div className="card-title">At a glance</div>
          {facts.length === 0 ? (
            <div className="muted">No details yet — they appear as modules finish.</div>
          ) : (
            <div className="facts">
              {facts.map((f) => (
                <div className="fact" key={f.label}>
                  <span className="l">{f.label}</span>
                  <span className={`v ${f.tone ? `tone-${f.tone}` : ''}`}>{f.value}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
