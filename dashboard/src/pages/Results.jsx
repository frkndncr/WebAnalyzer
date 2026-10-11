import React, { useEffect, useState } from 'react';
import { apiRequest } from '../api/client';
import { getApiUrl } from '../config';
import { extractScore, scoreSeverity, cleanDomain } from '../lib/analysis';
import { ScoreRing, Empty, Spinner, Icon, Badge } from '../components/ui';
import ResultRenderer from '../components/ResultRenderer';

export default function Results({ domain }) {
  const [target, setTarget] = useState(domain || '');
  const [input, setInput] = useState(domain || '');
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Note: App renders this component with key={domain}, so it remounts (and
  // re-initialises target/input from the prop) whenever the selected domain
  // changes — no prop→state sync effect needed.
  useEffect(() => {
    if (!target) return undefined;
    let stop = false;
    let timer;
    const controller = new AbortController();

    const tick = async (showLoad) => {
      if (showLoad) { setLoading(true); setError(null); setData(null); }
      try {
        const d = await apiRequest(`/api/status/${encodeURIComponent(target)}`, { signal: controller.signal });
        if (stop) return;
        setData(d);
        setError(null);
        setLoading(false);
        if (d.current_module === 'Finished') { stop = true; clearInterval(timer); }
      } catch (err) {
        if (controller.signal.aborted) return;
        setLoading(false);
        setData(null);
        if (err?.status === 404) setError('No results for this domain yet — launch a scan from New Scan.');
        else if (err?.status) setError('The backend did not return results.');
        else setError('Cannot reach the API.');
        clearInterval(timer);
      }
    };

    tick(true);
    timer = setInterval(() => tick(false), 2500);
    return () => { stop = true; clearInterval(timer); controller.abort(); };
  }, [target]);

  const submit = (e) => {
    e.preventDefault();
    const d = cleanDomain(input);
    if (d) setTarget(d);
  };

  const results = data?.results || null;
  const scanning = data && data.current_module && data.current_module !== 'Finished';
  const { score, grade } = extractScore(results?.['Security Analysis']?.security_score);
  const sev = scoreSeverity(score);

  return (
    <div className="fade">
      <form className="flex" onSubmit={submit} style={{ marginBottom: 20 }}>
        <input
          className="input"
          placeholder="Look up a domain…"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          style={{ maxWidth: 420 }}
        />
        <button className="btn" type="submit"><Icon name="search" size={16} /> Load</button>
        {target && results && (
          <div className="flex" style={{ marginLeft: 'auto', gap: 8 }}>
            <a className="btn sm" href={getApiUrl(`/api/report/${encodeURIComponent(target)}`)} target="_blank" rel="noreferrer">
              <Icon name="external" size={15} /> Report
            </a>
            <a className="btn sm" href={getApiUrl(`/api/export/${encodeURIComponent(target)}/json`)} target="_blank" rel="noreferrer">JSON</a>
            <a className="btn sm" href={getApiUrl(`/api/export/${encodeURIComponent(target)}/csv`)} target="_blank" rel="noreferrer">CSV</a>
          </div>
        )}
      </form>

      {!target && <Empty title="No domain selected"><div>Load a domain above, or start one from New Scan.</div></Empty>}

      {target && loading && <Empty title={<span><Spinner /> Loading {target}…</span>} />}

      {target && error && <Empty title={target}><div className="muted">{error}</div></Empty>}

      {target && data && !error && (
        <>
          <div className="card" style={{ marginBottom: 18 }}>
            <div className="ring-wrap">
              <ScoreRing value={score} grade={grade} sev={sev} />
              <div style={{ flex: 1 }}>
                <h2 style={{ fontSize: 20 }}>{target}</h2>
                <div className="muted" style={{ marginTop: 2 }}>
                  {results ? `${Object.keys(results).length} modules` : 'no modules'}
                  {score != null && <> · security score <Badge sev={sev}>{score}/100{grade ? ` (${grade})` : ''}</Badge></>}
                </div>
                {scanning && (
                  <div className="mt" style={{ maxWidth: 460 }}>
                    <div className="flex between" style={{ fontSize: 12, marginBottom: 6 }}>
                      <span className="flex"><Spinner /> {data.current_module}</span>
                      <span className="muted">{data.completed}/{data.total}</span>
                    </div>
                    <div className="bar"><i style={{ width: `${data.total ? (data.completed / data.total) * 100 : 0}%` }} /></div>
                  </div>
                )}
              </div>
            </div>
          </div>

          <ResultRenderer results={results} />
        </>
      )}
    </div>
  );
}
