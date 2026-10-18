import React, { useEffect, useMemo, useState } from 'react';
import { apiRequest, apiPost, ApiError } from '../api/client';
import { scoreSeverity } from '../lib/analysis';
import { useCatalogue } from '../context/catalogue';
import { extractFindings, countBySeverity, moduleStatus, postureScore } from '../lib/findings';
import { Empty, Spinner } from '../components/ui';
import DomainBar from '../components/DomainBar';
import ResultsHeader from '../components/results/ResultsHeader';
import SummaryTab from '../components/results/SummaryTab';
import FindingsTab from '../components/results/FindingsTab';
import ModulesTab from '../components/results/ModulesTab';

export default function Results({ domain, setDomain }) {
  const { names, presets } = useCatalogue();
  const [tab, setTab] = useState('summary');
  const [severity, setSeverity] = useState('all');
  const [reload, setReload] = useState(0);
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(Boolean(domain));
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const [toast, setToast] = useState(null);

  // App renders this page with key={domain}, so tab/filter state resets when the
  // domain changes and `domain` never needs to be mirrored into local state.
  useEffect(() => {
    if (!domain) return undefined;
    let stop = false;
    let timer;
    const controller = new AbortController();

    const tick = async (first) => {
      if (first) { setLoading(true); setError(null); setData(null); }
      try {
        const d = await apiRequest(`/api/status/${encodeURIComponent(domain)}`, { signal: controller.signal });
        if (stop) return;
        setData(d);
        setError(null);
        setLoading(false);
        if (d.current_module === 'Finished') { stop = true; clearInterval(timer); }
      } catch (err) {
        if (controller.signal.aborted) return;
        setLoading(false);
        setData(null);
        setError(err?.status === 404 ? 'not-found' : err?.status ? 'server' : 'offline');
        clearInterval(timer);
      }
    };

    tick(true);
    timer = setInterval(() => tick(false), 2500);
    return () => { stop = true; clearInterval(timer); controller.abort(); };
  }, [domain, reload]);

  const results = data?.results || null;
  const findings = useMemo(() => extractFindings(results), [results]);
  const counts = useMemo(() => countBySeverity(findings), [findings]);

  const say = (msg, isError = false) => {
    setToast({ msg, isError });
    setTimeout(() => setToast(null), 2600);
  };

  const copy = async (text, label = 'Copied to clipboard') => {
    try { await navigator.clipboard.writeText(text); say(label); } catch { say('Could not copy', true); }
  };

  const copyLink = () => copy(`${window.location.origin}${window.location.pathname}#/results/${encodeURIComponent(domain)}`, 'Link copied');

  const startScan = async (modules) => {
    setBusy(true);
    try {
      await apiPost('/api/scan', { domain, modules });
      setReload((n) => n + 1);
      setTab('summary');
    } catch (err) {
      if (err instanceof ApiError && err.status === 403) say('That target is not allowed on this instance.', true);
      else if (err instanceof ApiError && err.status === 429) say('Rate limit reached — try again in a few minutes.', true);
      else say('Could not start the scan. Is the API reachable?', true);
    } finally {
      setBusy(false);
    }
  };

  const rescan = () => {
    const known = new Set(names);
    const previous = Object.keys(results || {}).filter((n) => known.has(n));
    startScan(previous.length ? previous : presets.standard);
  };

  const { score, grade, penalty } = postureScore(results);
  const moduleTotal = results ? Object.keys(results).length : 0;
  const moduleOk = results ? Object.values(results).filter((d) => moduleStatus(d) !== 'error').length : 0;
  const scanning = Boolean(data && data.current_module && data.current_module !== 'Finished');

  const goFindings = (sev) => { setSeverity(sev); setTab('findings'); };

  const body = () => {
    if (!domain) {
      return <Empty title="Pick a domain"><div>Search above, choose one from Overview, or start a new scan.</div></Empty>;
    }
    if (loading) return <Empty title={<span><Spinner /> Loading {domain}…</span>} />;
    if (error === 'not-found') {
      return (
        <Empty title={`No results for ${domain} yet`}>
          <div style={{ marginBottom: 14 }}>It has not been scanned. Run a standard scan to get started.</div>
          <button className="btn primary" type="button" disabled={busy} onClick={() => startScan(presets.standard)}>
            {busy ? 'Starting…' : `Scan ${domain}`}
          </button>
        </Empty>
      );
    }
    if (error) {
      return (
        <Empty title="Something went wrong">
          <div>{error === 'offline' ? 'Cannot reach the API.' : 'The backend did not return results.'}</div>
        </Empty>
      );
    }
    if (!data) return null;

    return (
      <>
        <ResultsHeader
          domain={domain}
          score={score}
          grade={grade}
          penalty={penalty}
          sev={scoreSeverity(score)}
          status={data}
          moduleTotal={scanning ? data.total : moduleTotal}
          moduleOk={moduleOk}
          counts={counts}
          totalFindings={findings.length}
          onSeverity={goFindings}
          onRescan={rescan}
          onCopyLink={copyLink}
          busy={busy}
        />

        <div className="tabs" role="tablist">
          {[
            ['summary', 'Summary'],
            ['findings', 'Findings', findings.length],
            ['modules', 'Modules', moduleTotal],
          ].map(([id, label, count]) => (
            <button key={id} role="tab" aria-selected={tab === id} className={`tab ${tab === id ? 'active' : ''}`} onClick={() => setTab(id)}>
              {label}{count !== undefined && <span className="count">{count}</span>}
            </button>
          ))}
        </div>

        {tab === 'summary' && <SummaryTab results={results} findings={findings} onViewFindings={() => goFindings('all')} />}
        {tab === 'findings' && (
          <FindingsTab domain={domain} findings={findings} severity={severity} setSeverity={setSeverity} onCopy={(t) => copy(t, 'Findings copied')} />
        )}
        {tab === 'modules' && <ModulesTab results={results || {}} onCopy={(t) => copy(t, 'JSON copied')} />}
      </>
    );
  };

  return (
    <div className="fade">
      <DomainBar initial={domain} onSubmit={setDomain} placeholder="Look up a domain…" />
      {body()}
      {toast && <div className={`toast ${toast.isError ? 'err' : ''}`}>{toast.msg}</div>}
    </div>
  );
}
