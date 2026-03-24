import React from 'react';

const SSRF_PARAMS = ['url', 'uri', 'src', 'href', 'target', 'destination', 'redirect', 'redirect_to', 'redirect_url', 'return', 'return_to', 'next', 'continue', 'goto', 'load', 'file', 'path', 'image', 'img', 'proxy', 'forward', 'callback', 'webhook', 'feed', 'content', 'data', 'template', 'preview'];

const SsrfDetectionSection = ({ status, results }) => {
  return (
    <div className="acs-section-content">
      {/* 3 Layers */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1rem', marginBottom: '1.5rem' }}>
        {[
          { title: 'Form SSRF', type: 'Pasif', color: 'var(--accent-blue)', desc: 'HTML formlarındaki URL parametrelerini tespit' },
          { title: 'URL Param SSRF', type: 'Pasif', color: 'var(--accent-blue)', desc: 'Ziyaret edilen URL query parametrelerini kontrol' },
          { title: 'Aktif SSRF Probe', type: 'Aktif', color: 'var(--accent-red)', desc: 'API endpointlerine SSRF payload gönderim' },
        ].map(l => (
          <div key={l.title} className="glass-panel" style={{ padding: '1rem', borderTop: `3px solid ${l.color}` }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
              <strong style={{ fontSize: '0.9rem' }}>{l.title}</strong>
              <span className="acs-badge" style={{ background: l.type === 'Aktif' ? 'rgba(248, 81, 73, 0.15)' : 'rgba(88, 166, 255, 0.15)', color: l.color }}>{l.type}</span>
            </div>
            <p style={{ color: 'var(--text-secondary)', fontSize: '0.82rem' }}>{l.desc}</p>
          </div>
        ))}
      </div>

      {/* Form Detection Flow */}
      <div className="acs-flow-box">
        <h4 style={{ marginBottom: '1rem', color: 'var(--accent-blue)' }}>Form SSRF Tespit Koşulları</h4>
        <div className="acs-flow-steps">
          {[
            { step: '1', label: 'Parametre adı SSRF listesinde', desc: 'url, redirect, image, proxy, callback...' },
            { step: '2', label: 'Input type = "url"', desc: 'HTML5 URL alanı' },
            { step: '3', label: 'Değer http:// ile başlıyor', desc: 'URL içeren varsayılan değer' },
          ].map(s => (
            <div key={s.step} className="acs-flow-step">
              <div className="acs-flow-num">{s.step}</div>
              <div><strong>{s.label}</strong><p style={{ color: 'var(--text-secondary)', fontSize: '0.82rem', margin: '4px 0 0' }}>{s.desc}</p></div>
            </div>
          ))}
        </div>
      </div>

      {/* Active Probe */}
      <h4 style={{ margin: '1.5rem 0 0.8rem', fontSize: '0.9rem', color: 'var(--accent-red)', textTransform: 'uppercase' }}>Aktif Probe URL'leri</h4>
      <div className="acs-table-wrap">
        <table className="acs-table">
          <thead><tr><th>URL</th><th>Amaç</th></tr></thead>
          <tbody>
            <tr><td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>http://169.254.169.254/latest/meta-data/</td><td>AWS IMDSv1 metadata</td></tr>
            <tr><td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>http://metadata.google.internal/computeMetadata/v1/</td><td>GCP metadata</td></tr>
            <tr><td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>http://127.0.0.1:80</td><td>Localhost erişim testi</td></tr>
            <tr><td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--accent-purple)' }}>http://{'<hash>'}.{'<callback_domain>'}</td><td>OOB callback (opsiyonel)</td></tr>
          </tbody>
        </table>
      </div>

      {/* Confirmation criteria */}
      <div className="glass-panel" style={{ padding: '1rem', marginTop: '1.5rem', borderLeft: '4px solid var(--accent-green)' }}>
        <strong style={{ color: 'var(--accent-green)' }}>Doğrulama Kriteri</strong>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.88rem', marginTop: '0.5rem' }}>
          SSRF yalnızca sunucu yanıtındaki <code>Location</code> headerında probe URLsi yer aldığında <strong style={{ color: 'var(--accent-green)' }}>CONFIRMED</strong> olarak işaretlenir.
          Redirect yanıtları: 301, 302, 303, 307, 308
        </p>
      </div>

      {/* Comparison */}
      <h4 style={{ margin: '1.5rem 0 0.8rem', fontSize: '0.9rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Pasif vs Aktif Karşılaştırma</h4>
      <div className="acs-table-wrap">
        <table className="acs-table">
          <thead><tr><th>Alan</th><th>Pasif (Form/URL)</th><th>Aktif (Probe)</th></tr></thead>
          <tbody>
            <tr><td>confirmed</td><td>False</td><td style={{ color: 'var(--accent-green)', fontWeight: 700 }}>True</td></tr>
            <tr><td>severity</td><td>Medium</td><td style={{ color: 'var(--accent-orange)', fontWeight: 700 }}>High</td></tr>
            <tr><td>confidence</td><td>MEDIUM</td><td style={{ fontWeight: 700 }}>HIGH</td></tr>
          </tbody>
        </table>
      </div>

      {/* SSRF Params */}
      <h4 style={{ margin: '1.5rem 0 0.8rem', fontSize: '0.9rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>SSRF Parametre Listesi ({SSRF_PARAMS.length}+ parametre)</h4>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
        {SSRF_PARAMS.map(p => <span key={p} className="acs-badge" style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem' }}>{p}</span>)}
      </div>

      {results && <div className="acs-results-box"><h4>Sonuçlar</h4><pre className="json-view">{JSON.stringify(results, null, 2)}</pre></div>}
    </div>
  );
};

SsrfDetectionSection.meta = {
  id: 'ssrf_detection',
  title: 'SSRF Detection',
  icon: '🎯',
  layer: 'L1+L2',
  description: 'SSRF form/URL parametresi tespiti + aktif endpoint sondajı + OOB callback',
  docFile: '07-ssrf-detection.md',
};

export default SsrfDetectionSection;
