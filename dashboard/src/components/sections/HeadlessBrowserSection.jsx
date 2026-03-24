import React from 'react';

const HeadlessBrowserSection = ({ status, results }) => {
  return (
    <div className="acs-section-content">
      <div style={{ padding: '0.8rem', marginBottom: '1.5rem', background: 'rgba(188, 140, 255, 0.08)', borderRadius: '6px', border: '1px solid rgba(188, 140, 255, 0.15)' }}>
        <strong style={{ color: 'var(--accent-purple)' }}>Opsiyonel: </strong>
        <span style={{ color: 'var(--text-secondary)', fontSize: '0.88rem' }}>
          <code>playwright install chromium</code> gerektirir. Kurulu değilse atlanır.
        </span>
      </div>

      <div className="acs-flow-box">
        <h4 style={{ marginBottom: '1rem', color: 'var(--accent-purple)' }}>Headless Akışı</h4>
        <div className="acs-flow-steps">
          {[
            { step: '1', label: 'Chromium Başlat', desc: 'headless, no-sandbox' },
            { step: '2', label: 'Sayfaya Git', desc: 'networkidle bekle (20s)' },
            { step: '3', label: 'Runtime Secret', desc: 'window: secret|token|key|password' },
            { step: '4', label: 'Storage Tara', desc: 'localStorage + sessionStorage' },
            { step: '5', label: 'Network Yakala', desc: 'HTTP istekleri → API keşfi' },
            { step: '6', label: 'SPA Rotaları', desc: 'nav bağlantıları (max 15)' },
            { step: '7', label: 'Rendered HTML', desc: '_scan_secrets()' },
          ].map(s => (
            <div key={s.step} className="acs-flow-step">
              <div className="acs-flow-num" style={{ background: 'rgba(188, 140, 255, 0.15)', color: 'var(--accent-purple)' }}>{s.step}</div>
              <div><strong>{s.label}</strong><p style={{ color: 'var(--text-secondary)', fontSize: '0.82rem', margin: '4px 0 0' }}>{s.desc}</p></div>
            </div>
          ))}
        </div>
      </div>

      <h4 style={{ margin: '1.5rem 0 0.8rem', fontSize: '0.9rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Hata Yönetimi</h4>
      <div className="acs-table-wrap">
        <table className="acs-table">
          <thead><tr><th>Hata</th><th>Davranış</th></tr></thead>
          <tbody>
            <tr><td>PWTimeout</td><td>Uyarı logu, devam eder</td></tr>
            <tr><td>Exception</td><td>Hata logu, devam eder</td></tr>
            <tr><td>ImportError</td><td>L4 tamamen atlanır</td></tr>
          </tbody>
        </table>
      </div>

      {results && <div className="acs-results-box"><h4>Sonuçlar</h4><pre className="json-view">{JSON.stringify(results, null, 2)}</pre></div>}
    </div>
  );
};

HeadlessBrowserSection.meta = {
  id: 'headless_browser', title: 'Headless Browser', icon: '🌐', layer: 'L4',
  description: 'Playwright: runtime secret, storage, network, SPA keşfi',
  docFile: '09-headless-browser.md',
};

export default HeadlessBrowserSection;
