import React from 'react';

const EXEC_ORDER = [
  { n: 1, layer: 'L1', method: 'crawl_website()', desc: 'Pasif crawl + JS/secret/header', cond: 'Her zaman' },
  { n: 2, layer: 'L2', method: '_scan_sensitive_paths()', desc: 'Hassas dosya yolu keşfi', cond: 'active_scan=True' },
  { n: 3, layer: 'L2', method: '_test_cors()', desc: 'CORS yapılandırma testi', cond: 'active + test_cors' },
  { n: 4, layer: 'L2', method: '_test_auth_bypass()', desc: '403 bypass denemeleri', cond: 'active + test_auth' },
  { n: 5, layer: 'L2', method: '_run_nuclei()', desc: 'Nuclei CVE tarama', cond: 'active + nuclei var' },
  { n: 6, layer: 'L1', method: '_probe_endpoint_ssrf()', desc: 'API SSRF sondajı', cond: 'api_endpoints > 0' },
  { n: 7, layer: 'L4', method: '_run_headless_scan()', desc: 'Playwright headless', cond: 'headless=True' },
  { n: 8, layer: 'L1', method: 'Dinamik rota işleme', desc: 'Headless rotaları tara', cond: 'dynamic_routes > 0' },
  { n: 9, layer: 'L5', method: '_build_exploit_chains()', desc: 'Exploit zincirleri', cond: 'build_chains=True' },
  { n: 10, layer: '—', method: '_build_summary()', desc: 'Özet rapor', cond: 'Her zaman' },
  { n: 11, layer: '—', method: '_save_findings()', desc: 'JSON kaydet', cond: 'Her zaman' },
  { n: 12, layer: '—', method: '_save_state()', desc: 'Durum kaydet', cond: 'Her zaman' },
];

const LAYER_COLORS = { L1: '#58a6ff', L2: '#d29922', L3: '#3fb950', L4: '#bc8cff', L5: '#f85149', '—': '#8b949e' };

const MainFlowSection = ({ status, results }) => {
  return (
    <div className="acs-section-content">
      <h4 style={{ margin: '0 0 1rem', fontSize: '0.9rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>run() Çalışma Sırası</h4>
      <div className="acs-table-wrap">
        <table className="acs-table">
          <thead><tr><th>#</th><th>Katman</th><th>Metot</th><th>Açıklama</th><th>Koşul</th></tr></thead>
          <tbody>
            {EXEC_ORDER.map(e => (
              <tr key={e.n}>
                <td style={{ fontWeight: 700 }}>{e.n}</td>
                <td><span style={{ color: LAYER_COLORS[e.layer], fontWeight: 700 }}>{e.layer}</span></td>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: 'var(--accent-blue)' }}>{e.method}</td>
                <td>{e.desc}</td>
                <td style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>{e.cond}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <h4 style={{ margin: '1.5rem 0 1rem', fontSize: '0.9rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>L3 Entegrasyonu</h4>
      <div className="glass-panel" style={{ padding: '1rem', borderLeft: '4px solid var(--accent-green)' }}>
        <p style={{ color: 'var(--text-secondary)', fontSize: '0.88rem', margin: 0 }}>
          L3 ayrı bir adım değildir — L1 crawl sırasında entegre çalışır:
          <strong style={{ color: 'var(--accent-green)' }}> Taint Flow</strong> → _analyze_js() içinde,
          <strong style={{ color: 'var(--accent-green)' }}> Entropi puanlama</strong> → _scan_secrets() içinde,
          <strong style={{ color: 'var(--accent-green)' }}> FP filtreleme</strong> → _fp_value() / _fp_context() ile
        </p>
      </div>

      <h4 style={{ margin: '1.5rem 0 1rem', fontSize: '0.9rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>JSON Çıktı Yapısı</h4>
      <pre className="json-view" style={{ fontSize: '0.78rem' }}>{JSON.stringify({
        secrets: ['[...]'], js_vulnerabilities: ['[...]'], ssrf_vulnerabilities: ['[...]'],
        active_vulnerabilities: ['[...]'], security_headers: ['[...]'], exposed_endpoints: ['[...]'],
        exploit_chains: ['[...]'],
        summary: { scanner_version: '4.0.0', domain: 'example.com', scan_duration_seconds: 45.23,
          total_urls_crawled: 150, total_js_files: 42, overall_risk_score: 7.5, security_grade: 'D' }
      }, null, 2)}</pre>

      {results && <div className="acs-results-box"><h4>Sonuçlar</h4><pre className="json-view">{JSON.stringify(results, null, 2)}</pre></div>}
    </div>
  );
};

MainFlowSection.meta = {
  id: 'main_flow', title: 'Ana Akış (run())', icon: '🚀', layer: 'ALL',
  description: 'run() çalışma sırası, L3 entegrasyonu, JSON çıktı yapısı',
  docFile: '13-ana-akis.md',
};

export default MainFlowSection;
