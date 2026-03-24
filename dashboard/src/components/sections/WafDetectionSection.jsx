import React from 'react';

const WAF_SIGS = [
  { name: 'Cloudflare', sigs: 'cf-ray, cloudflare, __cfduid, cf_clearance' },
  { name: 'Akamai', sigs: 'akamai, akamaighost, x-akamai' },
  { name: 'Imperva', sigs: 'x-iinfo, x-cdn, incap_ses, visid_incap' },
  { name: 'AWS WAF', sigs: 'x-amzn-requestid, x-amz-cf-id' },
  { name: 'Sucuri', sigs: 'x-sucuri-id, x-sucuri-cache' },
  { name: 'F5 BIG-IP', sigs: 'bigipserver, f5-bigip' },
  { name: 'ModSecurity', sigs: 'mod_security, modsecurity' },
  { name: 'Fortinet', sigs: 'fortigate, fortiweb' },
  { name: 'Barracuda', sigs: 'barra_counter_session' },
];

const WafDetectionSection = ({ status, results }) => {
  return (
    <div className="acs-section-content">
      <div className="acs-flow-box">
        <h4 style={{ marginBottom: '1rem', color: 'var(--accent-red)' }}>WAF Tespit + Adaptif Akışı</h4>
        <div className="acs-flow-steps">
          {[
            { step: '1', label: 'WAF İmza Tarama', desc: 'Headers + body (ilk 2000 char) → 9 WAF markası kontrolü' },
            { step: '2', label: 'Rate Limit Yükselt', desc: 'WAF tespitinde: rate_limit = max(mevcut, 0.5s)' },
            { step: '3', label: 'Blok Kontrolü', desc: '403/406/429/503 + blocked/forbidden/access denied?' },
            { step: '4', label: 'Backoff Stratejisi', desc: '5+ blok → 3s hard backoff, sayaç sıfırla' },
          ].map(s => (
            <div key={s.step} className="acs-flow-step">
              <div className="acs-flow-num" style={{ background: 'rgba(248, 81, 73, 0.15)', color: 'var(--accent-red)' }}>{s.step}</div>
              <div><strong>{s.label}</strong><p style={{ color: 'var(--text-secondary)', fontSize: '0.82rem', margin: '4px 0 0' }}>{s.desc}</p></div>
            </div>
          ))}
        </div>
      </div>

      <h4 style={{ margin: '1.5rem 0 0.8rem', fontSize: '0.9rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>WAF İmza Veritabanı</h4>
      <div className="acs-table-wrap">
        <table className="acs-table">
          <thead><tr><th>WAF</th><th>İmzalar</th></tr></thead>
          <tbody>
            {WAF_SIGS.map(w => (
              <tr key={w.name}>
                <td style={{ fontWeight: 600, color: 'var(--accent-blue)' }}>{w.name}</td>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }}>{w.sigs}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <h4 style={{ margin: '1.5rem 0 0.8rem', fontSize: '0.9rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Adaptif Strateji</h4>
      <div className="acs-table-wrap">
        <table className="acs-table">
          <thead><tr><th>Olay</th><th>Aksiyon</th></tr></thead>
          <tbody>
            <tr><td>İlk WAF tespiti</td><td>Rate limit ≥ 0.5s, log</td></tr>
            <tr><td>1-5 blok</td><td>Sayaç artır, devam</td></tr>
            <tr><td>5+ blok</td><td style={{ color: 'var(--accent-red)', fontWeight: 700 }}>3s backoff, sıfırla</td></tr>
            <tr><td>SSL Hatası</td><td>SSL verify kapat, tekrar dene</td></tr>
          </tbody>
        </table>
      </div>

      {results && <div className="acs-results-box"><h4>Sonuçlar</h4><pre className="json-view">{JSON.stringify(results, null, 2)}</pre></div>}
    </div>
  );
};

WafDetectionSection.meta = {
  id: 'waf_detection', title: 'WAF Detection', icon: '🛡️', layer: 'L5',
  description: '9 WAF markası tespiti, adaptif rate limiting, blok yönetimi',
  docFile: '11-waf-detection.md',
};

export default WafDetectionSection;
