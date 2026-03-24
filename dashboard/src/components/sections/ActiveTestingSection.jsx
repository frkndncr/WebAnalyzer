import React, { useState } from 'react';

const BYPASS_HEADERS = [
  { header: 'X-Original-URL', value: '/admin' },{ header: 'X-Rewrite-URL', value: '/admin' },
  { header: 'X-Custom-IP-Authorization', value: '127.0.0.1' },{ header: 'X-Forwarded-For', value: '127.0.0.1' },
  { header: 'X-Forward-For', value: '127.0.0.1' },{ header: 'X-Remote-IP', value: '127.0.0.1' },
  { header: 'X-Originating-IP', value: '127.0.0.1' },{ header: 'X-Remote-Addr', value: '127.0.0.1' },
  { header: 'X-Client-IP', value: '127.0.0.1' },
];
const SQLI_ERRORS = ['sql syntax', 'mysql_fetch', 'ora-01756', 'microsoft ole db', 'unclosed quotation', 'pg_query', 'sqlite_', 'syntax error'];

const ActiveTestingSection = ({ status, results }) => {
  const [tab, setTab] = useState('fuzz');
  const tabs = [
    { id: 'fuzz', label: '💣 Form Fuzzing' },
    { id: 'auth', label: '🔓 Auth Bypass' },
    { id: 'cors', label: '🌐 CORS Test' },
    { id: 'nuclei', label: '☢️ Nuclei' },
    { id: 'paths', label: '📂 Sensitive Paths' },
  ];

  return (
    <div className="acs-section-content">
      <div className="acs-subtabs">
        {tabs.map(t => (
          <button key={t.id} className={`acs-subtab ${tab === t.id ? 'active' : ''}`} onClick={() => setTab(t.id)}>{t.label}</button>
        ))}
      </div>

      {tab === 'fuzz' && (
        <div>
          <div className="acs-flow-box">
            <h4 style={{ marginBottom: '1rem', color: 'var(--accent-blue)' }}>Form Fuzzing Akışı</h4>
            <div className="acs-flow-steps">
              {[
                { step: '1', label: 'Form Bul (max 3/sayfa)', desc: 'submit, hidden, button alanları hariç' },
                { step: '2', label: 'XSS / SQLi / SSTI test', desc: 'Her tür için payload gönderilir' },
                { step: '3', label: 'XSS: DOM-level doğrulama', desc: 'BeautifulSoup ile gerçek excutable XSS kontrolü. 3 aşama: event handler, script tag, javascript: protocol' },
                { step: '4', label: 'SQLi: Hata tespiti', desc: 'sql syntax, mysql_fetch, pg_query vb.' },
                { step: '5', label: 'SSTI: Diferansiyel test', desc: 'Baseline → {{7*7}}→49 → {{8*8}}→64: tümü doğru ise CONFIRMED' },
              ].map(s => (
                <div key={s.step} className="acs-flow-step">
                  <div className="acs-flow-num">{s.step}</div>
                  <div><strong>{s.label}</strong><p style={{ color: 'var(--text-secondary)', fontSize: '0.82rem', margin: '4px 0 0' }}>{s.desc}</p></div>
                </div>
              ))}
            </div>
          </div>
          <h4 style={{ margin: '1rem 0 0.5rem', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>SQLi Hata Anahtar Kelimeleri</h4>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
            {SQLI_ERRORS.map(e => <span key={e} className="acs-badge" style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem' }}>{e}</span>)}
          </div>
        </div>
      )}

      {tab === 'auth' && (
        <div>
          <p style={{ color: 'var(--text-secondary)', marginBottom: '1rem' }}>403 döndüren sayfalarda header ve path tabanlı bypass denemeleri yapılır.</p>
          <h4 style={{ fontSize: '0.9rem', color: 'var(--accent-orange)', marginBottom: '0.5rem' }}>Bypass Headerları</h4>
          <div className="acs-table-wrap">
            <table className="acs-table">
              <thead><tr><th>Header</th><th>Değer</th></tr></thead>
              <tbody>
                {BYPASS_HEADERS.map(h => (
                  <tr key={h.header}><td style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent-blue)' }}>{h.header}</td><td style={{ fontFamily: 'var(--font-mono)' }}>{h.value}</td></tr>
                ))}
              </tbody>
            </table>
          </div>
          <h4 style={{ fontSize: '0.9rem', color: 'var(--accent-orange)', margin: '1rem 0 0.5rem' }}>Path Bypass Denemeleri</h4>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
            {['/path/', '/path//', '/path/..', '/path%20', '/path?', '/path#'].map(p => <div key={p} style={{ padding: '2px 0' }}>{p}</div>)}
          </div>
        </div>
      )}

      {tab === 'cors' && (
        <div>
          <p style={{ color: 'var(--text-secondary)', marginBottom: '1rem' }}>base_url + API endpoint'lerine (max 10) 3 farklı origin ile CORS testi yapılır.</p>
          <div className="acs-info-grid" style={{ marginBottom: '1rem' }}>
            {['https://evil.com', 'https://attacker.com', 'null'].map(o => (
              <div key={o} className="acs-info-item"><span className="acs-info-label">Origin</span><span className="acs-info-value" style={{ fontFamily: 'var(--font-mono)' }}>{o}</span></div>
            ))}
          </div>
          <div className="acs-table-wrap">
            <table className="acs-table">
              <thead><tr><th>Tespit</th><th>Koşul</th><th>Severity</th></tr></thead>
              <tbody>
                <tr><td>Wildcard Origin</td><td>ACAO: *</td><td style={{ color: 'var(--accent-blue)' }}>Medium</td></tr>
                <tr><td>Origin Reflection</td><td>ACAO = gönderilen Origin</td><td style={{ color: 'var(--accent-blue)' }}>Medium</td></tr>
                <tr><td>Reflection + Credentials</td><td>ACAO = Origin + ACAC: true</td><td style={{ color: 'var(--accent-orange)', fontWeight: 700 }}>High</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      )}

      {tab === 'nuclei' && (
        <div>
          <p style={{ color: 'var(--text-secondary)', marginBottom: '1rem' }}>Harici nuclei binary ile 10.000+ CVE template taraması yapılır.</p>
          <div className="glass-panel" style={{ padding: '1rem', fontFamily: 'var(--font-mono)', fontSize: '0.82rem' }}>
            <div style={{ color: 'var(--accent-green)' }}>$ nuclei -u {'<base_url>'} \</div>
            <div>&nbsp;&nbsp;-json -o nuclei_output.json \</div>
            <div>&nbsp;&nbsp;-severity medium,high,critical \</div>
            <div>&nbsp;&nbsp;-timeout 10 -retries 1 \</div>
            <div>&nbsp;&nbsp;-rate-limit 30 -silent</div>
          </div>
          <div style={{ marginTop: '1rem', padding: '0.8rem', background: 'rgba(210, 153, 34, 0.1)', borderRadius: '6px', border: '1px solid rgba(210, 153, 34, 0.2)' }}>
            <strong style={{ color: 'var(--accent-orange)' }}>⚠️ </strong>
            <span style={{ fontSize: '0.88rem' }}>Nuclei binary yolu <code>shutil.which("nuclei")</code> ile otomatik bulunur veya <code>--nuclei</code> parametresi ile belirtilir. Timeout: 300s</span>
          </div>
        </div>
      )}

      {tab === 'paths' && (
        <div>
          <p style={{ color: 'var(--text-secondary)', marginBottom: '1rem' }}>50+ hassas dosya yolunu paralel ThreadPoolExecutor (max 20) ile tarar.</p>
          <div className="acs-table-wrap">
            <table className="acs-table">
              <thead><tr><th>Kategori</th><th>Örnekler</th><th>Severity</th></tr></thead>
              <tbody>
                {[
                  { cat: 'Environment', ex: '.env, .env.production', sev: 'Critical' },
                  { cat: 'Git/SVN', ex: '.git/config, .svn/entries', sev: 'Critical-High' },
                  { cat: 'DB Yedek', ex: 'backup.sql, dump.sql', sev: 'Critical' },
                  { cat: 'Debug', ex: '/debug, /actuator/env', sev: 'High-Critical' },
                  { cat: 'API Docs', ex: '/swagger, /openapi.json', sev: 'Medium' },
                  { cat: 'PHP/Server', ex: '/phpinfo.php, /server-status', sev: 'High-Medium' },
                  { cat: 'GraphQL', ex: '/graphql/schema, /graphiql', sev: 'Medium' },
                ].map(r => (
                  <tr key={r.cat}><td style={{ fontWeight: 500 }}>{r.cat}</td><td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }}>{r.ex}</td><td>{r.sev}</td></tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {results && <div className="acs-results-box"><h4>Sonuçlar</h4><pre className="json-view">{JSON.stringify(results, null, 2)}</pre></div>}
    </div>
  );
};

ActiveTestingSection.meta = {
  id: 'active_testing',
  title: 'Active Testing',
  icon: '⚔️',
  layer: 'L2',
  description: 'Form fuzzing (SQLi/XSS/SSTI), auth bypass, CORS testi, Nuclei CVE, hassas dosya keşfi',
  docFile: '08-active-testing.md',
};

export default ActiveTestingSection;
