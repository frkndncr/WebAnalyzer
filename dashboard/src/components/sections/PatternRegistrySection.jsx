import React, { useState } from 'react';

const SECRET_CATEGORIES = [
  { cat: 'Bulut Servisleri', items: [
    { name: 'AWS Access Key ID', sev: 'High', entropy: 3.2 },
    { name: 'AWS Secret Access Key', sev: 'Critical', entropy: 4.5 },
    { name: 'AWS Session Token', sev: 'Critical', entropy: 4.5 },
    { name: 'Google API Key', sev: 'High', entropy: 4.0 },
    { name: 'GCP Service Account Key', sev: 'Critical', entropy: 0 },
    { name: 'Cloudflare API Token', sev: 'High', entropy: 4.0 },
    { name: 'DigitalOcean PAT', sev: 'High', entropy: 4.5 },
  ]},
  { cat: 'AI/ML Servisleri', items: [
    { name: 'OpenAI API Key', sev: 'Critical', entropy: 4.5 },
    { name: 'OpenAI API Key (new)', sev: 'Critical', entropy: 4.5 },
    { name: 'Anthropic API Key', sev: 'Critical', entropy: 4.5 },
    { name: 'HuggingFace Token', sev: 'High', entropy: 4.0 },
    { name: 'Replicate API Token', sev: 'High', entropy: 4.0 },
  ]},
  { cat: 'Ödeme / Finans', items: [
    { name: 'Stripe Secret Key', sev: 'Critical', entropy: 4.0 },
    { name: 'Stripe Publishable Key', sev: 'Low', entropy: 4.0 },
    { name: 'PayPal/Braintree Access Token', sev: 'Critical', entropy: 4.5 },
  ]},
  { cat: 'DevOps / VCS', items: [
    { name: 'GitHub PAT (classic)', sev: 'High', entropy: 4.5 },
    { name: 'GitHub Fine-grained PAT', sev: 'High', entropy: 4.5 },
    { name: 'GitLab PAT', sev: 'High', entropy: 4.0 },
    { name: 'NPM Auth Token', sev: 'High', entropy: 3.5 },
  ]},
  { cat: 'Veritabanı', items: [
    { name: 'MongoDB Connection String', sev: 'Critical', entropy: 3.0 },
    { name: 'PostgreSQL Connection String', sev: 'Critical', entropy: 3.0 },
    { name: 'MySQL Connection String', sev: 'Critical', entropy: 3.0 },
    { name: 'Redis Connection String', sev: 'High', entropy: 2.5 },
  ]},
  { cat: 'Kriptografi / Kimlik', items: [
    { name: 'SSH/PEM Private Key', sev: 'Critical', entropy: 0 },
    { name: 'JWT Token', sev: 'Medium', entropy: 4.2 },
    { name: 'HashiCorp Vault Token', sev: 'Critical', entropy: 4.5 },
    { name: 'Generic High-Entropy Secret', sev: 'High', entropy: 5.0 },
  ]},
];

const JS_CATEGORIES = [
  { name: 'DOM XSS', count: 9, sev: 'High' },
  { name: 'Open Redirect', count: 3, sev: 'High' },
  { name: 'Prototype Pollution', count: 3, sev: 'High' },
  { name: 'Dynamic Code Execution', count: 4, sev: 'High' },
  { name: 'Insecure postMessage', count: 2, sev: 'Medium' },
  { name: 'Sensitive Data in Storage', count: 3, sev: 'Medium' },
  { name: 'WebSocket Plaintext', count: 1, sev: 'High' },
  { name: 'Weak / Broken Crypto', count: 3, sev: 'High' },
  { name: 'Path Traversal', count: 1, sev: 'High' },
  { name: 'JSONP Callback Injection', count: 2, sev: 'Medium' },
  { name: 'SSRF (JS)', count: 3, sev: 'High' },
  { name: 'Debug Console Leak', count: 1, sev: 'High' },
  { name: 'Hardcoded Internal IP', count: 1, sev: 'Medium' },
];

const FUZZ_TYPES = [
  { type: 'SQLi', count: 9, examples: ["' OR '1'='1", "1' AND SLEEP(2)--", "' UNION SELECT NULL--"] },
  { type: 'XSS', count: 8, examples: ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>', '{{7*7}}'] },
  { type: 'Path Traversal', count: 6, examples: ['../etc/passwd', '..%2Fetc%2Fpasswd'] },
  { type: 'SSTI', count: 6, examples: ['{{7*7}}', '${7*7}', '{{config}}'] },
  { type: 'CRLF', count: 3, examples: ['%0d%0aSet-Cookie:injected=1'] },
  { type: 'Open Redirect', count: 5, examples: ['https://evil.com', '//evil.com'] },
];

const SEV_COLORS = { Critical: '#f85149', High: '#d29922', Medium: '#58a6ff', Low: '#8b949e' };

const PatternRegistrySection = ({ status, results }) => {
  const [activeTab, setActiveTab] = useState('secrets');

  const tabs = [
    { id: 'secrets', label: 'Secret Desenleri (40+)', icon: '🔑' },
    { id: 'js', label: 'JS Security (14)', icon: '⚡' },
    { id: 'fuzz', label: 'Fuzz Payloads (6)', icon: '💣' },
  ];

  return (
    <div className="acs-section-content">
      <div className="acs-subtabs">
        {tabs.map(t => (
          <button key={t.id} className={`acs-subtab ${activeTab === t.id ? 'active' : ''}`} onClick={() => setActiveTab(t.id)}>
            {t.icon} {t.label}
          </button>
        ))}
      </div>

      {activeTab === 'secrets' && (
        <div>
          {SECRET_CATEGORIES.map(cat => (
            <div key={cat.cat} style={{ marginBottom: '1.5rem' }}>
              <h4 style={{ fontSize: '0.9rem', color: 'var(--accent-purple)', marginBottom: '0.5rem' }}>{cat.cat}</h4>
              <div className="acs-table-wrap">
                <table className="acs-table">
                  <thead><tr><th>Desen</th><th>Severity</th><th>Min Entropi</th></tr></thead>
                  <tbody>
                    {cat.items.map(item => (
                      <tr key={item.name}>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.82rem' }}>{item.name}</td>
                        <td><span style={{ color: SEV_COLORS[item.sev], fontWeight: 700 }}>{item.sev}</span></td>
                        <td style={{ fontFamily: 'var(--font-mono)' }}>{item.entropy}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ))}
        </div>
      )}

      {activeTab === 'js' && (
        <div className="acs-table-wrap">
          <table className="acs-table">
            <thead><tr><th>Kategori</th><th>Desen Sayısı</th><th>Severity</th></tr></thead>
            <tbody>
              {JS_CATEGORIES.map(c => (
                <tr key={c.name}>
                  <td style={{ fontWeight: 500 }}>{c.name}</td>
                  <td style={{ fontFamily: 'var(--font-mono)' }}>{c.count}</td>
                  <td><span style={{ color: SEV_COLORS[c.sev], fontWeight: 700 }}>{c.sev}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {activeTab === 'fuzz' && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: '1rem' }}>
          {FUZZ_TYPES.map(f => (
            <div key={f.type} className="glass-panel" style={{ padding: '1rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
                <strong style={{ color: 'var(--accent-blue)' }}>{f.type}</strong>
                <span className="acs-badge">{f.count} payload</span>
              </div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                {f.examples.map((ex, i) => (
                  <div key={i} style={{ padding: '2px 0', borderBottom: '1px solid var(--panel-border)' }}>{ex}</div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {results && (
        <div className="acs-results-box">
          <h4>Sonuçlar</h4>
          <pre className="json-view">{JSON.stringify(results, null, 2)}</pre>
        </div>
      )}
    </div>
  );
};

PatternRegistrySection.meta = {
  id: 'pattern_registry',
  title: 'Pattern Registry',
  icon: '📖',
  layer: 'CORE',
  description: '40+ secret deseni, 14 JS zafiyet kategorisi, fuzzing payload setleri',
  docFile: '03-pattern-registry.md',
};

export default PatternRegistrySection;
