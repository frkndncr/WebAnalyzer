import React from 'react';

const LAYERS = [
  { id: 'L1', name: 'Passive Recon', icon: '🔍', color: '#58a6ff', desc: 'Concurrent crawl, sitemap, source maps, JSON blobs, security headers, JS dosyası işleme, API endpoint çıkarma' },
  { id: 'L2', name: 'Active Testing', icon: '⚔️', color: '#d29922', desc: 'Nuclei entegrasyonu (10K+ CVE), aktif fuzzing (SQLi, XSS, SSTI, CRLF), auth bypass, CORS testi' },
  { id: 'L3', name: 'Smart Analysis', icon: '🧠', color: '#3fb950', desc: 'Taint-flow izleyici, entropi ağırlıklı puanlama, DOM sink numaralandırma, FP filtreleme' },
  { id: 'L4', name: 'Dynamic Runtime', icon: '🌐', color: '#bc8cff', desc: 'Playwright headless tarayıcı, runtime secret tarama, SPA rota keşfi, storage dump' },
  { id: 'L5', name: 'Autonomous Agent', icon: '🤖', color: '#f85149', desc: 'WAF tespiti/adaptasyon, exploit zinciri, risk puanlama, artımlı diff tarama' },
];

const DEPS = [
  { pkg: 'requests', required: true, purpose: 'HTTP istekleri' },
  { pkg: 'beautifulsoup4', required: true, purpose: 'HTML/XML ayrıştırma' },
  { pkg: 'validators', required: true, purpose: 'URL doğrulama' },
  { pkg: 'playwright', required: false, purpose: 'L4 headless tarayıcı' },
  { pkg: 'nuclei (binary)', required: false, purpose: 'L2 CVE tarama' },
];

const CLASSES = [
  { name: 'AdvancedContentScanner', type: 'Ana Sınıf', purpose: 'Tüm tarama sürecini yönetir' },
  { name: 'PatternRegistry', type: 'Kayıt Defteri', purpose: 'Tüm güvenlik desenleri, payloadlar, yapılandırmalar' },
  { name: 'TaintFlowTracker', type: 'Analiz', purpose: 'JS kaynak→hedef taint akış izleme' },
  { name: 'WAFDetector', type: 'Tespit', purpose: 'WAF tespiti ve blok kontrolü' },
  { name: 'SecretFinding', type: 'Data Class', purpose: 'Gizli bilgi bulgusu' },
  { name: 'JSVulnFinding', type: 'Data Class', purpose: 'JS zafiyet bulgusu' },
  { name: 'SSRFVulnFinding', type: 'Data Class', purpose: 'SSRF zafiyet bulgusu' },
  { name: 'ActiveVulnFinding', type: 'Data Class', purpose: 'Aktif test bulgusu' },
  { name: 'SecurityHeaderFinding', type: 'Data Class', purpose: 'Güvenlik başlığı bulgusu' },
  { name: 'ExposedEndpoint', type: 'Data Class', purpose: 'Açık endpoint bulgusu' },
];

const OverviewSection = ({ status, results }) => {
  return (
    <div className="acs-section-content">
      {/* Module Info */}
      <div className="acs-info-grid">
        <div className="acs-info-item">
          <span className="acs-info-label">Versiyon</span>
          <span className="acs-info-value">4.0.0 (Nirvana Edition)</span>
        </div>
        <div className="acs-info-item">
          <span className="acs-info-label">Yazar</span>
          <span className="acs-info-value">Furkan DINCER @f3rrkan</span>
        </div>
        <div className="acs-info-item">
          <span className="acs-info-label">Dosya</span>
          <span className="acs-info-value" style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>modules/advanced_content_scanner.py</span>
        </div>
        <div className="acs-info-item">
          <span className="acs-info-label">Toplam Satır</span>
          <span className="acs-info-value">2545</span>
        </div>
      </div>

      {/* 5 Layers */}
      <h4 style={{ margin: '1.5rem 0 1rem', fontSize: '0.95rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '1px' }}>5 Katmanlı Mimari</h4>
      <div className="acs-layers-stack">
        {LAYERS.map(l => (
          <div key={l.id} className="acs-layer-row" style={{ borderLeftColor: l.color }}>
            <div className="acs-layer-header">
              <span className="acs-layer-icon">{l.icon}</span>
              <span className="acs-layer-id" style={{ color: l.color }}>{l.id}</span>
              <span className="acs-layer-name">{l.name}</span>
            </div>
            <p className="acs-layer-desc">{l.desc}</p>
          </div>
        ))}
      </div>

      {/* Dependencies */}
      <h4 style={{ margin: '1.5rem 0 1rem', fontSize: '0.95rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '1px' }}>Bağımlılıklar</h4>
      <div className="acs-table-wrap">
        <table className="acs-table">
          <thead><tr><th>Paket</th><th>Zorunlu</th><th>Kullanım</th></tr></thead>
          <tbody>
            {DEPS.map(d => (
              <tr key={d.pkg}>
                <td style={{ fontFamily: 'var(--font-mono)' }}>{d.pkg}</td>
                <td>{d.required ? '✅' : '❌ Opsiyonel'}</td>
                <td>{d.purpose}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Class Map */}
      <h4 style={{ margin: '1.5rem 0 1rem', fontSize: '0.95rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '1px' }}>Sınıf Haritası</h4>
      <div className="acs-table-wrap">
        <table className="acs-table">
          <thead><tr><th>Sınıf</th><th>Tür</th><th>Amaç</th></tr></thead>
          <tbody>
            {CLASSES.map(c => (
              <tr key={c.name}>
                <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent-blue)' }}>{c.name}</td>
                <td><span className="acs-badge">{c.type}</span></td>
                <td>{c.purpose}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Results */}
      {results && (
        <div className="acs-results-box">
          <h4>Tarama Sonuçları</h4>
          <pre className="json-view">{JSON.stringify(results, null, 2)}</pre>
        </div>
      )}
    </div>
  );
};

OverviewSection.meta = {
  id: 'overview',
  title: 'Genel Bakış',
  icon: '📋',
  layer: 'ALL',
  description: 'Modül bilgileri, 5 katmanlı mimari, bağımlılıklar ve sınıf haritası',
  docFile: '01-genel-bakis.md',
};

export default OverviewSection;
