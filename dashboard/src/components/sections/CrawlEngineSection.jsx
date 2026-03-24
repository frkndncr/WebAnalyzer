import React from 'react';

const SKIP_EXTENSIONS = ['.pdf','.jpg','.jpeg','.png','.gif','.svg','.css','.woff','.woff2','.ttf','.mp4','.mp3','.zip','.rar','.doc','.docx','.xls','.xlsx','.csv'];
const LINK_SOURCES = [
  { tag: '<a href=...>', desc: 'Standart bağlantılar' },
  { tag: 'data-src', desc: 'Lazy-load kaynakları' },
  { tag: 'data-href', desc: 'Alternatif bağlantılar' },
  { tag: '<link rel="preload/prefetch">', desc: 'Performans ipuçları' },
  { tag: '<meta http-equiv="refresh">', desc: 'Yönlendirme meta' },
  { tag: '<form action=...>', desc: 'Form hedefleri' },
];

const CrawlEngineSection = ({ status, results }) => {
  return (
    <div className="acs-section-content">
      {/* Crawl Flow */}
      <div className="acs-flow-box">
        <h4 style={{ marginBottom: '1rem', color: 'var(--accent-blue)' }}>Crawl Akışı</h4>
        <div className="acs-flow-steps">
          {[
            { step: '1', label: 'Queue Oluştur', desc: 'base_url + sitemap URL\'leri kuyruğa ekle' },
            { step: '2', label: 'Thread Havuzu', desc: 'max_workers (15) daemon thread başlat' },
            { step: '3', label: 'URL İşle', desc: 'Kuyruktan URL al → _process_url()' },
            { step: '4', label: 'İçerik Analiz', desc: 'HTML → link/script/form | JS → analyze+secret' },
            { step: '5', label: 'Yeni URL Ekle', desc: 'Keşfedilen linkler kuyruğa geri düşer' },
          ].map(s => (
            <div key={s.step} className="acs-flow-step">
              <div className="acs-flow-num">{s.step}</div>
              <div>
                <strong>{s.label}</strong>
                <p style={{ color: 'var(--text-secondary)', fontSize: '0.82rem', margin: '4px 0 0' }}>{s.desc}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Config Table */}
      <h4 style={{ margin: '1.5rem 0 0.8rem', fontSize: '0.9rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Yapılandırma</h4>
      <div className="acs-info-grid">
        <div className="acs-info-item"><span className="acs-info-label">max_depth</span><span className="acs-info-value">3</span></div>
        <div className="acs-info-item"><span className="acs-info-label">max_pages</span><span className="acs-info-value">200</span></div>
        <div className="acs-info-item"><span className="acs-info-label">max_workers</span><span className="acs-info-value">15</span></div>
        <div className="acs-info-item"><span className="acs-info-label">rate_limit</span><span className="acs-info-value">0.15s</span></div>
        <div className="acs-info-item"><span className="acs-info-label">timeout</span><span className="acs-info-value">12s</span></div>
        <div className="acs-info-item"><span className="acs-info-label">retry</span><span className="acs-info-value">3x + 0.5s backoff</span></div>
      </div>

      {/* Link Sources */}
      <h4 style={{ margin: '1.5rem 0 0.8rem', fontSize: '0.9rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Link Toplama Kaynakları</h4>
      <div className="acs-table-wrap">
        <table className="acs-table">
          <thead><tr><th>Kaynak</th><th>Açıklama</th></tr></thead>
          <tbody>
            {LINK_SOURCES.map(s => (
              <tr key={s.tag}><td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>{s.tag}</td><td>{s.desc}</td></tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* URL Filter */}
      <h4 style={{ margin: '1.5rem 0 0.8rem', fontSize: '0.9rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>URL Filtreleme Zinciri</h4>
      <div className="acs-filter-chain">
        {['http/https?', 'Atlanacak uzantı?', 'Kapsam içinde?', 'robots.txt izinli?'].map((f, i) => (
          <React.Fragment key={f}>
            <div className="acs-filter-node">{f}</div>
            {i < 3 && <span className="acs-filter-arrow">→</span>}
          </React.Fragment>
        ))}
        <span className="acs-filter-arrow">→</span>
        <div className="acs-filter-node" style={{ background: 'rgba(63, 185, 80, 0.15)', borderColor: 'var(--accent-green)' }}>✅ Taranabilir</div>
      </div>

      {/* Skipped Extensions */}
      <h4 style={{ margin: '1.5rem 0 0.8rem', fontSize: '0.9rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Atlanan Uzantılar</h4>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
        {SKIP_EXTENSIONS.map(ext => (
          <span key={ext} className="acs-badge" style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem' }}>{ext}</span>
        ))}
      </div>

      {/* Sitemap */}
      <h4 style={{ margin: '1.5rem 0 0.8rem', fontSize: '0.9rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Sitemap Kontrol Yolları</h4>
      <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.82rem', color: 'var(--accent-blue)' }}>
        {['/sitemap.xml', '/sitemap_index.xml', '/sitemaps/sitemap.xml', '+ robots.txt Sitemap:'].map(p => (
          <div key={p} style={{ padding: '4px 0' }}>{p}</div>
        ))}
      </div>

      {results && <div className="acs-results-box"><h4>Sonuçlar</h4><pre className="json-view">{JSON.stringify(results, null, 2)}</pre></div>}
    </div>
  );
};

CrawlEngineSection.meta = {
  id: 'crawl_engine',
  title: 'Crawl Engine',
  icon: '🕷️',
  layer: 'L1',
  description: 'Eş zamanlı crawl motoru, sitemap/robots.txt, link harvesting, URL filtreleme',
  docFile: '04-crawl-engine.md',
};

export default CrawlEngineSection;
