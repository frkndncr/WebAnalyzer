import React from 'react';

const CLI_PARAMS = [
  { param: 'domain', def: '(zorunlu)', desc: 'Hedef domain' },
  { param: '--depth', def: '3', desc: 'Crawl derinliği' },
  { param: '--pages', def: '200', desc: 'Maks sayfa' },
  { param: '--workers', def: '15', desc: 'Thread sayısı' },
  { param: '--rate', def: '0.15', desc: 'İstekler arası bekleme (s)' },
  { param: '--active / --no-active', def: 'True', desc: 'Aktif test' },
  { param: '--headless', def: 'False', desc: 'Playwright headless' },
  { param: '--nuclei', def: 'None', desc: 'Nuclei binary yolu' },
  { param: '--oob-domain', def: 'None', desc: 'SSRF OOB callback domain' },
  { param: '--resume', def: 'False', desc: 'Önceki durumdan devam' },
  { param: '--min-severity', def: 'Low', desc: 'Minimum ciddiyet filtresi' },
];

const GRADES = [
  { range: '≥ 9.0', grade: 'F', color: '#f85149' }, { range: '≥ 7.5', grade: 'D', color: '#d29922' },
  { range: '≥ 5.0', grade: 'C', color: '#d29922' }, { range: '≥ 3.0', grade: 'B', color: '#58a6ff' },
  { range: '≥ 1.0', grade: 'A', color: '#3fb950' }, { range: '0', grade: 'A+', color: '#3fb950' },
];

const UtilitiesSection = ({ status, results }) => {
  return (
    <div className="acs-section-content">
      <h4 style={{ margin: '0 0 1rem', fontSize: '0.9rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Yardımcı Fonksiyonlar</h4>
      <div className="acs-table-wrap">
        <table className="acs-table">
          <thead><tr><th>Fonksiyon</th><th>Amaç</th></tr></thead>
          <tbody>
            {[
              ['_entropy(s)', 'Shannon entropi hesaplama'],
              ['_mask(s)', 'Hassas değeri maskele (ilk4+****+son4)'],
              ['_shash(s)', 'MD5 kısa hash (10 char)'],
              ['_fp_value(val)', 'Değer bazlı FP kontrolü'],
              ['_fp_context(ctx)', 'Bağlam bazlı FP kontrolü'],
              ['_sev_passes(sev)', 'Minimum ciddiyet filtresi'],
              ['_is_new(h)', 'Thread-safe deduplikasyon'],
              ['_next_id(cat)', 'Thread-safe artan ID'],
              ['_add_finding(cat, f)', 'Thread-safe bulgu ekleme'],
              ['_risk_score(sev, conf, entr)', 'CVSS-tabanlı risk puanı'],
              ['_save_state()', 'Durumu JSON dosyasına kaydet'],
              ['_load_state()', 'Önceki durumdan devam et'],
            ].map(([fn, desc]) => (
              <tr key={fn}><td style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent-blue)', fontSize: '0.82rem' }}>{fn}</td><td>{desc}</td></tr>
            ))}
          </tbody>
        </table>
      </div>

      <h4 style={{ margin: '1.5rem 0 1rem', fontSize: '0.9rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Güvenlik Notu Skalası</h4>
      <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
        {GRADES.map(g => (
          <div key={g.grade} style={{ padding: '8px 16px', borderRadius: '8px', border: `1px solid ${g.color}30`, background: `${g.color}10`, textAlign: 'center' }}>
            <div style={{ fontSize: '1.5rem', fontWeight: 800, color: g.color }}>{g.grade}</div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>{g.range}</div>
          </div>
        ))}
      </div>

      <h4 style={{ margin: '1.5rem 0 1rem', fontSize: '0.9rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>CLI Parametreleri</h4>
      <div className="acs-table-wrap">
        <table className="acs-table">
          <thead><tr><th>Parametre</th><th>Varsayılan</th><th>Açıklama</th></tr></thead>
          <tbody>
            {CLI_PARAMS.map(p => (
              <tr key={p.param}><td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>{p.param}</td><td style={{ fontFamily: 'var(--font-mono)' }}>{p.def}</td><td>{p.desc}</td></tr>
            ))}
          </tbody>
        </table>
      </div>

      {results && <div className="acs-results-box"><h4>Sonuçlar</h4><pre className="json-view">{JSON.stringify(results, null, 2)}</pre></div>}
    </div>
  );
};

UtilitiesSection.meta = {
  id: 'utilities', title: 'Utilities & Helpers', icon: '🔧', layer: 'ALL',
  description: 'Yardımcı fonksiyonlar, güvenlik notu, CLI parametreleri',
  docFile: '12-utilities-and-helpers.md',
};

export default UtilitiesSection;
