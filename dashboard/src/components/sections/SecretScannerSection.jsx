import React from 'react';

const SCAN_SOURCES = ['Inline <script> tagları', 'Harici JS dosyaları', 'Source map dosyaları', 'JSON Blobları (__NEXT_DATA__, LD+JSON)', 'URL parametreleri', 'L4: Headless rendered HTML', 'L4: window/globalThis', 'L4: localStorage/sessionStorage'];
const FP_CONTEXT = ['example', 'sample', 'placeholder', 'dummy', 'test', 'demo', 'your_', 'INSERT_', 'TODO', 'changeme'];
const FP_VALUE = ['200+ karakter alfanümerik (minified)', 'Unicode escape dizisi', 'MD5 hash (32 hex)', 'Sadece harfler', 'Sadece rakamlar', 'data:image/ ile başlayan'];

const SecretScannerSection = ({ status, results }) => {
  return (
    <div className="acs-section-content">
      {/* Scan Flow */}
      <div className="acs-flow-box">
        <h4 style={{ marginBottom: '1rem', color: 'var(--accent-blue)' }}>Secret Tarama Akışı</h4>
        <div className="acs-flow-steps">
          {[
            { step: '1', label: 'Harici Kütüphane Kontrolü', desc: 'CDN hostlarından gelen dosyalar atlanır' },
            { step: '2', label: 'Desen Eşleştirme', desc: '40+ regex deseni sırasıyla çalıştırılır' },
            { step: '3', label: 'Shannon Entropi', desc: 'H(X) = -Σ p(x) × log₂(p(x))' },
            { step: '4', label: 'FP Değer Filtresi', desc: 'Sadece harf/rakam, çok uzun, base64 resim vb. filtrele' },
            { step: '5', label: 'FP Bağlam Filtresi', desc: 'example, test, placeholder, TODO vb. çevreleri filtrele' },
            { step: '6', label: 'Güven Seviyesi', desc: 'Entropi ≥ min+1.0 → HIGH, aksi → MEDIUM' },
            { step: '7', label: 'Deduplikasyon', desc: 'Hash ile tekrar kontrolü' },
            { step: '8', label: 'Risk Puanı', desc: 'base × confidence × entropy çarpanı (max 10)' },
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

      {/* Risk Score Formula */}
      <h4 style={{ margin: '1.5rem 0 0.8rem', fontSize: '0.9rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Risk Puanı Formülü</h4>
      <div className="glass-panel" style={{ padding: '1rem', fontFamily: 'var(--font-mono)', fontSize: '0.85rem' }}>
        <div style={{ color: 'var(--accent-purple)', marginBottom: '8px' }}>base = SEV_WEIGHT[severity]</div>
        <div style={{ color: 'var(--text-secondary)', marginBottom: '4px' }}>Critical=10.0 | High=7.5 | Medium=4.0 | Low=1.5 | Info=0.5</div>
        <div style={{ color: 'var(--accent-blue)', marginTop: '8px' }}>score = min(base × conf_m × entropy_m + entropy_bonus, 10.0)</div>
        <div style={{ color: 'var(--text-secondary)', marginTop: '4px' }}>conf_m: HIGH=1.0, MEDIUM=0.7, LOW=0.4</div>
      </div>

      {/* Entropy Examples */}
      <h4 style={{ margin: '1.5rem 0 0.8rem', fontSize: '0.9rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Entropi Örnekleri</h4>
      <div className="acs-table-wrap">
        <table className="acs-table">
          <thead><tr><th>Giriş</th><th>Entropi</th><th>Yorum</th></tr></thead>
          <tbody>
            <tr><td style={{ fontFamily: 'var(--font-mono)' }}>"aaaaaaa"</td><td>0.0</td><td>Rastgelelik yok</td></tr>
            <tr><td style={{ fontFamily: 'var(--font-mono)' }}>"password"</td><td>~2.75</td><td>Düşük entropi</td></tr>
            <tr><td style={{ fontFamily: 'var(--font-mono)' }}>"aK4$mX9!qZ"</td><td>~3.91</td><td>Orta entropi</td></tr>
            <tr><td style={{ fontFamily: 'var(--font-mono)' }}>"sk-proj-abc123..."</td><td>4.5+</td><td style={{ color: 'var(--accent-green)' }}>Gerçek anahtar</td></tr>
          </tbody>
        </table>
      </div>

      {/* Scan Sources */}
      <h4 style={{ margin: '1.5rem 0 0.8rem', fontSize: '0.9rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Tarama Kaynakları</h4>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
        {SCAN_SOURCES.map(s => <span key={s} className="acs-badge">{s}</span>)}
      </div>

      {/* FP Filters */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginTop: '1.5rem' }}>
        <div>
          <h4 style={{ fontSize: '0.9rem', color: 'var(--accent-orange)', marginBottom: '0.5rem' }}>Bağlam FP Filtreleri</h4>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
            {FP_CONTEXT.map(t => <span key={t} className="acs-badge" style={{ fontSize: '0.72rem' }}>{t}</span>)}
          </div>
        </div>
        <div>
          <h4 style={{ fontSize: '0.9rem', color: 'var(--accent-orange)', marginBottom: '0.5rem' }}>Değer FP Filtreleri</h4>
          <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>
            {FP_VALUE.map(v => <div key={v} style={{ padding: '2px 0' }}>• {v}</div>)}
          </div>
        </div>
      </div>

      {/* Masking */}
      <h4 style={{ margin: '1.5rem 0 0.8rem', fontSize: '0.9rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Maskeleme Kuralı</h4>
      <div className="glass-panel" style={{ padding: '1rem', fontFamily: 'var(--font-mono)', fontSize: '0.82rem' }}>
        <div>len ≤ 8 → ilk 2 + "****"</div>
        <div>len {'>'} 8 → ilk 4 + "****" + son 4</div>
        <div style={{ color: 'var(--text-secondary)', marginTop: '8px' }}>Örnek: "sk-abc123xyz789" → "sk-a****9789"</div>
      </div>

      {results && <div className="acs-results-box"><h4>Sonuçlar</h4><pre className="json-view">{JSON.stringify(results, null, 2)}</pre></div>}
    </div>
  );
};

SecretScannerSection.meta = {
  id: 'secret_scanner',
  title: 'Secret Scanner',
  icon: '🔐',
  layer: 'L1+L3',
  description: 'Gizli bilgi tarama, Shannon entropi, risk puanlama, FP filtreleme',
  docFile: '05-secret-scanner.md',
};

export default SecretScannerSection;
