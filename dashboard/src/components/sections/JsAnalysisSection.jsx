import React from 'react';

const SOURCES = ['location.search/hash/href/pathname', 'document.referrer/URL/cookie', 'window.name/location', 'URLSearchParams().get()', 'req.query/body/params/headers[]', 'getParameter()', 'localStorage/sessionStorage.getItem()'];
const SINKS = ['.innerHTML =', '.outerHTML =', 'document.write()', 'eval()', 'new Function()', 'dangerouslySetInnerHTML', 'bypassSecurityTrust'];
const SAFE_PATTERNS = ['Drupal.*', 'angular.*', '.settings.*', 'console.*'];
const TAINT_CONDITIONS = [
  'Değişken, kullanıcı kontrollü bir kaynaktan atanmış olmalı',
  'Aynı satırda hem tainted değişken hem tehlikeli sink bulunmalı',
  'Sink gerçekten tehlikeli olmalı (DOM/eval/fetch)',
  'Değişken adı en az 2 karakter olmalı (minified gürültü filtresi)',
  'Güvenli config ataması olmamalı (Drupal.settings vb.)',
];

const JsAnalysisSection = ({ status, results }) => {
  return (
    <div className="acs-section-content">
      {/* JS Analysis Flow */}
      <div className="acs-flow-box">
        <h4 style={{ marginBottom: '1rem', color: 'var(--accent-blue)' }}>JS Analiz Akışı</h4>
        <div className="acs-flow-steps">
          {[
            { step: '1', label: 'Harici Kütüphane?', desc: 'CDN dosyaları atlanır' },
            { step: '2', label: 'Minified Tespiti', desc: 'len > 3000 && satır sayısı < len/500 → sadece HIGH güven desenleri' },
            { step: '3', label: 'Taint Flow (L3)', desc: 'TaintFlowTracker ile kaynak→hedef izleme' },
            { step: '4', label: 'Desen Analizi', desc: '14 kategori desen eşleştirme' },
            { step: '5', label: 'Math.random Filtresi', desc: 'Çevrede token/secret/key yoksa atla' },
            { step: '6', label: 'JSVulnFinding Kaydet', desc: 'Hash, risk puanı, PoC ile birlikte' },
          ].map(s => (
            <div key={s.step} className="acs-flow-step">
              <div className="acs-flow-num">{s.step}</div>
              <div><strong>{s.label}</strong><p style={{ color: 'var(--text-secondary)', fontSize: '0.82rem', margin: '4px 0 0' }}>{s.desc}</p></div>
            </div>
          ))}
        </div>
      </div>

      {/* Taint Flow */}
      <h4 style={{ margin: '1.5rem 0 0.8rem', fontSize: '0.9rem', color: 'var(--accent-purple)', textTransform: 'uppercase' }}>🧠 Taint Flow Tracker (L3)</h4>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1.5rem' }}>
        <div>
          <h5 style={{ color: 'var(--accent-green)', marginBottom: '0.5rem', fontSize: '0.85rem' }}>Kaynaklar (Sources)</h5>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }}>
            {SOURCES.map(s => <div key={s} style={{ padding: '3px 0', borderBottom: '1px solid var(--panel-border)' }}>{s}</div>)}
          </div>
        </div>
        <div>
          <h5 style={{ color: 'var(--accent-red)', marginBottom: '0.5rem', fontSize: '0.85rem' }}>Hedefler (Sinks)</h5>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }}>
            {SINKS.map(s => <div key={s} style={{ padding: '3px 0', borderBottom: '1px solid var(--panel-border)' }}>{s}</div>)}
          </div>
        </div>
      </div>

      {/* Safe Patterns */}
      <h5 style={{ color: 'var(--accent-orange)', fontSize: '0.85rem', marginBottom: '0.5rem' }}>Güvenli Sink Filtreleri</h5>
      <div style={{ display: 'flex', gap: '6px', marginBottom: '1.5rem' }}>
        {SAFE_PATTERNS.map(p => <span key={p} className="acs-badge" style={{ fontFamily: 'var(--font-mono)' }}>{p}</span>)}
      </div>

      {/* 5 Conditions */}
      <h4 style={{ margin: '1rem 0 0.8rem', fontSize: '0.9rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>5 Zorunlu Koşul (Tümü Gerekli)</h4>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
        {TAINT_CONDITIONS.map((c, i) => (
          <div key={i} style={{ display: 'flex', gap: '10px', alignItems: 'flex-start', padding: '8px 12px', background: 'rgba(63, 185, 80, 0.06)', borderRadius: '6px', border: '1px solid rgba(63, 185, 80, 0.1)' }}>
            <span style={{ color: 'var(--accent-green)', fontWeight: 700, minWidth: '20px' }}>✅</span>
            <span style={{ fontSize: '0.88rem' }}>{c}</span>
          </div>
        ))}
      </div>

      {/* Taint chain output */}
      <h4 style={{ margin: '1.5rem 0 0.8rem', fontSize: '0.9rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>Taint Zinciri Çıktısı</h4>
      <pre className="json-view" style={{ fontSize: '0.78rem' }}>{JSON.stringify({
        sink_line: 145,
        sink_pattern: '.innerHTML\\s*[+]?=',
        tainted_variable: 'userInput',
        source_lines: [132, 140],
        sink_code: 'el.innerHTML = userInput',
      }, null, 2)}</pre>

      {/* API Endpoint Extraction */}
      <h4 style={{ margin: '1.5rem 0 0.8rem', fontSize: '0.9rem', color: 'var(--text-secondary)', textTransform: 'uppercase' }}>API Endpoint Çıkarma Kalıpları</h4>
      <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: 'var(--accent-blue)' }}>
        {['/api/v\\d+/...', '/api/...', '/graphql', '/rest/v\\d+/...', '/ajax/...', '/wp-json/...', '"https://..."'].map(p => (
          <div key={p} style={{ padding: '3px 0' }}>{p}</div>
        ))}
      </div>

      {results && <div className="acs-results-box"><h4>Sonuçlar</h4><pre className="json-view">{JSON.stringify(results, null, 2)}</pre></div>}
    </div>
  );
};

JsAnalysisSection.meta = {
  id: 'js_analysis',
  title: 'JS Analysis & Taint Tracking',
  icon: '⚡',
  layer: 'L1+L3',
  description: 'JavaScript güvenlik analizi, kaynak→hedef taint-flow izleme, API endpoint çıkarma',
  docFile: '06-js-analysis.md',
};

export default JsAnalysisSection;
