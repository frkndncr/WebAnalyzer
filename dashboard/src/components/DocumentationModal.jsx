import React from 'react';

const DOC_CONTENT = {
  '01-genel-bakis.md': {
    title: 'Genel Bakış',
    sections: [
      { heading: 'Modül Bilgileri', content: 'Advanced Content Scanner v4.0.0 (Nirvana Edition) — 2545 satır.\nYazar: Furkan DINCER (@f3rrkan)\nDosya: modules/advanced_content_scanner.py' },
      { heading: '5 Katmanlı Mimari', content: '• L1 — Passive Recon: Concurrent crawl, sitemap, source map, JSON blob, güvenlik header, JS işleme\n• L2 — Active Testing: Nuclei (10K+ CVE), fuzzing (SQLi/XSS/SSTI/CRLF), auth bypass, CORS\n• L3 — Smart Analysis: Taint-flow izleyici, entropi puanlama, DOM sink, FP filtreleme\n• L4 — Dynamic Runtime: Playwright headless, runtime secret, SPA rota keşfi\n• L5 — Autonomous Agent: WAF adaptasyon, exploit zinciri, risk puanlama' },
      { heading: 'Bağımlılıklar', content: '✅ requests, beautifulsoup4, validators\n❌ playwright (opsiyonel), nuclei binary (opsiyonel)' },
    ]
  },
  '02-veri-siniflari.md': {
    title: 'Veri Sınıfları',
    sections: [
      { heading: '6 Data Class', content: '1. SecretFinding — Gizli bilgi bulgusu (API key, token, parola)\n2. JSVulnFinding — JS zafiyet bulgusu (DOM XSS, Open Redirect)\n3. SSRFVulnFinding — SSRF bulgusu (form/URL/confirmed)\n4. ActiveVulnFinding — Aktif test bulgusu (SQLi, XSS, SSTI)\n5. SecurityHeaderFinding — Güvenlik başlığı bulgusu\n6. ExposedEndpoint — Açık endpoint bulgusu' },
      { heading: 'Hash Deduplikasyon', content: 'sha256(type:source_url:value) → ilk 16 karakter.\n_seen_hashes kümesi ile aynı bulgunun iki kez kaydedilmesi engellenir.' },
    ]
  },
  '03-pattern-registry.md': {
    title: 'Pattern Registry',
    sections: [
      { heading: 'Secret Desenleri', content: '40+ regex deseni: AWS, GCP, OpenAI, Stripe, GitHub, MongoDB, SSH Key, JWT, HashiCorp Vault vb.\nHer desen: regex, min_entropy, severity, capture group bilgisi içerir.' },
      { heading: 'JS Security', content: '14 kategori: DOM XSS (9), Open Redirect (3), Prototype Pollution (3), Dynamic Code Exec (4), postMessage (2), Storage (3), WebSocket (1), Crypto (3), Path Traversal (1), JSONP (2), SSRF (3), Console Leak (1), Internal IP (1)' },
      { heading: 'Fuzzing Payload', content: 'SQLi (9), XSS (8), Path Traversal (6), SSTI (6), CRLF (3), Open Redirect (5) payload seti.' },
      { heading: 'Hassas Yollar', content: '50+ endpoint: .env, .git/config, backup.sql, /debug, /swagger, /phpinfo.php, /graphql vb.' },
    ]
  },
  '04-crawl-engine.md': {
    title: 'Crawl Engine',
    sections: [
      { heading: 'Çalışma Prensibi', content: 'Queue tabanlı concurrent crawl.\n• max_depth=3, max_pages=200, max_workers=15\n• Thread havuzu ile paralel sayfa işleme\n• Her sayfa: headers, tech fingerprint, links, scripts, forms, SSRF kontrol' },
      { heading: 'URL Filtreleme', content: '4 aşamalı filtre: http/https? → Atlanacak uzantı? → Kapsam içinde? → robots.txt izinli?' },
      { heading: 'Link Kaynakları', content: '<a href>, data-src, data-href, <link rel="preload/prefetch">, <meta refresh>, <form action>' },
    ]
  },
  '05-secret-scanner.md': {
    title: 'Secret Scanner',
    sections: [
      { heading: 'Tarama Akışı', content: '8 adım: Harici kütüphane kontrolü → Desen eşleştirme → Shannon entropi → FP değer filtresi → FP bağlam filtresi → Güven seviyesi → Deduplikasyon → Risk puanı' },
      { heading: 'Entropi Formülü', content: 'H(X) = -Σ p(x) × log₂(p(x))\n"aaaaaaa" → 0.0 | "password" → ~2.75 | Gerçek key → 4.5+' },
      { heading: 'Risk Puanı', content: 'score = min(base × conf_m × entropy_m + bonus, 10.0)\nbase: Critical=10, High=7.5, Medium=4, Low=1.5' },
    ]
  },
  '06-js-analysis.md': {
    title: 'JS Analysis & Taint Tracking',
    sections: [
      { heading: 'JS Analiz', content: 'Minified tespiti → Taint flow → 14 kategori desen → Math.random filtresi → JSVulnFinding' },
      { heading: 'Taint-Flow Tracker', content: 'Kaynaklar: location.search/hash, document.referrer, URLSearchParams, localStorage\nHedefler: innerHTML, document.write, eval, new Function, dangerouslySetInnerHTML\n5 zorunlu koşul ile false positive minimizasyonu.' },
    ]
  },
  '07-ssrf-detection.md': {
    title: 'SSRF Detection',
    sections: [
      { heading: '3 Katman', content: '1. Form SSRF (pasif): HTML form parametreleri kontrolü\n2. URL Param SSRF (pasif): Query parameter kontrolü\n3. Aktif SSRF Probe: Gerçek payload gönderimi + redirect doğrulama' },
      { heading: 'Doğrulama', content: 'SSRF yalnızca Location headerında probe URLsi yer aldığında CONFIRMED olarak işaretlenir.' },
    ]
  },
  '08-active-testing.md': {
    title: 'Active Testing',
    sections: [
      { heading: 'Form Fuzzing', content: 'XSS: DOM-level 3 aşamalı doğrulama (event handler, script tag, javascript: protocol)\nSQLi: Hata mesajı tespiti\nSSTI: Diferansiyel test (baseline → {{7*7}}→49 → {{8*8}}→64)' },
      { heading: 'Auth Bypass', content: '9 header (X-Forwarded-For, X-Original-URL vb.) + 6 path varyasyonu ile 403 bypass' },
      { heading: 'CORS & Nuclei', content: 'CORS: 3 origin ile test (evil.com, attacker.com, null)\nNuclei: 10K+ CVE template, medium/high/critical severity, 300s timeout' },
    ]
  },
  '09-headless-browser.md': {
    title: 'Headless Browser',
    sections: [
      { heading: 'Playwright Akışı', content: '7 adım: Chromium başlat → Sayfaya git → Runtime secret tara → Storage tara → Network yakala → SPA rotaları keşfet → Rendered HTML tara' },
    ]
  },
  '10-exploit-chains.md': {
    title: 'Exploit Chains',
    sections: [
      { heading: '5 Saldırı Zinciri', content: '1. .env → Credential Exfil (10.0, T1552.001)\n2. SQLi → Auth Bypass → Data Exfil (9.8, T1190)\n3. XSS → Session Hijack (8.5, T1185)\n4. SSRF → Cloud Metadata → IAM (9.5, T1552.005)\n5. Secret → API Abuse (9.0, T1552.001)' },
    ]
  },
  '11-waf-detection.md': {
    title: 'WAF Detection',
    sections: [
      { heading: 'WAF Tespiti', content: '9 WAF markası: Cloudflare, Akamai, Imperva, AWS WAF, Sucuri, F5, Barracuda, Fortinet, ModSecurity' },
      { heading: 'Adaptif Strateji', content: 'WAF tespitinde rate_limit ≥ 0.5s\n5+ blok → 3s hard backoff\nSSL hatası → verify=False ile tekrar dene' },
    ]
  },
  '12-utilities-and-helpers.md': {
    title: 'Utilities & Helpers',
    sections: [
      { heading: 'Fonksiyonlar', content: '_entropy(), _mask(), _shash(), _fp_value(), _fp_context(), _sev_passes(), _is_new(), _next_id(), _add_finding(), _risk_score(), _save_state(), _load_state()' },
      { heading: 'Güvenlik Notu', content: '≥9.0=F, ≥7.5=D, ≥5.0=C, ≥3.0=B, ≥1.0=A, 0=A+' },
      { heading: 'CLI', content: '--depth, --pages, --workers, --rate, --active, --headless, --nuclei, --oob-domain, --resume, --min-severity' },
    ]
  },
  '13-ana-akis.md': {
    title: 'Ana Akış — run()',
    sections: [
      { heading: 'Çalışma Sırası', content: '12 adım: crawl_website → sensitive_paths → CORS → auth_bypass → nuclei → SSRF probe → headless → dynamic routes → exploit chains → summary → save → state' },
      { heading: 'L3 Entegrasyonu', content: 'L3 ayrı adım değil — L1 crawl sırasında entegre: Taint flow → _analyze_js(), Entropi → _scan_secrets(), FP → _fp_value()/_fp_context()' },
    ]
  },
};

const DocumentationModal = ({ isOpen, onClose, docFile }) => {
  if (!isOpen || !docFile) return null;

  const doc = DOC_CONTENT[docFile];
  if (!doc) return null;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content acs-doc-modal" onClick={e => e.stopPropagation()}>
        <button className="modal-close" onClick={onClose}>×</button>
        <h2 style={{ marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span style={{ fontSize: '1.3rem' }}>📖</span> {doc.title}
        </h2>
        <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginBottom: '1.5rem', fontFamily: 'var(--font-mono)' }}>
          {docFile}
        </div>
        
        {doc.sections.map((sec, i) => (
          <div key={i} style={{ marginBottom: '1.5rem' }}>
            <h3 style={{ fontSize: '1rem', color: 'var(--accent-blue)', marginBottom: '0.5rem', paddingBottom: '0.3rem', borderBottom: '1px solid var(--panel-border)' }}>
              {sec.heading}
            </h3>
            <div style={{ whiteSpace: 'pre-wrap', fontSize: '0.88rem', lineHeight: '1.7', color: 'var(--text-primary)' }}>
              {sec.content}
            </div>
          </div>
        ))}

        <div style={{ marginTop: '1.5rem', padding: '0.8rem', background: 'rgba(88, 166, 255, 0.06)', borderRadius: '6px', fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
          Tam dokümantasyon: docs/detailed-documentation/advanced_content_scanner/{docFile}
        </div>
      </div>
    </div>
  );
};

export default DocumentationModal;
