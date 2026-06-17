import React from 'react';

const DOC_CONTENT = {
  '01-genel-bakis.md': {
    title: 'Overview',
    sections: [
      { heading: 'Module Information', content: 'Advanced Content Scanner v4.0.0 (Nirvana Edition) — 2545 lines.\nAuthor: Furkan DINCER (@f3rrkan)\nFile: modules/advanced_content_scanner.py' },
      { heading: '5-Layer Architecture', content: '• L1 — Passive Recon: Concurrent crawl, sitemap, source map, JSON blob, security headers, JS processing\n• L2 — Active Testing: Nuclei (10K+ CVE), fuzzing (SQLi/XSS/SSTI/CRLF), auth bypass, CORS\n• L3 — Smart Analysis: Taint-flow tracker, entropy scoring, DOM sink, FP filtering\n• L4 — Dynamic Runtime: Playwright headless, runtime secrets, SPA route discovery\n• L5 — Autonomous Agent: WAF adaptation, exploit chains, risk scoring' },
      { heading: 'Dependencies', content: '✅ requests, beautifulsoup4, validators\n❌ playwright (optional), nuclei binary (optional)' },
    ]
  },
  '02-veri-siniflari.md': {
    title: 'Data Classes',
    sections: [
      { heading: '6 Data Classes', content: '1. SecretFinding — Secret discovery (API key, token, password)\n2. JSVulnFinding — JS vulnerability finding (DOM XSS, Open Redirect)\n3. SSRFVulnFinding — SSRF finding (form/URL/confirmed)\n4. ActiveVulnFinding — Active test finding (SQLi, XSS, SSTI)\n5. SecurityHeaderFinding — Security header finding\n6. ExposedEndpoint — Exposed endpoint finding' },
      { heading: 'Hash Deduplication', content: 'sha256(type:source_url:value) → first 16 characters.\n_seen_hashes set prevents the same finding from being recorded twice.' },
    ]
  },
  '03-pattern-registry.md': {
    title: 'Pattern Registry',
    sections: [
      { heading: 'Secret Patterns', content: '40+ regex patterns: AWS, GCP, OpenAI, Stripe, GitHub, MongoDB, SSH Key, JWT, HashiCorp Vault, etc.\nEach pattern contains: regex, min_entropy, severity, capture group info.' },
      { heading: 'JS Security', content: '14 categories: DOM XSS (9), Open Redirect (3), Prototype Pollution (3), Dynamic Code Exec (4), postMessage (2), Storage (3), WebSocket (1), Crypto (3), Path Traversal (1), JSONP (2), SSRF (3), Console Leak (1), Internal IP (1)' },
      { heading: 'Fuzzing Payloads', content: 'SQLi (9), XSS (8), Path Traversal (6), SSTI (6), CRLF (3), Open Redirect (5) payload sets.' },
      { heading: 'Sensitive Paths', content: '50+ endpoints: .env, .git/config, backup.sql, /debug, /swagger, /phpinfo.php, /graphql, etc.' },
    ]
  },
  '04-crawl-engine.md': {
    title: 'Crawl Engine',
    sections: [
      { heading: 'Operating Principle', content: 'Queue-based concurrent crawl.\n• max_depth=3, max_pages=200, max_workers=15\n• Parallel page processing with thread pool\n• Each page: headers, tech fingerprint, links, scripts, forms, SSRF checks' },
      { heading: 'URL Filtering', content: '4-stage filter: http/https? → Skip extension? → In scope? → robots.txt allowed?' },
      { heading: 'Link Sources', content: '<a href>, data-src, data-href, <link rel="preload/prefetch">, <meta refresh>, <form action>' },
    ]
  },
  '05-secret-scanner.md': {
    title: 'Secret Scanner',
    sections: [
      { heading: 'Scan Flow', content: '8 steps: External library check → Pattern matching → Shannon entropy → FP value filter → FP context filter → Confidence level → Deduplication → Risk score' },
      { heading: 'Entropy Formula', content: 'H(X) = -Σ p(x) × log₂(p(x))\n"aaaaaaa" → 0.0 | "password" → ~2.75 | Real key → 4.5+' },
      { heading: 'Risk Score', content: 'score = min(base × conf_m × entropy_m + bonus, 10.0)\nbase: Critical=10, High=7.5, Medium=4, Low=1.5' },
    ]
  },
  '06-js-analysis.md': {
    title: 'JS Analysis & Taint Tracking',
    sections: [
      { heading: 'JS Analysis', content: 'Minified detection → Taint flow → 14 category patterns → Math.random filter → JSVulnFinding' },
      { heading: 'Taint-Flow Tracker', content: 'Sources: location.search/hash, document.referrer, URLSearchParams, localStorage\nSinks: innerHTML, document.write, eval, new Function, dangerouslySetInnerHTML\n5 mandatory conditions for false positive minimization.' },
    ]
  },
  '07-ssrf-detection.md': {
    title: 'SSRF Detection',
    sections: [
      { heading: '3 Layers', content: '1. Form SSRF (passive): HTML form parameter checks\n2. URL Param SSRF (passive): Query parameter checks\n3. Active SSRF Probe: Real payload submission + redirect validation' },
      { heading: 'Validation', content: 'SSRF is only marked as CONFIRMED when the probe URL appears in the Location header.' },
    ]
  },
  '08-active-testing.md': {
    title: 'Active Testing',
    sections: [
      { heading: 'Form Fuzzing', content: 'XSS: DOM-level 3-stage validation (event handler, script tag, javascript: protocol)\nSQLi: Error message detection\nSSTI: Differential test (baseline → {{7*7}}→49 → {{8*8}}→64)' },
      { heading: 'Auth Bypass', content: '9 headers (X-Forwarded-For, X-Original-URL, etc.) + 6 path variations for 403 bypass' },
      { heading: 'CORS & Nuclei', content: 'CORS: 3 origin tests (evil.com, attacker.com, null)\nNuclei: 10K+ CVE templates, medium/high/critical severity, 300s timeout' },
    ]
  },
  '09-headless-browser.md': {
    title: 'Headless Browser',
    sections: [
      { heading: 'Playwright Flow', content: '7 steps: Launch Chromium → Navigate to page → Runtime secret scan → Storage scan → Network capture → SPA route discovery → Rendered HTML scan' },
    ]
  },
  '10-exploit-chains.md': {
    title: 'Exploit Chains',
    sections: [
      { heading: '5 Attack Chains', content: '1. .env → Credential Exfil (10.0, T1552.001)\n2. SQLi → Auth Bypass → Data Exfil (9.8, T1190)\n3. XSS → Session Hijack (8.5, T1185)\n4. SSRF → Cloud Metadata → IAM (9.5, T1552.005)\n5. Secret → API Abuse (9.0, T1552.001)' },
    ]
  },
  '11-waf-detection.md': {
    title: 'WAF Detection',
    sections: [
      { heading: 'WAF Detection', content: '9 WAF vendors: Cloudflare, Akamai, Imperva, AWS WAF, Sucuri, F5, Barracuda, Fortinet, ModSecurity' },
      { heading: 'Adaptive Strategy', content: 'When WAF is detected, rate_limit ≥ 0.5s\n5+ blocks → 3s hard backoff\nSSL error → retry with verify=False' },
    ]
  },
  '12-utilities-and-helpers.md': {
    title: 'Utilities & Helpers',
    sections: [
      { heading: 'Functions', content: '_entropy(), _mask(), _shash(), _fp_value(), _fp_context(), _sev_passes(), _is_new(), _next_id(), _add_finding(), _risk_score(), _save_state(), _load_state()' },
      { heading: 'Security Grading', content: '≥9.0=F, ≥7.5=D, ≥5.0=C, ≥3.0=B, ≥1.0=A, 0=A+' },
      { heading: 'CLI', content: '--depth, --pages, --workers, --rate, --active, --headless, --nuclei, --oob-domain, --resume, --min-severity' },
    ]
  },
  '13-ana-akis.md': {
    title: 'Main Flow — run()',
    sections: [
      { heading: 'Execution Order', content: '12 steps: crawl_website → sensitive_paths → CORS → auth_bypass → nuclei → SSRF probe → headless → dynamic routes → exploit chains → summary → save → state' },
      { heading: 'L3 Integration', content: 'L3 is not a separate step — it is integrated during L1 crawl: Taint flow → _analyze_js(), Entropy → _scan_secrets(), FP → _fp_value()/_fp_context()' },
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
          Full documentation: docs/detailed-documentation/advanced_content_scanner/{docFile}
        </div>
      </div>
    </div>
  );
};

export default DocumentationModal;
