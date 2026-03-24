# Utilities & Helpers (Yardımcı Fonksiyonlar)

Bu bölüm, `AdvancedContentScanner` sınıfının yardımcı metotlarını, açıklama/öneri tablolarını ve durum yönetimi mekanizmalarını kapsar.

---

## Yardımcı Metotlar

### `_entropy(s)` (Satır 2222-2228)

Shannon entropi hesaplaması. Bir stringin rastgelelik derecesini ölçer.

```
H(X) = -Σ p(x) × log₂(p(x))
```

- Tamamen tekrarlı string → 0.0
- Gerçek bir API key → 4.5+

---

### `_mask(s)` (Satır 2230-2233)

Hassas değerleri maskeleyerek güvenli şekilde gösterir:

| Uzunluk | Maskeleme | Örnek |
|---------|-----------|-------|
| ≤ 8 karakter | İlk 2 + `****` | `sk` → `sk****` |
| > 8 karakter | İlk 4 + `****` + Son 4 | `sk-abcdef123456` → `sk-a****3456` |

---

### `_shash(s)` (Satır 2235-2237)

Kısa MD5 hash (10 karakter). Deduplikasyon ve tanımlama amaçlı:

```python
hashlib.md5(s.encode(errors="replace")).hexdigest()[:10]
```

---

### `_fp_value(val)` (Satır 2239-2242)

Değer bazlı false positive kontrolü. [Detaylar: 05-secret-scanner.md]

---

### `_fp_context(ctx)` (Satır 2244-2246)

Bağlam bazlı false positive kontrolü. [Detaylar: 05-secret-scanner.md]

---

### `_sev_passes(sev)` (Satır 2248-2249)

Minimum ciddiyet filtresi. `min_severity` parametresinin altındaki bulguları filtreler:

```python
_sev_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
# Örnek: min_severity="Medium" → Low bulguları atlanır
```

---

### `_is_new(h)` (Satır 1067-1070)

Thread-safe deduplikasyon kontrolü. Hash `_seen_hashes` kümesinde yoksa `True` döndürür ve hash'i ekler.

---

### `_next_id(cat)` (Satır 1072-1075)

Thread-safe artan ID üreteci. Her kategori için bağımsız sayaç tutar.

---

### `_add_finding(cat, finding)` (Satır 1077-1081)

Thread-safe bulgu ekleme. Dataclass nesnesi veya dict kabul eder.

---

### `_risk_score(severity, confidence, entropy)` (Satır 1083-1088)

CVSS-tabanlı bileşik risk puanı hesaplama. [Detaylar: 05-secret-scanner.md]

---

### `_root_domain(netloc)` (Satır 949-952)

Netloc'tan kök domain çıkarır:
- `www.example.com` → `example.com`
- `sub.api.example.co.uk` → `co.uk` (basit 2-parçalı mantık)

---

### `_is_external_lib(url)` (Satır 1027-1031)

URL'nin bilinen CDN host'larından gelip gelmediğini kontrol eder. [Detaylar: 03-pattern-registry.md]

---

## Açıklama ve Öneri Tabloları

### JS Zafiyet Açıklamaları — `_JS_DESCS` (Satır 2255-2270)

| Kategori | Açıklama |
|----------|----------|
| DOM XSS | Kullanıcı kontrollü veri, sanitize edilmeden DOM sink'ine akar |
| Open Redirect | Kullanıcı girdisi yönlendirme hedefini belirler |
| Prototype Pollution | Object prototype kullanıcı kontrollü anahtarlarla manipüle edilir |
| Dynamic Code Execution | Potansiyel olarak sanitize edilmemiş girdi ile kod çalıştırılır |
| Insecure postMessage | postMessage wildcard origin kullanıyor veya alıcı origin doğrulamıyor |
| Sensitive Data in Client Storage | Hassas değerler localStorage/sessionStorage/cookie'de saklanıyor |
| WebSocket Plaintext | WebSocket şifrelenmemiş ws:// protokolü kullanıyor |
| Weak / Broken Crypto | Kullanımdan kaldırılmış veya güvensiz kriptografik primitif |
| Path Traversal | Dosya yolu kullanıcı girdisinden türetiliyor |
| JSONP Callback Injection | JSONP callback adı kullanıcı girdisinden geliyor |
| Server-Side Request Forgery (JS) | fetch/axios/XHR URL'si kullanıcı kontrollü girdiden oluşturuluyor |
| Debug / Secret Console Leak | Hassas değerler console.* ile loglanıyor |
| Hardcoded Internal IP | İç ağ IP adresi istemci tarafı kodda bulundu |
| Taint Flow: Source → Sink | Kullanıcı kontrollü veri tainted kaynaktan tehlikeli sink'e akıyor |

### JS Zafiyet Önerileri — `_JS_RECS` (Satır 2272-2287)

| Kategori | Öneri |
|----------|-------|
| DOM XSS | DOMPurify kullan; düz metin için textContent kullan |
| Open Redirect | İzin verilen hedefleri allowlist ile sınırla |
| Prototype Pollution | Güvenilmeyen map'ler için Object.create(null) kullan |
| Dynamic Code Execution | eval()/new Function() kaldır, statik import kullan |
| Insecure postMessage | Tam target origin belirt; event.origin doğrula |
| Sensitive Data in Client Storage | Token'ları HttpOnly cookie'lerde sakla |
| WebSocket Plaintext | Her zaman wss:// kullan |
| Weak / Broken Crypto | SHA-256+ kullan; Math.random() yerine crypto.getRandomValues() |
| Path Traversal | path.resolve() kullan, sonucun izin verilen dizin içinde olduğunu doğrula |
| JSONP Callback Injection | JSONP yerine CORS destekli JSON API kullan |
| Server-Side Request Forgery (JS) | fetch hedeflerini allowlist ile sınırla |
| Debug / Secret Console Leak | Prodüksiyonda hassas debug loglama kaldır |
| Hardcoded Internal IP | Hardcode yerine servis keşfi (env-based) kullan |

### Secret Önerileri — `_SEC_RECS` (Satır 2289-2301)

| Secret Türü | Öneri |
|-------------|-------|
| AWS Access Key ID | AWS IAM ile rotate et. IAM role tercih et |
| AWS Secret Access Key | Hemen rotate et. AWS Secrets Manager kullan |
| Google API Key | Kapsamı kısıtla ve rotate et |
| OpenAI API Key | platform.openai.com'dan rotate et |
| Stripe Secret Key | Stripe dashboard'dan rotate et |
| GitHub PAT (classic) | github.com → Settings → Tokens'tan revoke et |
| SSH/PEM Private Key | Tüm sunucularda keypair değiştir |
| MongoDB Connection String | Credential'ları rotate et |
| HashiCorp Vault Token | `vault token revoke` ile revoke et |

---

## Durum Yönetimi

### `_save_state()` (Satır 2422-2427)

Ziyaret edilen URL'leri JSON dosyasına kaydeder:

```python
# Dosya: {output_dir}/.state_{domain}.json
{"visited_urls": ["https://example.com/", ...]}
```

### `_load_state()` (Satır 2429-2437)

`resume=True` ile başlatıldığında daha önce kaydedilen durumu yükler:

```python
self.visited_urls = set(state.get("visited_urls", []))
```

### `_on_sigint()` (Satır 954-956)

SIGINT (Ctrl+C) yakalandığında `_shutdown` event'i set edilir → tüm thread'ler güvenli şekilde durur.

---

## Özet Rapor — `_build_summary()` (Satır 2332-2393)

Tüm bulguları özetleyen kapsamlı bir rapor oluşturur.

### Güvenlik Notu

| Risk Puanı | Not |
|------------|-----|
| ≥ 9.0 | F |
| ≥ 7.5 | D |
| ≥ 5.0 | C |
| ≥ 3.0 | B |
| ≥ 1.0 | A |
| 0 | A+ |

### Özet Alanları

| Alan | Açıklama |
|------|----------|
| `scanner_version` | Tarayıcı versiyonu |
| `scan_date` | Tarama tarihi (UTC ISO) |
| `scan_duration_seconds` | Toplam süre |
| `total_urls_crawled` | Taranan URL sayısı |
| `total_js_files` | İşlenen JS dosyası sayısı |
| `total_api_endpoints` | Keşfedilen API endpoint sayısı |
| `detected_waf` | Tespit edilen WAF |
| `overall_risk_score` | Genel risk puanı (0-10) |
| `security_grade` | Güvenlik notu (A+ – F) |

---

## CLI (Komut Satırı Arayüzü) — (Satır 2491-2544)

```bash
# Temel kullanım
python advanced_content_scanner.py example.com

# Tam özelliklerle
python advanced_content_scanner.py example.com \
    --active --headless \
    --nuclei /usr/bin/nuclei \
    --depth 4 --pages 500 \
    --oob-domain xxx.interact.sh

# Aktif testi kapalı
python advanced_content_scanner.py example.com --no-active
```

### CLI Parametreleri

| Parametre | Varsayılan | Açıklama |
|-----------|-----------|----------|
| `domain` | (zorunlu) | Hedef domain |
| `--depth` | 3 | Crawl derinliği |
| `--pages` | 200 | Maksimum sayfa |
| `--workers` | 15 | Eş zamanlı thread |
| `--rate` | 0.15 | İstekler arası bekleme (saniye) |
| `--no-ssl-verify` | False | SSL doğrulamayı kapat |
| `--log-level` | INFO | Log seviyesi |
| `--output-dir` | None | Çıktı dizini |
| `--oob-domain` | None | SSRF OOB callback domain |
| `--subdomains` | False | Alt domain'leri dahil et |
| `--resume` | False | Önceki durumdan devam et |
| `--min-severity` | Low | Minimum ciddiyet filtresi |
| `--active/--no-active` | True | Aktif test |
| `--nuclei` | None | Nuclei binary yolu |
| `--headless` | False | Playwright headless |
| `--no-fuzz` | True | Form fuzzing |
| `--no-chains` | True | Exploit zinciri |
