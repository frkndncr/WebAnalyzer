# L2 — Active Testing (Aktif Güvenlik Testleri)

L2 katmanı, hedef siteye aktif olarak payload gönderen, yanıtları analiz eden ve güvenlik açıklarını doğrulayan bileşenleri içerir.

## L2 Bileşenleri

```mermaid
flowchart TD
    L2["L2 — Active Testing"]
    L2 --> SP["_scan_sensitive_paths()<br/>Hassas dosya yolu keşfi"]
    L2 --> FF["_test_forms_active()<br/>Form fuzzing (SQLi, XSS, SSTI)"]
    L2 --> AB["_test_auth_bypass()<br/>403 bypass testleri"]
    L2 --> CO["_test_cors()<br/>CORS yapılandırma testi"]
    L2 --> NU["_run_nuclei()<br/>Nuclei CVE tarama"]

    style L2 fill:#e8710a,color:#fff
    style SP fill:#d32f2f,color:#fff
    style FF fill:#d32f2f,color:#fff
    style AB fill:#d32f2f,color:#fff
    style CO fill:#d32f2f,color:#fff
    style NU fill:#d32f2f,color:#fff
```

---

## 1. Hassas Dosya Yolu Keşfi — `_scan_sensitive_paths()` (Satır 1603–1635)

50+ hassas yolu paralel Thread havuzu ile tarar.

```mermaid
flowchart TD
    A["50+ hassas yol listesi"] --> B["ThreadPoolExecutor<br/>(max 20 worker)"]
    B --> C["Her yol için GET isteği"]
    C --> D{"HTTP yanıt kodu?"}
    D -- "200/206" --> E["İçerik 10+ karakter mi?"]
    E -- Evet --> F["ExposedEndpoint kaydet"]
    D -- "401/403" --> G["Mevcut ama korumalı"]
    G --> H["Severity düşür (Critical → High)"]
    H --> F
    D -- Diğer --> SKIP["Atla"]
    E -- Hayır --> SKIP
```

### Kontrol Edilen Yol Kategorileri

| Kategori | Örnekler | Severity |
|----------|----------|----------|
| Environment | `.env`, `.env.production` | Critical |
| Git/SVN | `.git/config`, `.svn/entries` | Critical–High |
| Veritabanı Yedekleri | `backup.sql`, `dump.sql` | Critical |
| Debug Endpoint | `/debug`, `/actuator/env` | High–Critical |
| API Dokümantasyon | `/swagger`, `/openapi.json` | Medium |
| Sunucu Bilgisi | `/phpinfo.php`, `/server-status` | High–Medium |
| Parola Dosyaları | `.htpasswd` | Critical |

---

## 2. Form Fuzzing — `_test_forms_active()` (Satır 1641–1718)

Her sayfadaki formları 3 farklı payload türüyle test eder.

```mermaid
flowchart TD
    A["HTML formlarını bul (max 3/sayfa)"] --> B["Form alanlarını çıkar<br/>(submit, hidden, button hariç)"]
    B --> C["Her fuzz türü için döngü"]
    
    C --> XSS["XSS Testi"]
    C --> SQLI["SQLi Testi"]
    C --> SSTI["SSTI Testi"]
    
    XSS --> XSS_SEND["Form alanlarına payload gönder"]
    XSS_SEND --> XSS_CHECK{"'alert(1)' yanıtta var mı?"}
    XSS_CHECK -- Evet --> XSS_DOM["_is_real_xss_in_body():<br/>DOM-level doğrulama"]
    XSS_DOM -- Gerçek XSS --> XSS_SAVE["ActiveVulnFinding kaydet<br/>(High, Reflected XSS)"]
    
    SQLI --> SQLI_SEND["SQL metakarakterleri gönder"]
    SQLI_SEND --> SQLI_CHECK{"SQL hata mesajı var mı?"}
    SQLI_CHECK -- Evet --> SQLI_SAVE["ActiveVulnFinding kaydet<br/>(Critical, SQL Injection)"]
    
    SSTI --> SSTI_SEND["{{7*7}} gönder"]
    SSTI_SEND --> SSTI_CHECK["_check_ssti_differential()"]
```

### XSS Doğrulama — `_is_real_xss_in_body()` (Satır 1720–1767)

3 aşamalı DOM-seviye XSS doğrulaması:

```mermaid
flowchart TD
    A["Yanıt HTML'ini<br/>BeautifulSoup ile ayrıştır"] --> B["Kontrol 1: Gerçek DOM event handler"]
    B --> C{"onerror/onload/onclick<br/>attribute'unda 'alert' var mı?"}
    C -- Evet --> TRUE["✅ Gerçek XSS"]
    C -- Hayır --> D["Kontrol 2: <script> tag içinde alert"]
    D --> E["Yorum ve string literal'leri çıkar"]
    E --> F{"Temizlenmiş kodda<br/>alert() var mı?"}
    F -- Evet --> TRUE
    F -- Hayır --> G["Kontrol 3: javascript: protocol"]
    G --> H{"href/src/action'da<br/>javascript:alert var mı?"}
    H -- Evet --> TRUE
    H -- Hayır --> FALSE["❌ XSS değil (FP)"]
```

> **Önemli**: Bu yöntem, `<img onerror=alert(1)>` gibi payload'ların HTML-encode edilmiş halde geri döndüğü durumları doğru şekilde filtreler.

### SQLi Hata Tespiti

Aşağıdaki SQL hata mesajları aranır:
```
sql syntax, mysql_fetch, ora-01756, microsoft ole db,
unclosed quotation, pg_query, sqlite_, syntax error,
division by zero, invalid query
```

### SSTI Diferansiyel Testi — `_check_ssti_differential()` (Satır 1769–1819)

3 adımlı güvenilir SSTI tespiti:

```mermaid
flowchart TD
    A["1. Baseline gönder:<br/>'scanner_baseline_xyz'"] --> B["Baseline yanıtını kaydet"]
    B --> C["2. Payload 1 gönder:<br/>'{{7*7}}'"]
    C --> D["Yanıtta '49' var mı?"]
    D --> E["3. Kontrol payload gönder:<br/>'{{8*8}}'"]
    E --> F["Yanıtta '64' var mı?"]
    F --> G{"Tüm koşullar sağlanıyor mu?"}
    G --> H["• '49' yanıtta var VE baseline'da yok<br/>• '64' yanıtta var VE baseline'da yok<br/>• '{{7*7}}' olduğu gibi yanıtta yok"]
    H -- Tümü Evet --> I["✅ SSTI Doğrulandı!<br/>(Critical, HIGH confidence)"]
    H -- Herhangi biri Hayır --> J["❌ SSTI değil"]
```

---

## 3. Auth Bypass — `_test_auth_bypass()` (Satır 1840–1895)

403 yanıt döndüren sayfalarda bypass denemeleri yapar.

```mermaid
flowchart TD
    A["Ziyaret edilmiş URL'lerden<br/>403 döndürenleri bul (max 30)"] --> B["İlk 5'ini test et"]
    B --> C["Header tabanlı bypass"]
    B --> D["Path tabanlı bypass"]
    
    C --> C1["X-Original-URL: /admin"]
    C --> C2["X-Forwarded-For: 127.0.0.1"]
    C --> C3["X-Client-IP: 127.0.0.1"]
    C --> C4["... 9 farklı header"]
    C1 --> CHECK_H{"403 → 200?"}
    CHECK_H -- Evet --> SAVE_H["ActiveVulnFinding kaydet<br/>(High, 403 Bypass via Header)"]
    
    D --> D1["/path/"]
    D --> D2["/path//"]
    D --> D3["/path/.."]
    D --> D4["/path%20"]
    D --> D5["/path?"]
    D1 --> CHECK_P{"403 → 200?"}
    CHECK_P -- Evet --> SAVE_P["ActiveVulnFinding kaydet<br/>(High, 403 Bypass via Path)"]
```

### Bypass Header'ları

| Header | Değer |
|--------|-------|
| `X-Original-URL` | `/admin` |
| `X-Rewrite-URL` | `/admin` |
| `X-Custom-IP-Authorization` | `127.0.0.1` |
| `X-Forwarded-For` | `127.0.0.1` |
| `X-Forward-For` | `127.0.0.1` |
| `X-Remote-IP` | `127.0.0.1` |
| `X-Originating-IP` | `127.0.0.1` |
| `X-Remote-Addr` | `127.0.0.1` |
| `X-Client-IP` | `127.0.0.1` |

---

## 4. CORS Testi — `_test_cors()` (Satır 1901–1939)

CORS yapılandırma hataları için aktif sondaj yapar.

```mermaid
flowchart TD
    A["Test URL'leri: base_url + API endpoint'leri (max 10)"] --> B["Her URL için 3 test origin"]
    B --> C["Origin: https://evil.com"]
    B --> D["Origin: https://attacker.com"]
    B --> E["Origin: null"]
    C --> F["GET isteği + Origin header"]
    F --> G{"ACAO header kontrol"}
    G -- "ACAO: *" --> H["CORS Wildcard Origin<br/>(Medium severity)"]
    G -- "origin yansıtıldı" --> I{"ACAC: true?"}
    I -- Evet --> J["CORS Origin Reflection + Credentials<br/>(High severity)"]
    I -- Hayır --> K["CORS Origin Reflection<br/>(Medium severity)"]
```

### Test Origin'leri
- `https://evil.com`
- `https://attacker.com`
- `null`

### Kontrol Edilen Header'lar
- `Access-Control-Allow-Origin` (ACAO)
- `Access-Control-Allow-Credentials` (ACAC)

---

## 5. Nuclei Entegrasyonu — `_run_nuclei()` (Satır 1945–1987)

Harici Nuclei binary'sini çalıştırarak 10.000+ CVE template ile tarar.

```mermaid
flowchart TD
    A{"Nuclei binary var mı?"}
    A -- Hayır --> SKIP["Atla (log bilgisi)"]
    A -- Evet --> B["Nuclei çalıştır:<br/>nuclei -u base_url -json -severity medium,high,critical"]
    B --> C{"300s timeout?"}
    C -- Timeout --> D["Uyarı logu"]
    C -- Tamamlandı --> E["JSON çıktısını oku"]
    E --> F["Her satır için ActiveVulnFinding oluştur"]
    F --> G["Template ID, CVSS, açıklama, remediation bilgisi al"]
```

### Nuclei Komut Parametreleri

```bash
nuclei -u <base_url> \
  -json \
  -o <output_dir>/nuclei_output.json \
  -severity medium,high,critical \
  -timeout 10 \
  -retries 1 \
  -rate-limit 30 \
  -silent
```
