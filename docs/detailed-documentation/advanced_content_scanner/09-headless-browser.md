# L4 — Headless Browser (Playwright Entegrasyonu)

L4 katmanı, Playwright headless tarayıcısı kullanarak çalışma zamanı (runtime) analizi yapar. Statik analizin kaçırdığı dinamik içerikleri, SPA rotalarını ve runtime gizli bilgileri tespit eder.

## Ön Koşullar

| Gereksinim | Durum |
|------------|-------|
| `playwright` Python paketi | Opsiyonel (graceful fallback) |
| Chromium binary | `playwright install chromium` |
| `headless=True` parametresi | Scanner init'te aktif edilmeli |

```python
# Opsiyonel import — kurulu değilse PLAYWRIGHT_AVAILABLE = False
try:
    from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
```

---

## Genel Akış

```mermaid
flowchart TD
    START["_run_headless_scan()"] --> CHECK{"Playwright mevcut?<br/>headless aktif?"}
    CHECK -- Hayır --> SKIP["Atla (log bilgisi)"]
    CHECK -- Evet --> LAUNCH["Chromium başlat<br/>(headless=True, no-sandbox)"]
    LAUNCH --> NAV["base_url'e git<br/>(networkidle bekle, 20s timeout)"]
    NAV --> S1["1️⃣ Runtime Secret Tarama"]
    S1 --> S2["2️⃣ Storage Tarama"]
    S2 --> S3["3️⃣ Network İstek Yakalama"]
    S3 --> S4["4️⃣ SPA Rota Keşfi"]
    S4 --> S5["5️⃣ Rendered HTML Tarama"]
    S5 --> CLOSE["Browser kapat"]

    style START fill:#9c27b0,color:#fff
    style LAUNCH fill:#1a73e8,color:#fff
    style CLOSE fill:#0d904f,color:#fff
```

---

## 1️⃣ Runtime Secret Tarama — `window` / `globalThis`

Tarayıcı bağlamında JavaScript çalıştırarak `window` nesnesindeki hassas değişkenleri tarar.

```mermaid
flowchart TD
    A["page.evaluate():<br/>Object.keys(window) üzerinde döngü"] --> B["Regex: /secret|token|key|password|api|auth/i"]
    B --> C{"Eşleşme var mı?"}
    C -- Evet --> D["Değerin Entropy'sini hesapla"]
    D --> E{"Entropi > 3.5?"}
    E -- Evet --> F["SecretFinding kaydet<br/>(type='Runtime Window Secret',<br/>severity=High, confidence=HIGH)"]
    E -- Hayır --> SKIP["Atla"]
    C -- Hayır --> SKIP
```

### JavaScript Kodu (Tarayıcıda Çalışır)

```javascript
() => {
    const keys = [];
    const sensitive = /secret|token|key|password|api|auth/i;
    try {
        for (const k of Object.keys(window)) {
            if (sensitive.test(k))
                keys.push({key: k, val: String(window[k]).slice(0,100)});
        }
    } catch(e) {}
    return keys;
}
```

---

## 2️⃣ Storage Tarama — localStorage / sessionStorage

```mermaid
flowchart TD
    A["page.evaluate():<br/>localStorage + sessionStorage oku"] --> B["Her anahtar için kontrol"]
    B --> C{"Anahtar adında<br/>token/key/secret/auth/pass var mı?"}
    C -- Evet --> D["Değerin Entropy'sini hesapla"]
    D --> E{"Entropi > 3.0?"}
    E -- Evet --> F["SecretFinding kaydet<br/>(type='Secret in Browser Storage',<br/>severity=High)"]
    E -- Hayır --> SKIP["Atla"]
    C -- Hayır --> SKIP
```

**Öneri:** `"Store tokens in HttpOnly cookies, not Web Storage."`

---

## 3️⃣ Network İstek Yakalama

Sayfa yüklenirken yapılan tüm HTTP istekleri kaydedilir:

```python
captured_requests: List[str] = []
page.on("request", lambda req: captured_requests.append(req.url))
```

```mermaid
flowchart TD
    A["Yakalanan tüm request URL'leri"] --> B{"Kapsam içinde mi?"}
    B -- Evet --> C{"Ziyaret edilmemiş mi?"}
    C -- Evet --> D{"API regex eşleşiyor mu?"}
    D -- Evet --> E["api_endpoints kümesine ekle"]
    B -- Hayır --> SKIP["Atla"]
```

Bu sayede lazy-loaded API çağrıları, AJAX istekleri ve üçüncü taraf servis bağlantıları tespit edilir.

---

## 4️⃣ SPA Rota Keşfi

Navigasyon bağlantılarına tıklayarak SPA (Single Page Application) rotalarını keşfeder:

```mermaid
flowchart TD
    A["Nav elemanlarını bul:<br/>a[href^='/'], nav a, [role='navigation'] a"] --> B["İlk 15 link"]
    B --> C["Her link için href oku"]
    C --> D{"http/javascript/# ile başlamıyor?"}
    D -- Evet --> E["Mutlak URL'e dönüştür"]
    E --> F{"Ziyaret edilmemiş mi?"}
    F -- Evet --> G["_dynamic_routes kümesine ekle"]
```

> **Not:** Keşfedilen dinamik rotalar, daha sonra `_process_url()` ile tek tek işlenir (ana `run()` akışında).

---

## 5️⃣ Rendered HTML Tarama

Playwright ile render edilen HTML, statik HTML'den farklı olabilir (React, Vue, Angular uygulamaları). Bu nedenle render edilmiş HTML de gizli bilgi taramasından geçirilir:

```python
html = page.content()
self._scan_secrets(html, f"{self.base_url}#headless-rendered")
```

---

## Hata Yönetimi

| Hata Türü | Davranış |
|-----------|----------|
| `PWTimeout` (Playwright Timeout) | Uyarı logu, tarama devam eder |
| Genel `Exception` | Hata logu, tarama devam eder |
| `ImportError` (Playwright yok) | `PLAYWRIGHT_AVAILABLE = False`, L4 tamamen atlanır |

---

## L4'ün Diğer Katmanlarla Entegrasyonu

```mermaid
flowchart LR
    L4["L4: Headless Browser"]
    L4 --> |"Runtime secrets"| L1_SEC["L1: _scan_secrets()"]
    L4 --> |"API endpoints"| L1_API["L1: api_endpoints"]
    L4 --> |"Dynamic routes"| L1_PROC["L1: _process_url()"]
    L4 --> |"Storage secrets"| FINDINGS["findings[secrets]"]
    
    style L4 fill:#9c27b0,color:#fff
```
