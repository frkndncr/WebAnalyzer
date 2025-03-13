# Web Analiz Aracı

## Genel Bakış
**Web Analiz Aracı**, WHOIS bilgisi alma, DNS kayıtları, alt alan adı keşfi, SEO analizi, web teknolojisi tespiti ve gelişmiş güvenlik analizi gibi alan analizleri için tasarlanmış kapsamlı bir Python tabanlı uygulamadır.

---

## Özellikler

1. **Alan Bilgisi Alma**
   - WHOIS bilgilerini (kayıt şirketi, oluşturma tarihi, son kullanma tarihi vb.) getirir.
   - Gizlilik korumasını, DNSSEC durumunu ve SSL ayrıntılarını tespit eder.
   - Sunucu sağlayıcısını ve fiziksel konum bilgisini alır.

2. **DNS Kayıt Analizi**
   - A (IPv4), AAAA (IPv6), MX (Posta Sunucuları), TXT (Doğrulama) ve NS (Ad Sunucusu) kayıtlarını çözer.
   - DNS yanıt süresini ölçer.

3. **Alt Alan Adı Keşfi**
   - Belirtilen alanın alt alan adlarını keşfetmek için **Subfinder** kullanır.
   - Sonuçları `logs/` altındaki ilgili alan klasörüne kaydeder.

4. **SEO ve Analitik Analizi**
   - Meta etiketleri (açıklama, anahtar kelimeler, kanonik bağlantılar) çıkarır.
   - Open Graph ve Twitter etiketlerini tanımlar.
   - Doğrulama etiketlerini (Google, Bing, Yandex) tespit eder.
   - Analitik araçları (Google Analytics, Tag Manager, Facebook Pixel vb.) tanır.
   - JavaScript çerçevelerini ve yapılandırılmış verileri değerlendirir.
   - Sayfa yükleme süresini ölçer ve performans metriklerini kontrol eder.
   - `robots.txt` ve `sitemap.xml` dosyalarını analiz eder.

5. **Web Teknolojisi Tespiti**
   - Arka uç teknolojilerini (PHP, Django, Node.js vb.) tespit eder.
   - Ön uç çerçevelerini (React, Angular, Bootstrap vb.) tanır.
   - CDN hizmetlerini tanır ve sıkıştırma ile önbellekleme politikalarını kontrol eder.

6. **Gelişmiş Güvenlik Analizi**
   - Web Uygulama Güvenlik Duvarlarını (WAF) tespit eder.
   - HTTPS zorlamasını ve SSL sertifikalarını analiz eder.
   - Güvenlik başlıklarını (CSP, HSTS vb.) inceler.
   - Çapraz Kaynak Paylaşım (CORS) politikasını kontrol eder.

7. **Alt Alan Adı Ele Geçirme Tespiti**
   - Keşfedilen alt alan adlarını alt alan adı ele geçirme saldırılarına karşı potansiyel güvenlik açıkları için tarar.
   - Güvenlik açıklarını güven derecesine göre kategorize eder (Yüksek, Orta, Düşük).
   - Belirli hizmetleri ve olası sömürü yöntemlerini tanımlar.
   - Savunmasız alt alan adları için azaltma önerileri sunar.
   - Acil dikkat gerektiren kritik güvenlik açıklarını vurgular.

8. **Gelişmiş İçerik Tarayıcı**
   - Birden fazla sayfa üzerinde derin web içeriği analizi gerçekleştirir.
   - Hassas bilgi sızıntılarını keşfeder ve analiz eder.
   - Potansiyel JavaScript tabanlı güvenlik açıklarını tespit eder.
   - Sunucu Taraflı İstek Sahteciliği (SSRF) risklerini belirler.
   - Açığa çıkan sırları, API anahtarlarını ve kimlik bilgilerini tarar.
   - Yüksek önem derecesine sahip bulgular hakkında ayrıntılı raporlama sağlar.
   - Yapılandırılabilir tarama derinliği ve sayfa sınırlarını destekler.

---

## Kurulum

### Gereksinimler
Aşağıdaki bağımlılıkların yüklü olduğundan emin olun:
- Python 3.x
- Go (Subfinder için)
- Git

### Kurulum Adımları

1. Depoyu klonlayın:
   ```bash
   git clone https://github.com/frkndncr/WebAnalyzer.git
   cd WebAnalyzer
   ```

2. Python Bağımlılıklarını Yükleyin:
   ```bash
   pip install -r requirements.txt
   ```

3. Kurulum betiğini çalıştırın:
   ```bash
   ./setup.sh
   ```
   Bu betik şunları yapar:
   - Gerekli sistem paketlerini kurar.
   - **Subfinder**'ı kurar ve yapılandırır.

4. Kurulumu doğrulayın:
   - `subfinder`'ın PATH içinde kullanılabilir olduğundan emin olun.
   - Tüm Python modüllerinin başarıyla yüklendiğini kontrol edin.

---

## Kullanım

1. Ana betiği çalıştırın:
   ```bash
   python main.py
   ```

2. İstendiğinde alan adını girin:
   ```
   Lütfen bir alan adı girin (örneğin, example.com): sizin-alan-adiniz.com
   ```

3. Araç şunları yapar:
   - Tüm analizleri gerçekleştirir.
   - Sonuçları terminalde görüntüler.
   - Tüm sonuçları `logs/{alan}/results.json` altında yapılandırılmış bir JSON dosyasına kaydeder.

---

## Proje Yapısı

```plaintext
.
├── main.py                 # Uygulamanın giriş noktası
├── setup.sh                # Kurulum betiği
├── requirements.txt        # Python bağımlılıkları
├── logs/                   # Analiz sonuçlarını saklama dizini
├── modules/                # Tüm analiz modüllerini içeren dizin
│   ├── domain_dns.py       # DNS kayıt analizi modülü
│   ├── domain_info.py      # WHOIS bilgisi alma modülü
│   ├── seo_analysis.py     # SEO ve analitik analiz modülü
│   ├── security_analysis.py# Güvenlik analizi modülü
│   ├── subfinder_tool.py   # Alt alan adı keşif modülü
│   ├── web_technologies.py # Web teknolojisi tespiti modülü
│   ├── subdomain_takeover.py # Alt alan adı ele geçirme güvenlik açığı tespiti modülü
│   ├── advanced_content_scanner.py # Gelişmiş web içeriği tarama modülü
└── tests/                  # Proje için test betikleri
    └── test_main.py        # main.py için birim testleri
```

---

## Örnek Çıktı Ekran Görüntüsü

![resim](https://github.com/user-attachments/assets/61580f3c-741b-46b3-aefb-5590f895f856)

### JSON Çıktısı:
Sonuçlar, ilgili alan klasöründe `results.json` olarak kaydedilir:

```json
{
  "Alan Bilgisi": {
    "Alan": "example.com",
    "Kayıt Şirketi": "Kayıt Şirketi Adı",
    "Oluşturma Tarihi": "2020-01-01",
    "Bitiş Tarihi": "2025-01-01",
    "Gizlilik Koruması": "Etkin",
    "Sunucu Sağlayıcı": "Cloudflare",
    "Fiziksel Konum": "San Francisco, ABD"
  },
  "DNS Kayıtları": {
    "A Kayıtları (IPv4)": ["192.168.0.1"],
    "MX Kayıtları (Posta Sunucuları)": ["mail.example.com"],
    "Yanıt Süresi (ms)": 35.5
  },
  "Alt Alan Adları": ["www.example.com", "blog.example.com"],
  "SEO Analizi": {
    "Meta Etiketler": {"Açıklama": "Örnek açıklama"},
    "Analitik Araçlar": {"Google Analytics Kimlikleri": ["UA-123456-7"]}
  },
  "Web Teknolojileri": {
    "Arka Uç Teknolojileri": ["PHP", "WordPress"],
    "Ön Uç Teknolojileri": ["Bootstrap"],
    "İçerik Dağıtım Ağı (CDN)": "Cloudflare"
  },
  "Güvenlik Analizi": {
    "Web Uygulama Güvenlik Duvarı": "Cloudflare",
    "SSL Bilgisi": {"Düzenleyen": "Let's Encrypt"}
  },
  "Alt Alan Adı Ele Geçirme": {
    "Savunmasız Alt Alan Adları": [
      {
        "alt_alan": "dev.example.com",
        "güvenlik_açığı_türü": "Heroku Alt Alan Adı Ele Geçirme",
        "güven": "Yüksek",
        "hizmet": "Heroku",
        "sömürü_zorluğu": "Orta",
        "azaltma": "Alt alan adını talep et veya DNS kaydını kaldır"
      }
    ],
    "İstatistikler": {
      "kontrol_edilen_toplam_alt_alan": 10,
      "yüksek_güven_açıkları": 1,
      "orta_güven_açıkları": 0,
      "düşük_güven_açıkları": 0
    }
  },
  "Gelişmiş İçerik Taraması": {
    "özet": {
      "taranan_toplam_url": 50,
      "toplam_js_dosyaları": 20,
      "toplam_api_uç_noktaları": 15
    },
    "sırlar": [
      {
        "tür": "API Anahtarı",
        "kaynak_url": "https://example.com/js/config.js",
        "önem": "Yüksek"
      }
    ],
    "js_güvenlik_açıkları": [
      {
        "tür": "Çapraz Site Komut Dosyası Çalıştırma (XSS)",
        "kaynak_url": "https://example.com/main.js",
        "önem": "Orta"
      }
    ],
    "ssrf_güvenlik_açıkları": [
      {
        "tür": "Potansiyel SSRF Uç Noktası",
        "kaynak_url": "https://example.com/proxy",
        "önem": "Yüksek"
      }
    ]
  }
}
```

---

## Katkı

Bu projeye şu yollarla katkıda bulunabilirsiniz:
- Sorunları bildirin.
- Özellik önerilerinde bulunun.
- Çekme istekleri gönderin.

---

## Lisans

Bu proje MIT Lisansı altında lisanslanmıştır.

## İletişim

- Instagram: https://www.instagram.com/f3rrkan/
- LinkedIn: https://www.linkedin.com/in/furkan-dincer/
- E-posta: hi@c4softwarestudio.com

---
