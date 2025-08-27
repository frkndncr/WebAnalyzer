# WebAnalyzer - Gelişmiş Alan Adı Güvenlik, OSINT & Açık Tespit Aracı

<div align="center">

![WebAnalyzer Banner](https://img.shields.io/badge/WebAnalyzer-v2.0-blue?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.8+-green?style=for-the-badge&logo=python)
![License](https://img.shields.io/badge/License-MIT-red?style=for-the-badge)
![Security](https://img.shields.io/badge/Güvenlik-Odaklı-orange?style=for-the-badge)

**Siber güvenlik uzmanları için kapsamlı alan adı analizi, OSINT ve güvenlik değerlendirme aracı**

</div>

## 🚀 Genel Bakış

WebAnalyzer, **Python tabanlı gelişmiş bir alan adı analiz ve güvenlik değerlendirme framework’üdür**.  
Siber güvenlik uzmanları, penetrasyon testçileri ve OSINT araştırmacıları için geliştirilmiştir.  

Bu araç, **keşif (reconnaissance), güvenlik testleri ve istihbarat toplama (OSINT)** özelliklerini tek bir çatı altında toplar.  
Ayrıca gelişmiş **IP rotasyonu ve rate limit koruması** ile tespit edilmeden çalışabilir.

### ✨ Temel Özellikler

- **12 Gelişmiş Analiz Modülü** – Basit domain bilgisinden API güvenlik testine kadar  
- **IP Rotasyonu & Rate Limit Koruması** – Tespit önleyici mekanizmalar  
- **Kapsamlı Güvenlik Testleri** – Çeşitli zafiyet tespit teknikleri  
- **OSINT & İstihbarat Toplama** – İletişim bilgileri, sosyal medya, metadata keşfi  
- **Profesyonel Raporlama** – JSON formatında detaylı risk skorlaması  
- **Modüler Mimari** – Kolayca özelleştirilebilir ve genişletilebilir  

---

## 🛠️ Analiz Modülleri

### 📊 Temel İstihbarat Modülleri

| Modül | Açıklama | Risk Seviyesi |
|-------|----------|---------------|
| **Domain Bilgisi** | WHOIS verileri, kayıt bilgileri, DNS kayıtları | Düşük |
| **DNS Analizi** | Detaylı DNS kayıt incelemesi | Düşük |
| **SEO Analizi** | 13 kategoriye göre arama motoru optimizasyonu incelemesi | Düşük |
| **Web Teknolojileri** | Kullanılan frontend/backend teknolojilerinin tespiti | Düşük |

### 🔍 Keşif (Reconnaissance) Modülleri

| Modül | Açıklama | Risk Seviyesi |
|-------|----------|---------------|
| **Alt Alan Adı Keşfi** | Subfinder ile gelişmiş alt alan adı taraması | Orta |
| **İletişim İstihbaratı** | E-posta, telefon, sosyal medya profili bulma | Orta |
| **İçerik Taraması** | Web içeriğinde hassas bilgi ve veri arama | Orta |

### 🔒 Güvenlik Testi Modülleri

| Modül | Açıklama | Risk Seviyesi |
|-------|----------|---------------|
| **Güvenlik Analizi** | Güvenlik header’ları, SSL/TLS konfigürasyonu | Orta |
| **Subdomain Takeover** | Alt alan adı takeover zafiyet taraması | Yüksek |
| **CloudFlare Bypass** | WAF bypass ve gerçek IP bulma | Yüksek |
| **Ağ Tarayıcı** | Port taraması ve servis tespiti | Yüksek |
| **API Güvenlik Tarayıcı** | API zafiyet ve exploit testleri | Kritik |

---

## ⚡ Kurulum

### Gereksinimler
```bash
- Python 3.8+
- Go (Subfinder entegrasyonu için)
- Git
```

### Hızlı Kurulum
```bash
# Depoyu klonla
git clone https://github.com/frkndncr/WebAnalyzer.git
cd WebAnalyzer

# Python bağımlılıklarını yükle
pip install -r requirements.txt --break-system-packages

# Kurulum scriptini çalıştır
chmod +x setup.sh
./setup.sh

# Çalıştırmayı doğrula
python main.py
```

### Gelişmiş Konfigürasyon
```bash
# Konfigürasyon dosyası oluştur
python config.py --create-config

# API anahtarlarını ekle (opsiyonel)
export WHOIS_API_KEY="api_anahtarınız"
python config.py --set-api-key "api_anahtarınız"

# Proxy ayarları (opsiyonel)
python config.py --add-proxy "http://proxy:8080"
```

---

## 🎯 Kullanım

### İnteraktif Mod
```bash
python main.py
# Domain gir: example.com
# Modül seç: A (Hepsi) veya numara
```

---

## 📋 Analiz Sonuçları

### Örnek Çıktı
```json
{
  "domain": "example.com",
  "scan_timestamp": "2024-01-15 14:30:00",
  "modules_executed": 12,
  "risk_assessment": {
    "overall_grade": "B",
    "security_score": "78/100",
    "critical_findings": 0,
    "high_risk_findings": 2
  },
  "detailed_results": {
    "SEO Analizi": {
      "score": "85/100",
      "grade": "A",
      "load_time": "0.8s"
    },
    "API Güvenlik Tarayıcı": {
      "vulnerabilities": 3,
      "risk_level": "Yüksek",
      "exploitation_possible": true
    }
  }
}
```

### Risk Skorlama Sistemi
- **A (90-100)**: Çok iyi güvenlik duruşu  
- **B (80-89)**: İyi, küçük iyileştirmeler gerekli  
- **C (70-79)**: Orta risk, dikkat gerekli  
- **D (60-69)**: Zayıf güvenlik, acil aksiyon gerekli  
- **F (0-59)**: Kritik açıklar mevcut  

---

## ⚠️ Yasal ve Etik Kullanım

```
⚠️  YASAL UYARI ⚠️
Bu araç aşağıdaki agresif güvenlik testlerini içermektedir:
- Zafiyet taramaları ve exploit denemeleri
- Kimlik doğrulama atlatma teknikleri
- Enjeksiyon saldırı vektörleri
- Rate limit bypass yöntemleri

✅ YALNIZCA YETKİLİ KULLANIM
- Sadece kendi sistemlerinizde kullanın
- Yazılı izin almadan test yapmayın
- Rate limit ve kullanım şartlarına uyun
- Sorumlu zafiyet bildirim süreçlerini takip edin

❌ İZİNSİZ TESTLER YASAL SUÇTUR
```

---

## 🛡️ Güvenlik Özellikleri

### IP Rotasyonu & Kaçınma
- **Dinamik Oturum Yönetimi** – IP ve User-Agent rotasyonu  
- **Akıllı Gecikme Sistemi** – Tespit edilmemek için rastgele zamanlama  
- **Rate Limit Algılama** – Sunucu yanıtlarına göre otomatik ayarlama  
- **Header Rastgeleleştirme** – Gerçekçi tarayıcı kimliği  

### Gizlilik Yetkinlikleri
- **Proxy Chain Desteği** – Çoklu proxy sunucu desteği  
- **İstek Yavaşlatma** – İstekler arasında gecikme ayarlama  
- **Hata Kurtarma** – Farklı parametrelerle otomatik yeniden deneme  
- **Parmak İzi Gizleme** – Anti-detection teknikleri  

---

## 📁 Proje Yapısı

```
WebAnalyzer/
├── main.py                 # Ana uygulama giriş noktası
├── config.py               # Konfigürasyon yönetimi
├── requirements.txt        # Python bağımlılıkları
├── setup.sh                # Kurulum betiği
├── modules/                # Analiz modüllerini içeren dizin
│   ├── domain_dns.py       # DNS kayıt analizi modülü
│   ├── domain_info.py      # WHOIS bilgi toplama modülü
│   ├── seo_analysis.py     # SEO ve analiz modülü
│   ├── security_analysis.py# Güvenlik analizi modülü
│   ├── subfinder_tool.py   # Alt alan adı keşfi modülü
│   ├── web_technologies.py # Web teknolojisi tespit modülü
│   ├── subdomain_takeover.py # Subdomain takeover güvenlik açığı tespiti
│   ├── advanced_content_scanner.py # Gelişmiş web içerik tarama modülü
│   ├── cloudflare_bypass.py # Cloudflare ve WAF atlatma modülü
│   ├── contact_spy.py      # İletişim bilgisi keşfi modülü
│   ├── nmap_zero_day.py    # Zero-day güvenlik açığı tarama modülü
│   ├── api_security_scanner.py # API güvenlik açığı tarama modülü
├── utils/                  # Yardımcı fonksiyonlar
│   ├── session_manager.py  # IP rotasyonu ve oturum yönetimi
│   ├── module_wrapper.py   # Modül yürütme altyapısı
│   └── utils.py            # Yardımcı fonksiyonlar
└── logs/                   # Analiz sonuçları ve raporlar
```

---

## 🤝 Katkı Sağlama

Topluluktan gelecek katkılara açığız!  

### Geliştirme Alanları
- Yeni analiz modülleri (API, mobil, bulut güvenliği)  
- Kaçınma teknikleri (anti-detection yöntemleri)  
- Raporlama (daha iyi görselleştirme)  
- Performans optimizasyonu  

### Katkı Süreci
```bash
# Depoyu GitHub üzerinden fork edin
# Sonra kendi fork’unuzu klonlayın
git clone https://github.com/frkndncr/WebAnalyzer.git

# Yeni branch oluşturun
git checkout -b feature/yeni-modul

# Testleri çalıştırın
python -m pytest tests/

# Pull request açın
```

---

## 📊 Performans Metrikleri

- **Tarama Hızı**: Dakikada 10-50 endpoint  
- **Tespit Oranı**: Yaygın zafiyetlerde %95+ doğruluk  
- **Yanlış Pozitif Oranı**: <%5  
- **Kaynak Kullanımı**: Düşük CPU, orta seviye ağ trafiği  
- **Stealth Seviyesi**: Doğru konfigürasyonla yüksek  

---

## 📞 İletişim & Destek

### Profesyonel Destek
- Güvenlik danışmanlığı  
- Özel modül geliştirme  
- Eğitim hizmetleri  

### Topluluk & İletişim
- **Instagram**: [@f3rrkan](https://www.instagram.com/f3rrkan/)  
- **LinkedIn**: [Furkan Dinçer](https://www.linkedin.com/in/furkan-dincer/)  
- **E-posta**: hi@c4softwarestudio.com  
- **GitHub Issues**: Hata bildirimleri ve geliştirme talepleri  

---

## 📄 Lisans

Bu proje **MIT Lisansı** ile lisanslanmıştır. Detaylar için LICENSE dosyasına bakın.  

---

<div align="center">

**⭐ WebAnalyzer size yardımcı olduysa, depoyu yıldızlamayı unutmayın!**  

Furkan Dinçer tarafından ❤️ ile geliştirildi.  

</div>
