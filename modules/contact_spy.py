import os
import re
import csv
import json
import time
import logging
import requests
import validators
import tldextract
import iso3166
import pycountry
import warnings
import phonenumbers
from bs4 import BeautifulSoup
from datetime import datetime
from typing import Set, List, Dict, Tuple
from urllib.parse import urlparse, urljoin, urlunparse
from urllib3.exceptions import InsecureRequestWarning
from concurrent.futures import ThreadPoolExecutor
from phonenumbers import geocoder, carrier
from timezonefinder import TimezoneFinder
from dataclasses import dataclass, asdict
from langdetect import detect, LangDetectException

# Uyarıları bastır
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

@dataclass
class PhoneInfo:
    number: str         # Uluslararası formatta (+XX...) çıkacak
    country_code: str   # Örn. 'US', 'TR' vs.
    country_name: str   # Örn. 'United States', 'Turkey'
    carrier: str        # Operatör bilgisi (varsa)
    type: str           # Mobile, Fixed Line vs.
    valid: bool
    region: str         # country_name ile aynı olabilir veya ekstra region bilgisi
    timezone: str       # Zaman dilimi, virgülle birleştirilebilir

    def __hash__(self):
        """PhoneInfo nesnesi için hash metodu"""
        # Telefon numarasını ve ülke kodunu birlikte hashliyoruz
        return hash((self.number, self.country_code))

    def __eq__(self, other):
        """PhoneInfo nesnelerini karşılaştırma metodu"""
        if isinstance(other, PhoneInfo):
            # İki PhoneInfo nesnesini numara ve ülke koduna göre karşılaştırıyoruz
            return self.number == other.number and self.country_code == other.country_code
        return False

class PhoneScraper:
    def __init__(self, logger=None):
        self.logger = logger or self._default_logger()

    def _default_logger(self):
        import logging
        logger = logging.getLogger("PhoneScraper")
        logger.setLevel(logging.DEBUG)
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)
        logger.addHandler(ch)
        return logger

@dataclass
class SocialMediaProfile:
    platform: str
    url: str
    username: str
    found_on: str
    language: str

@dataclass
class ScrapedInfo:
    emails: Set[str]
    phones: List[PhoneInfo]
    social_media: List[SocialMediaProfile]
    source_url: str
    language: str
    region: str

def setup_logging(log_dir="logs", log_file="scraper.log", show_info=False):
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    
    log_path = os.path.join(log_dir, log_file)
    logger = logging.getLogger('modules.contact_spy')
    logger.setLevel(logging.INFO)
    
    # Mevcut handler'ları kapat ve temizle
    for handler in logger.handlers[:]:  # Kopya liste üzerinde döngü
        if isinstance(handler, logging.FileHandler):
            handler.close()  # Dosyayı kapat
        logger.removeHandler(handler)
    
    # FileHandler
    file_handler = logging.FileHandler(log_path, mode='a', encoding='utf-8')
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    logger.addHandler(file_handler)
    
    # ConsoleHandler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
    console_handler.setLevel(logging.INFO if show_info else logging.ERROR)
    logger.addHandler(console_handler)
    
    return logger
    
class GlobalDomainScraper:
    def __init__(self, domain: str, max_pages: int = 100, log_dir: str = "logs"):
        self.domain = domain
        self.max_pages = max_pages
        self.visited_urls: Set[str] = set()
        self.found_info: List[ScrapedInfo] = []
        self.session = requests.Session()
        self.session.verify = False  
        self.logger = setup_logging(log_dir=log_dir, log_file=f"scraper_{self.domain}.log", show_info=False)
        self.setup_patterns()
    
    def setup_patterns(self):
        """Çok dilli regex pattern'lerini hazırla"""
        # Global email patterns
        self.email_patterns = [
            r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}',
            r'mailto:[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}',
            # Yaygın email obfuscation teknikleri
            r'[A-Za-z0-9._%+-]+\s*[\[at\]|\(at\)|\[@\]|@]\s*[A-Za-z0-9.-]+\s*[\[dot\]|\(dot\)|\[.\]|\.]\s*[A-Z|a-z]{2,}',
            # Unicode karakterli emailleri de kapsa
            r'[\w\.-]+@[\w\.-]+\.\w+',
        ]

        # Global sosyal medya platformları
        self.social_media_patterns = {
            'Facebook': [
                r'(?:facebook|fb)\.com/(?:profile\.php\?id=\d+|[^/\s"\']+/?)',
                r'fb\.me/[^/\s"\']+',
                r'm\.facebook\.com/[^/\s"\']+',
            ],
            'Twitter/X': [
                r'(?:twitter|x)\.com/[^/\s"\']+',
                r'(?:mobile\.)?twitter\.com/[^/\s"\']+',
            ],
            'Instagram': [
                r'(?:www\.|mobile\.)?instagram\.com/[^/\s"\']+',
                r'instagr\.am/[^/\s"\']+',
            ],
            'LinkedIn': [
                r'linkedin\.com/(?:in|company|school)/[^/\s"\']+',
                r'lnkd\.in/[^/\s"\']+',
            ],
            'YouTube': [
                r'(?:www\.|m\.)?youtube\.com/(?:channel/|user/|c/|@)?[^/\s"\']+',
                r'youtu\.be/[^/\s"\']+',
            ],
            'GitHub': [
                r'github\.com/[^/\s"\']+',
                r'gist\.github\.com/[^/\s"\']+',
            ],
            'TikTok': [
                r'(?:www\.|vm\.)?tiktok\.com/[@\w]+',
                r'tiktok\.com/@[^/\s"\']+',
            ],
            'WeChat': [
                r'weixin\.qq\.com/[^/\s"\']+',
                r'wechat\.com/[^/\s"\']+',
            ],
            'Weibo': [
                r'weibo\.com/[^/\s"\']+',
                r't\.cn/[^/\s"\']+',
            ],
            'VK': [
                r'vk\.com/[^/\s"\']+',
            ],
            'LINE': [
                r'line\.me/[^/\s"\']+',
            ],
            'Telegram': [
                r't\.me/[^/\s"\']+',
                r'telegram\.me/[^/\s"\']+',
            ],
            'WhatsApp': [
                r'wa\.me/[^/\s"\']+',
                r'(?:chat\.)?whatsapp\.com/[^/\s"\']+',
            ],
            'Viber': [
                r'chats\.viber\.com/[^/\s"\']+',
            ],
            'QQ': [
                r'qq\.com/[^/\s"\']+',
            ],
            'Snapchat': [
                r'snapchat\.com/add/[^/\s"\']+',
            ],
            'Reddit': [
                r'reddit\.com/(?:u|user|r)/[^/\s"\']+',
            ],
            'Medium': [
                r'medium\.com/@?[^/\s"\']+',
            ],
            'Discord': [
                r'discord\.gg/[^/\s"\']+',
                r'discord\.com/invite/[^/\s"\']+',
            ]
        }

    def get_country_info(self, phone_number: phonenumbers.PhoneNumber) -> Tuple[str, str, str]:
        country_code = "Unknown"
        region = "Unknown"
        timezone = "Unknown"

        try:
            if not phonenumbers.is_valid_number(phone_number):
                return country_code, region, timezone

            cc = phonenumbers.region_code_for_number(phone_number)
            if cc:
                country_code = cc
                country = pycountry.countries.get(alpha_2=cc)
                if country:
                    region = country.name

            # time_zones_for_number yerine timezoneları kendin bulmak istersen:
            # (Bu örnekte numaradan enlem-boylam çıkarma olmadığı için
            # tam konuma göre timezone bulmak zordur, pratikte sabit bir mantık gerekli.)
            tf = TimezoneFinder()
            # Burada telefon numarasından konum almak
            # normalde libphonenumber ile doğrudan mümkün değil.
            # Sadece ülke koduna dayanarak tahmin edebilirsin, ya da harici bir mantık kurarsın.
            # (Örnek olarak 'Turkey' -> 'Europe/Istanbul' vb. sabit bir eşleştirme gibi.)

        except Exception as e:
            self.logger.error(f"Error getting country info: {str(e)}")

        return country_code, region, timezone

    def analyze_phone_number(self, phone_str: str) -> PhoneInfo:
        """
        Senin daha önceki analyze_phone_number fonksiyonuna benzer bir yapı.
        phonenumbers ile parse edip PhoneInfo döndürüyor.
        """
        try:
            # None: Sadece uluslararası format kabul ediyoruz (+ başlıyorsa parse eder)
            # region parametresi yok --> eğer numara '+...' içermezse genelde Invalid sayılacak
            parsed = phonenumbers.parse(phone_str, None)

            # check validity
            if not (phonenumbers.is_possible_number(parsed) and phonenumbers.is_valid_number(parsed)):
                raise ValueError("Invalid phone number")

            # Ülke kodu
            country_code = phonenumbers.region_code_for_number(parsed) or "Unknown"

            # Pycountry üzerinden tam ülke ismi
            import pycountry
            region = "Unknown"
            country = pycountry.countries.get(alpha_2=country_code)
            if country:
                region = country.name

            # Zaman dilimi
            # Yeni phonenumbers sürümünde time_zones_for_number mevcuttur
            # Yoksa fallback yapabilirsin
            try:
                timezones = phonenumbers.time_zones_for_number(parsed)
                timezone_str = ", ".join(timezones) if timezones else "Unknown"
            except:
                timezone_str = "Unknown"

            # Operatör
            from phonenumbers import carrier, PhoneNumberType
            carrier_name = "Unknown"
            for lang in ['en', 'local']:
                try:
                    temp = carrier.name_for_number(parsed, lang)
                    if temp:
                        carrier_name = temp
                        break
                except:
                    continue

            # Numara Tipi
            number_type_map = {
                phonenumbers.PhoneNumberType.MOBILE: "Mobile",
                phonenumbers.PhoneNumberType.FIXED_LINE: "Fixed Line",
                phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed Line or Mobile",
                phonenumbers.PhoneNumberType.TOLL_FREE: "Toll Free",
                phonenumbers.PhoneNumberType.PREMIUM_RATE: "Premium Rate",
                phonenumbers.PhoneNumberType.SHARED_COST: "Shared Cost",
                phonenumbers.PhoneNumberType.VOIP: "VoIP",
                phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "Personal",
                phonenumbers.PhoneNumberType.PAGER: "Pager",
                phonenumbers.PhoneNumberType.UAN: "UAN",
                phonenumbers.PhoneNumberType.UNKNOWN: "Unknown"
            }
            p_type = phonenumbers.number_type(parsed)
            final_type = number_type_map.get(p_type, "Unknown")

            return PhoneInfo(
                number=phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
                country_code=country_code,
                country_name=region,
                carrier=carrier_name,
                type=final_type,
                valid=True,
                region=region,  # Yukarıdaki region ile aynı
                timezone=timezone_str
            )

        except Exception as e:
            # self.logger.debug(...) ile hata detayını yazmak istersen
            self.logger.debug(f"analyze_phone_number -> invalid: {phone_str}, Error: {e}")
            return PhoneInfo(
                number=phone_str,
                country_code="Unknown",
                country_name="Unknown",
                carrier="Unknown",
                type="Unknown",
                valid=False,
                region="Unknown",
                timezone="Unknown"
            )

    def analyze_phone_number_with_fallback(self, phone_str: str, fallback_regions: List[str] = None) -> PhoneInfo:
        """
        + ile başlamayan numaraları, fallback bölgeler yardımıyla da denemek istersek bu fonksiyonu kullanabiliriz.
        """
        # 1) İlk deneme: uluslararası format
        info = self.analyze_phone_number(phone_str)
        if info.valid:
            return info

        # 2) Geçerli bulunmazsa fallback denemeleri
        fallback_regions = fallback_regions or ["US", "TR", "GB", "DE", "FR"]
        for region_code in fallback_regions:
            try:
                parsed = phonenumbers.parse(phone_str, region_code)
                if phonenumbers.is_possible_number(parsed) and phonenumbers.is_valid_number(parsed):
                    return self.analyze_phone_number(phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164))
            except:
                continue

        # Hepsi başarısızsa
        return PhoneInfo(
            number=phone_str,
            country_code="Unknown",
            country_name="Unknown",
            carrier="Unknown",
            type="Unknown",
            valid=False,
            region="Unknown",
            timezone="Unknown"
        )

    def extract_phones_from_text(self, text: str) -> Set[PhoneInfo]:
        """
        Gelişmiş phone scraping: 
        1) Regex ile potansiyel telefon parçalarını yakala
        2) Temizle ve uzunluk kontrolü yap
        3) analyze_phone_number_with_fallback() ile doğrula
        4) Set halinde döndür
        """
        phones_found = set()

        # Örnek regex: 7 ila 20 karakter, + destekli, parantez, tire, boşluk olabilir
        # (E.164 max 15 hane, ama bazen local + ext. vs. 20'ye çıkarmak isteyen olabilir.)
        pattern = r'\+?[\d\s\-\(\)\[\]]{7,20}'
        for match in re.finditer(pattern, text):
            raw_phone = match.group()
            # Rakam ve + işaretini koruyalım
            cleaned = re.sub(r'[^\d+]', '', raw_phone)
            # Çok kısa veya çok uzunları eliyoruz
            if not (7 <= len(cleaned) <= 15):
                continue

            # analyze_phone_number_with_fallback ile kontrol
            phone_info = self.analyze_phone_number_with_fallback(cleaned)
            if phone_info.valid:
                phones_found.add(phone_info)

        return phones_found

    def _build_phone_info(self, parsed_number: phonenumbers.PhoneNumber) -> PhoneInfo:
        """Parsed phone number için PhoneInfo nesnesi oluşturur."""
        country_code, region, tz = self.get_country_info(parsed_number)

        carrier_name = "Unknown"
        for lang in ['en', 'local']:
            try:
                name = carrier.name_for_number(parsed_number, lang)
                if name:
                    carrier_name = name
                    break
            except:
                continue

        number_type = phonenumbers.number_type(parsed_number)
        number_type_map = {
            phonenumbers.PhoneNumberType.MOBILE: "Mobile",
            phonenumbers.PhoneNumberType.FIXED_LINE: "Fixed Line",
            phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed Line or Mobile",
            phonenumbers.PhoneNumberType.TOLL_FREE: "Toll Free",
            phonenumbers.PhoneNumberType.PREMIUM_RATE: "Premium Rate",
            phonenumbers.PhoneNumberType.SHARED_COST: "Shared Cost",
            phonenumbers.PhoneNumberType.VOIP: "VoIP",
            phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "Personal",
            phonenumbers.PhoneNumberType.PAGER: "Pager",
            phonenumbers.PhoneNumberType.UAN: "UAN",
            phonenumbers.PhoneNumberType.UNKNOWN: "Unknown"
        }

        return PhoneInfo(
            number=phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            country_code=country_code,
            country_name=region,
            carrier=carrier_name,
            type=number_type_map.get(number_type, "Unknown"),
            valid=True,
            region=region,
            timezone=tz
        )

    def detect_language(self, text: str) -> str:
        """Metnin dilini tespit et (güncellenmiş sürüm)."""
        text = text.strip()
        # Metin çok kısaysa "unknown"
        if len(text) < 2:
            return "unknown"

        try:
            return detect(text)
        except LangDetectException:
            return "unknown"
        except Exception as e:
            self.logger.error(f"Language detection error: {str(e)}")
            return "unknown"

    def scrape_page(self, url: str) -> ScrapedInfo:
        """Sayfayı scrape et ve tekrar eden verileri engelle."""
        try:
            parsed_url = urlparse(url)
            if parsed_url.path.endswith('/index') or parsed_url.path.endswith('/index.html'):
                self.logger.info(f"Skipping index page: {url}")
                return None
            # 1) Görsel veya asset dosyalarını doğrudan atla
            if 'assets/images' in url or url.endswith(('jpg', 'jpeg', 'png', 'gif', 'svg', 'bmp', 'webp')):
                self.logger.info(f"Skipping image or asset URL: {url}")
                return None

            # 2) İstek gönder
            response = self.session.get(
                url,
                timeout=10,
                verify=False,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': '*',
                }
            )

            # 3) 404 veya farklı hataları yönet
            if response.status_code == 404:
                self.logger.error(f"Page not found: {url}")
                return None
            response.raise_for_status()

            # 4) Content-Type kontrolü (yalnızca HTML işliyoruz)
            content_type = response.headers.get('Content-Type', '').lower()
            if 'text/html' not in content_type:
                self.logger.info(f"Skipping non-HTML content: {url} ({content_type})")
                return None

            # 5) HTML parse
            soup = BeautifulSoup(response.text, 'html.parser')
            for invisible in soup(['style', 'script', 'head', 'title', 'meta', '[document]']):
                invisible.decompose()

            # 6) Metin ve linkler
            text = soup.get_text(separator=' ', strip=True)
            links = [a.get('href', '') for a in soup.find_all('a')]
            full_content = text + ' ' + ' '.join(links)

            # 7) E-posta desenleri
            email_obfuscation_patterns = [
                r'mailto:([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})',
                r'[\w.\-]+[\s]*[\[at\]|\(at\)|\[@\]|@][\s]*[\w.\-]+[\s]*[\[dot\]|\(dot\)|\[.\]|\.][A-Za-z]{2,}',
                r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}',
            ]
            emails = set()
            for pattern in email_obfuscation_patterns:
                found = re.findall(pattern, full_content, flags=re.IGNORECASE)
                # Bazı regex’lerde gruplama olabilir; gerekirse düzleştirilir
                if found and isinstance(found[0], tuple):
                    for f in found:
                        emails.add(f[0])
                else:
                    emails.update(found)

            # 8) Obfuscation temizliği
            cleaned_emails = {
                e.lower().strip()
                .replace('mailto:', '')
                .replace('[at]', '@').replace('(at)', '@').replace('[@]', '@')
                .replace('[dot]', '.').replace('(dot)', '.').replace('[.]', '.')
                for e in emails
            }

            # 9) Geçersiz e-postaları ayıkla
            filtered_emails = {
                e for e in cleaned_emails
                if 'protected' not in e and 'email address' not in e
                and ' ' not in e and '.' in e and '@' in e
            }
            
            # Telefon işlemleri
            phones = set()
            phone_patterns = [
                r'\+?[\d\s\-.()\[\]]{10,}',
                r'\b\d{3}[\s.-]?\d{3}[\s.-]?\d{4}\b',
                r'\+?\d{1,4}[\s.-]?\(?\d{1,4}\)?[\s.-]?\d{1,4}[\s.-]?\d{1,4}'
            ]

            for pattern in phone_patterns:
                matches = re.finditer(pattern, text)
                for match in matches:
                    phone = match.group()
                    cleaned_phone = re.sub(r'[^\d+]', '', phone)
                    if len(cleaned_phone) >= 10:
                        try:
                            phone_info = self.analyze_phone_number(cleaned_phone)
                            if phone_info.valid:
                                phones.add(phone_info)
                        except:
                            continue

            # Sosyal medya scraping
            social_media = []
            language = self.detect_language(text)

            # Global seen_profiles, tüm sayfalarda aynı profil tekrarı engellensin
            if not hasattr(self, 'seen_profiles'):
                self.seen_profiles = set()

            for platform, patterns in self.social_media_patterns.items():
                for pattern in patterns:
                    matches = re.finditer(pattern, full_content, re.IGNORECASE)
                    
                    for match in matches:
                        url_match = match.group(0)
                        
                        # URL'yi normalize et
                        if not url_match.startswith(('http://', 'https://')):
                            url_match = 'https://' + url_match
                        
                        try:
                            parsed_url = urlparse(url_match)
                            
                            # Username çıkarma mantığını geliştir
                            path_parts = parsed_url.path.strip('/').split('/')
                            username = None
                            
                            # Platform özel username çıkarma
                            if platform == 'Facebook':
                                if 'profile.php' in parsed_url.path:
                                    query_params = urllib.parse.parse_qs(parsed_url.query)
                                    username = query_params.get('id', [None])[0]
                                else:
                                    username = path_parts[0]
                            elif platform in ['Twitter/X', 'Instagram', 'LinkedIn']:
                                username = path_parts[-1] if path_parts else None
                            else:
                                username = path_parts[0] if path_parts else None

                            if username and username not in ['', 'in', 'company', 'user']:
                                # Profil benzersiz kimliğini oluştur
                                profile_id = f"{platform}:{username}".lower()

                                # Eğer bu profil daha önce eklenmemişse
                                if profile_id not in self.seen_profiles:
                                    self.seen_profiles.add(profile_id)
                                    social_media.append(SocialMediaProfile(
                                        platform=platform,
                                        url=url_match,
                                        username=username,
                                        found_on=url,
                                        language=language
                                    ))
                        
                        except Exception as e:
                            self.logger.error(f"Social media parsing error for {url_match}: {str(e)}")
                            continue

            return ScrapedInfo(
                emails=filtered_emails,
                phones=list(phones),
                social_media=social_media,
                source_url=url,
                language=language,
                region=self.get_page_region(soup)
            )
        except Exception as e:
            self.logger.error(f"Error scraping {url}: {str(e)}")
            return ScrapedInfo(
                emails=set(),
                phones=[],
                social_media=[],
                source_url=url,
                language="unknown",
                region="unknown"
            )

    def _group_social_media(self, profiles: List[SocialMediaProfile]) -> Dict:
            """Sosyal medya profillerini platformlara göre grupla"""
            grouped = {}
            for profile in profiles:
                if profile.platform not in grouped:
                    grouped[profile.platform] = []
                grouped[profile.platform].append(asdict(profile))
            return grouped

    def get_page_region(self, soup: BeautifulSoup) -> str:
        """Sayfanın hedef bölgesini tespit et (Geolocation API'si kullanılmaz)."""
        try:
            # 1) Olası meta etiketlerini sırayla kontrol edelim.
            #    'geo.region', 'geo.position', 'geo.placename' gibi eklemeler yapıyoruz.
            meta_names = ['geo.region', 'geo.position', 'geo.placename']
            for name in meta_names:
                meta_tag = soup.find('meta', attrs={'name': name})
                if meta_tag and meta_tag.has_attr('content'):
                    content_val = meta_tag['content'].strip()
                    if content_val:
                        # Eğer 'US-CA' gibi bir format varsa, burada parse edebilirsin.
                        return content_val
            
            # 2) <html lang="en-US" veya "en_US" vs. fallback
            html_tag = soup.find('html')
            if html_tag:
                html_lang = html_tag.get('lang', '').strip()
                if html_lang:
                    # Tire veya alt çizgi ile ayrılmış ülke kodlarını yakalama
                    import re
                    # Ör: "en-US" -> "US", "en_US" -> "US"
                    parts = re.split(r'[-_]', html_lang)
                    if len(parts) > 1:
                        return parts[-1].upper()
            
            # Yukarıdaki hiçbir etiket veya lang bulunamadıysa
            return "unknown"
        except Exception as e:
            self.logger.error(f"Error in get_page_region: {str(e)}")
            return "unknown"

    def normalize_url(
        self,
        url: str,
        base_url: str,
        max_path_segments: int = 1,
        allow_subdomains: bool = False,
        skip_file_extensions=None
        ) -> str:
        """
        Normalize the given URL based on the following rules:
        - Build an absolute URL from 'base_url'.
        - Only allow links that are under the same domain (or subdomains, if 'allow_subdomains' is True).
        - Limit the number of path segments to 'max_path_segments'.
        - Skip certain file extensions (e.g., .pdf, .docx, .jpg, etc.).
        - Skip possible homepage variants (/, index, home, homepage, default, main, etc.).
        - Return a normalized URL if it meets all criteria; otherwise, return an empty string.
        """

        # 1) If no URL is provided, return an empty string
        if not url:
            return ""

        # 2) Define default file extensions to skip if none provided
        if skip_file_extensions is None:
            skip_file_extensions = {'.pdf', '.doc', '.docx', '.xlsx', '.zip', '.jpg', '.png', '.gif'}

        # 3) Remove anything after '#' (fragment) and strip whitespace
        url = url.split('#')[0].strip()

        # 4) Build an absolute URL using 'base_url'
        abs_url = urljoin(base_url, url)
        if not abs_url:
            return ""

        # 5) Parse the base and the absolute URL for comparison
        parsed_base = urlparse(base_url)
        parsed_url = urlparse(abs_url)

        base_domain = parsed_base.netloc.lower()
        target_domain = parsed_url.netloc.lower()

        # 6) Check domain or subdomain acceptance
        if allow_subdomains:
            # If subdomains are allowed, the target domain should end with the base domain
            if not target_domain.endswith(base_domain):
                return ""
        else:
            # If subdomains are not allowed, the domain must match exactly
            if base_domain != target_domain:
                return ""

        # 7) Check the path segment limit
        path_segments = [seg for seg in parsed_url.path.split('/') if seg]
        if len(path_segments) > max_path_segments:
            return ""

        # 8) Check for file extensions to skip
        _, ext = os.path.splitext(parsed_url.path.lower())
        if ext in skip_file_extensions:
            return ""

        # 9) Skip possible homepage paths: "/", "/index", "/home", "/homepage", etc.
        homepage_keywords = {"", "index", "home", "homepage", "default", "main"}
        # Extract the last path segment in lowercase (without extension)
        last_segment = path_segments[-1].lower() if path_segments else ""
        filename_no_ext, _ = os.path.splitext(last_segment)

        # If the path is empty or the last segment matches any homepage keyword, skip
        if filename_no_ext in homepage_keywords:
            return ""

        # 10) Remove trailing slash if it's not just the root "/"
        scheme = parsed_url.scheme.lower()
        netloc = target_domain
        path = parsed_url.path
        if path.endswith('/') and path != '/':
            path = path.rstrip('/')

        # 11) Keep the query parameters (you may clear or filter them if needed)
        query = parsed_url.query

        # 12) Rebuild and return the final normalized URL
        final_url = urlunparse((scheme, netloc, path, '', query, ''))
        return final_url

    def is_valid_url(self, url: str) -> bool:
        """
        Checks whether the URL is valid and excludes unwanted pages or file types.
        """
        try:
            parsed = urlparse(url)

            # 1) Scheme and netloc must be present (e.g. 'http://example.com')
            if not (parsed.scheme and parsed.netloc):
                return False

            # 2) Only allow http or https (exclude mailto:, ftp:, javascript:, etc.)
            if parsed.scheme.lower() not in ["http", "https"]:
                return False

            # 3) File extensions to exclude (add any you want)
            #    e.g. images, office docs, archives, media files, etc.
            file_ext_pattern = r'\.(?:jpg|jpeg|png|gif|bmp|pdf|zip|rar|mp3|mp4|svg|doc|docx|xlsx)$'
            if re.search(file_ext_pattern, parsed.path.lower()):
                return False

            # 4) Exclude certain directories (assets, images, videos, etc.)
            blocked_dirs = ["assets", "images", "videos", "downloads"]
            if any(dir_name in parsed.path.lower() for dir_name in blocked_dirs):
                return False

            # 5) Exclude typical homepage references (if desired):
            #    '/index', '/home', '/homepage', '/', etc.
            #    We'll compare the path's last segment, ignoring extensions like .html
            #    If you don't need this, remove or adjust.
            homepage_keywords = {"index", "home", "homepage", "default", "main"}
            path_lower = parsed.path.lower().rstrip('/')
            if path_lower in ["", "/"]:
                # This is the root page (like 'https://example.com/')
                return False
            # Remove extension if it exists
            if '.' in path_lower.split('/')[-1]:
                last_segment_name = re.split(r'\.', path_lower.split('/')[-1])[0]
            else:
                last_segment_name = path_lower.split('/')[-1]
            if last_segment_name in homepage_keywords:
                return False

            # 6) If URL specifically ends with '/#' (fragment only) or '/index'
            #    you can also exclude them here:
            if url.endswith('/#') or url.endswith('/index'):
                return False

            return True

        except Exception as e:
            self.logger.error(f"Error validating URL {url}: {str(e)}")
            return False

    def export_results(self, results: Dict, output_format: str = 'json', filename: str = None, export_dir: str = None) -> None:
        """
        Export the scraping results to the desired format (JSON or CSV).
        
        :param results: Dictionary containing the scraping or scanning results.
                        Expected format:
                        {
                            "page_results": [
                                {
                                    "url": "http://example.com/page1",
                                    "emails": [...],
                                    "phones": [...],
                                    "social_media": [...]
                                },
                                ...
                            ],
                            ...
                        }
        :param output_format: 'json' or 'csv' (extendable to 'yaml', etc.)
        :param filename: Custom file name (without extension). If None, auto-generate.
        :param export_dir: Directory to place exported files. If None, current directory is used.
        """
        try:
            # 1) Prepare default filename if not provided
            if filename is None:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"scan_results_{self.domain}_{timestamp}"

            # 2) Create export directory: if export_dir is not provided,
            # use "logs/<domain>" folder under the current directory.
            if export_dir:
                os.makedirs(export_dir, exist_ok=True)
            else:
                export_dir = os.path.join(os.getcwd(), "logs", self.domain)
                os.makedirs(export_dir, exist_ok=True)

            # 3) Export as JSON
            if output_format.lower() == 'json':
                output_path = os.path.join(export_dir, f"{filename}.json")
                try:
                    with open(output_path, 'w', encoding='utf-8') as f:
                        json.dump(results, f, ensure_ascii=False, indent=2, default=str)
                    self.logger.info(f"Results exported to JSON: {output_path}")
                except Exception as e:
                    self.logger.error(f"Failed to write JSON file: {e}")

            # 5) Export as CSV
            elif output_format.lower() == 'csv':
                try:
                    # Emails CSV
                    emails_path = os.path.join(export_dir, f"{filename}_emails.csv")
                    with open(emails_path, 'w', newline='', encoding='utf-8') as f:
                        writer = csv.writer(f, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                        writer.writerow(['Email', 'Source URL'])
                        for page in page_results:
                            emails = page.get('emails', [])
                            for email in emails:
                                writer.writerow([email, page.get('url', '')])
                    self.logger.info(f"Emails CSV exported: {emails_path}")

                    # Phones CSV
                    phones_path = os.path.join(export_dir, f"{filename}_phones.csv")
                    with open(phones_path, 'w', newline='', encoding='utf-8') as f:
                        writer = csv.writer(f, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                        writer.writerow(['Number', 'Country', 'Carrier', 'Type', 'Valid', 'Region', 'Timezone', 'Source URL'])
                        for page in page_results:
                            phones = page.get('phones', [])
                            for phone in phones:
                                # Make sure these keys exist; otherwise use ''
                                writer.writerow([
                                    phone.get('number', ''),
                                    phone.get('country_name', ''),
                                    phone.get('carrier', ''),
                                    phone.get('type', ''),
                                    phone.get('valid', ''),
                                    phone.get('region', ''),
                                    phone.get('timezone', ''),
                                    page.get('url', '')
                                ])
                    self.logger.info(f"Phones CSV exported: {phones_path}")

                    # Social Media CSV
                    social_path = os.path.join(export_dir, f"{filename}_social_media.csv")
                    with open(social_path, 'w', newline='', encoding='utf-8') as f:
                        writer = csv.writer(f, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                        writer.writerow(['Platform', 'URL', 'Username', 'Found On', 'Language'])
                        for page in page_results:
                            social_list = page.get('social_media', [])
                            for profile in social_list:
                                writer.writerow([
                                    profile.get('platform', ''),
                                    profile.get('url', ''),
                                    profile.get('username', ''),
                                    profile.get('found_on', ''),
                                    profile.get('language', '')
                                ])
                    self.logger.info(f"Social media CSV exported: {social_path}")

                except Exception as e:
                    self.logger.error(f"Failed to write CSV files: {e}")

            else:
                # 6) Unsupported format
                self.logger.error(f"Unsupported output format: {output_format}")

        except Exception as e:
            self.logger.error(f"Error exporting results: {e}")
 
    def crawl(self) -> Dict:
        """Domain'i crawl et ve bilgileri topla"""
        start_url = f"https://{self.domain}"
        urls_to_visit = {start_url}  # Başlangıç URL'si
        self.visited_urls = set()  # Ziyaret edilen URL'ler
        self.found_info = []  # Bulunan bilgiler


        with ThreadPoolExecutor(max_workers=5) as executor:
            while urls_to_visit and len(self.visited_urls) < self.max_pages:
                current_url = urls_to_visit.pop()
                if current_url in self.visited_urls:
                    continue

                self.visited_urls.add(current_url)
                self.logger.info(f"Scraping: {current_url}")

                try:
                    # Sayfayı scrape et
                    scraped_info = executor.submit(self.scrape_page, current_url).result()
                    if scraped_info:  # Eğer None döndürülmemişse (geçersiz sayfa değilse)
                        self.found_info.append(scraped_info)

                    # Yeni linkleri bul
                    response = self.session.get(current_url, timeout=10, verify=False)
                    soup = BeautifulSoup(response.text, 'html.parser')
                    links = soup.find_all('a', href=True)

                    for link in links:
                        url = self.normalize_url(link['href'], current_url)
                        if url and url not in self.visited_urls:
                            urls_to_visit.add(url)

                except Exception as e:
                    self.logger.error(f"Error processing {current_url}: {str(e)}")
                    continue

                time.sleep(1)  # Rate limiting

        with ThreadPoolExecutor(max_workers=5) as executor:
            while urls_to_visit and len(self.visited_urls) < self.max_pages:
                current_url = urls_to_visit.pop()
                if current_url in self.visited_urls:  # Ziyaret edilen URL'leri kontrol et
                    continue

                if not self.is_valid_url(current_url):
                    self.logger.info(f"Skipping invalid URL: {current_url}")
                    continue

                self.visited_urls.add(current_url)
                self.logger.info(f"Scraping: {current_url}")

                try:
                    # Sayfayı scrape et
                    scraped_info = executor.submit(self.scrape_page, current_url).result()
                    
                    # Eğer veri varsa ekle
                    if scraped_info.emails or scraped_info.phones or scraped_info.social_media:
                        self.found_info.append(scraped_info)

                    # Yeni linkleri bul
                    response = self.session.get(current_url, timeout=10, verify=False)
                    if response.status_code == 404:
                        continue  # 404 sayfasını atla

                    soup = BeautifulSoup(response.text, 'html.parser')
                    links = soup.find_all('a', href=True)

                    for link in links:
                        url = self.normalize_url(link['href'], current_url)
                        if url and url not in self.visited_urls:
                            urls_to_visit.add(url)

                except Exception as e:
                    self.logger.error(f"Error processing {current_url}: {str(e)}")
                    continue

                time.sleep(1)  # Rate limiting

        # Sonuçları düzenle
        all_emails = set()
        all_phones = []
        all_social_media = []
        page_results = []

        for info in self.found_info:
            all_emails.update(info.emails)
            all_phones.extend(info.phones)
            all_social_media.extend(info.social_media)

            page_results.append({
                "url": info.source_url,
                "emails": list(info.emails),
                "phones": info.phones,
                "social_media": info.social_media
            })

        results = {
            "domain": self.domain,
            "scan_date": datetime.now().isoformat(),
            "pages_scanned": len(self.visited_urls),
            "summary": {
                "total_emails": len(all_emails),
                "total_phones": len(all_phones),
                "total_social_media": len(all_social_media),
                "unique_emails": list(all_emails),
                "unique_phones": list(set(all_phones)),
                "social_media_by_platform": self._group_social_media(all_social_media)
            },
        }

        return results

def main(domain: str, max_pages: int = 100, output_format: str = 'json') -> dict:
    """
    Main function to run the GlobalDomainScraper.
    
    :param domain: Domain to scan (e.g., 'example.com')
    :param max_pages: Maximum number of pages to crawl
    :param output_format: 'json' or 'csv'
    :return: Results dictionary containing the scan summary and details
    """
    # Instantiate the scraper with the given domain and page limit
    scraper = GlobalDomainScraper(domain, max_pages)
    print(f"Scanning domain: {domain}")

    # Perform the crawl
    results = scraper.crawl()

    # Print a summary to console
    print("\nScan Summary:")
    print(f"Pages scanned: {results.get('pages_scanned', 0)}")
    summary = results.get('summary', {})
    print(f"Total emails found: {summary.get('total_emails', 0)}")
    print(f"Total phone numbers found: {summary.get('total_phones', 0)}")
    print(f"Total social media profiles found: {summary.get('total_social_media', 0)}")

    # Export results in the chosen format
    scraper.export_results(results, output_format)

    return results

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Global Domain Scanner')
    parser.add_argument('domain', help='Domain to scan (e.g., example.com)')
    parser.add_argument('--max-pages', type=int, default=100, help='Maximum number of pages to scan')
    parser.add_argument('--output-format', choices=['json', 'csv'], default='json', help='Output format')
    args = parser.parse_args()

    main(args.domain, args.max_pages, args.output_format)
