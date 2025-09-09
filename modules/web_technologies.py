# modules/web_technologies.py - Enhanced web technologies detection with security focus
import requests
import re
import json
import ssl
import socket
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Optional
import warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

def detect_web_technologies(domain: str) -> Dict:
    """
    Enhanced detection of backend, frontend, CDN, and other web technologies with security focus.
    
    Args:
        domain (str): Target domain
        
    Returns:
        Dict: Comprehensive technology and security analysis
    """
    try:
        # URL formatını düzenle
        if not domain.startswith(('http://', 'https://')):
            url = f"https://{domain}"
        else:
            url = domain
            
        # Özel headers - bot tespitini engellemek için
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        
        response = requests.get(url, headers=headers, timeout=30, allow_redirects=True, verify=False)
        response.raise_for_status()
        
        html_content = response.text
        response_headers = response.headers
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Temel teknoloji analizi
        basic_analysis = {
            "Web Server": detect_web_server(response_headers),
            "Backend Technologies": detect_backend_technologies(html_content, response_headers, soup),
            "Frontend Technologies": detect_frontend_technologies(html_content, soup),
            "JavaScript Libraries": detect_js_libraries(html_content, soup),
            "CSS Frameworks": detect_css_frameworks(html_content, soup),
            "Content Management System": detect_cms(html_content, response_headers, soup),
            "E-commerce Platform": detect_ecommerce(html_content, soup),
            "CDN & Cloud Services": detect_cdn_services(response_headers, html_content),
            "Analytics & Tracking": detect_analytics(html_content, soup),
        }
        
        # Güvenlik odaklı analizler
        security_analysis = {
            "Security Headers": analyze_security_headers(response_headers),
            "Security Vulnerabilities": detect_security_vulnerabilities(html_content, response_headers, soup),
            "Information Disclosure": detect_information_disclosure(html_content, response_headers),
            "SSL/TLS Security": analyze_ssl_security(domain),
            "Security Services": detect_security_services(response_headers, html_content),
            "Cookie Security": analyze_cookie_security(response_headers),
        }
        
        # WordPress özel analizi
        wordpress_analysis = {}
        if is_wordpress_site(html_content, response_headers, soup):
            wordpress_analysis = {
                "WordPress Analysis": enhanced_wordpress_analysis(domain, html_content, response_headers, soup)
            }
        
        # Teknoloji güvenlik değerlendirmesi
        tech_security = {
            "Technology Security Analysis": analyze_technology_security({**basic_analysis, **wordpress_analysis}),
            "Security Score": calculate_security_score({**basic_analysis, **security_analysis, **wordpress_analysis})
        }
        
        # Tüm analizleri birleştir
        complete_analysis = {**basic_analysis, **security_analysis, **wordpress_analysis, **tech_security}
        
        return complete_analysis
        
    except requests.exceptions.RequestException as e:
        return {"Error": f"Could not analyze target: {str(e)}"}
    except Exception as e:
        return {"Error": f"Analysis failed: {str(e)}"}

def detect_web_server(headers: Dict) -> str:
    """Gelişmiş web sunucusu tespiti"""
    server = headers.get('Server', '').lower()
    powered_by = headers.get('X-Powered-By', '').lower()
    
    servers = {
        'nginx': 'Nginx',
        'apache': 'Apache HTTP Server',
        'iis': 'Microsoft Internet Information Services',
        'cloudflare': 'Cloudflare',
        'litespeed': 'LiteSpeed Web Server',
        'caddy': 'Caddy Web Server',
        'traefik': 'Traefik Proxy',
        'envoy': 'Envoy Proxy',
        'gunicorn': 'Gunicorn WSGI',
        'uwsgi': 'uWSGI',
    }
    
    for key, name in servers.items():
        if key in server or key in powered_by:
            version_match = re.search(r'[\d\.]+', server)
            version = f" {version_match.group()}" if version_match else ""
            return f"{name}{version}"
    
    return server.split('/')[0].title() if server else "Not Detected"

def detect_backend_technologies(html: str, headers: Dict, soup: BeautifulSoup) -> List[str]:
    """Gelişmiş backend teknoloji tespiti"""
    technologies = []
    html_lower = html.lower()
    powered_by = headers.get('X-Powered-By', '').lower()
    
    # Framework tespit kalıpları
    patterns = {
        'PHP': [
            lambda: 'php' in powered_by,
            lambda: re.search(r'\.php(\?|"|\s|$)', html_lower),
            lambda: 'phpsessid' in html_lower,
            lambda: 'set-cookie' in str(headers).lower() and 'phpsessid' in str(headers).lower(),
        ],
        'ASP.NET': [
            lambda: 'asp.net' in powered_by,
            lambda: '__viewstate' in html_lower,
            lambda: 'aspxauth' in html_lower,
            lambda: soup.find('form', {'id': 'aspnetForm'}),
            lambda: soup.find('input', {'name': '__VIEWSTATE'}),
        ],
        'Node.js': [
            lambda: 'express' in headers.get('X-Powered-By', ''),
            lambda: 'node' in headers.get('Server', '').lower(),
            lambda: 'koa' in headers.get('X-Powered-By', ''),
        ],
        'Python Django': [
            lambda: 'django' in html_lower,
            lambda: 'csrfmiddlewaretoken' in html_lower,
            lambda: soup.find('input', {'name': 'csrfmiddlewaretoken'}),
        ],
        'Python Flask': [
            lambda: 'flask' in html_lower,
            lambda: 'werkzeug' in headers.get('Server', '').lower(),
        ],
        'Ruby on Rails': [
            lambda: 'ruby' in powered_by,
            lambda: 'rails' in html_lower,
            lambda: soup.find('meta', {'name': 'csrf-token'}),
            lambda: 'authenticity_token' in html_lower,
        ],
        'Java': [
            lambda: 'servlet' in html_lower,
            lambda: 'jsessionid' in html_lower,
            lambda: 'struts' in html_lower,
            lambda: 'spring' in html_lower,
            lambda: '.jsp' in html_lower,
        ],
        'Go': [
            lambda: 'golang' in html_lower,
            lambda: 'gin-gonic' in html_lower,
            lambda: 'go' in headers.get('Server', '').lower(),
        ],
    }
    
    for tech, checks in patterns.items():
        if any(check() for check in checks if callable(check)):
            technologies.append(tech)
    
    return technologies if technologies else ["Not Detected"]

def detect_frontend_technologies(html: str, soup: BeautifulSoup) -> List[str]:
    """Frontend framework tespiti"""
    technologies = []
    html_lower = html.lower()
    
    scripts = soup.find_all('script', src=True)
    script_content = ' '.join([tag.get('src', '') for tag in scripts]).lower()
    
    patterns = {
        'React': [
            lambda: 'react' in script_content,
            lambda: soup.find('div', {'id': 'react-root'}),
            lambda: 'data-reactroot' in html_lower,
            lambda: '__react' in html_lower,
        ],
        'Vue.js': [
            lambda: 'vue' in script_content,
            lambda: 'v-app' in html_lower,
            lambda: soup.find(attrs={'v-cloak': True}),
            lambda: re.search(r'v-[a-z]+', html_lower),
        ],
        'Angular': [
            lambda: 'angular' in script_content,
            lambda: 'ng-app' in html_lower,
            lambda: soup.find(attrs={'ng-app': True}),
            lambda: 'ng-version' in html_lower,
        ],
        'Svelte': [
            lambda: 'svelte' in script_content,
            lambda: '_svelte' in html_lower,
        ],
        'Ember.js': [
            lambda: 'ember' in script_content,
            lambda: 'ember-application' in html_lower,
        ],
        'Alpine.js': [
            lambda: 'alpine' in script_content,
            lambda: 'x-data' in html_lower,
        ],
        'jQuery': [
            lambda: 'jquery' in script_content,
            lambda: re.search(r'\$\(.*\)', html_lower),
        ],
    }
    
    for tech, checks in patterns.items():
        if any(check() for check in checks if callable(check)):
            technologies.append(tech)
    
    return technologies if technologies else ["Not Detected"]

def detect_js_libraries(html: str, soup: BeautifulSoup) -> List[str]:
    """JavaScript kütüphane tespiti"""
    libraries = []
    scripts = soup.find_all('script', src=True)
    script_content = ' '.join([tag.get('src', '') for tag in scripts]).lower()
    inline_js = ' '.join([tag.string or '' for tag in soup.find_all('script') if not tag.get('src')]).lower()
    
    js_libs = {
        'jQuery': ['jquery', '$'],
        'Lodash': ['lodash', 'underscore'],
        'Moment.js': ['moment.js', 'moment.min.js'],
        'D3.js': ['d3.js', 'd3.min.js'],
        'Chart.js': ['chart.js', 'chart.min.js'],
        'Three.js': ['three.js', 'three.min.js'],
        'GSAP': ['gsap', 'tweenmax'],
        'Axios': ['axios'],
        'Swiper': ['swiper'],
        'Bootstrap JS': ['bootstrap.js', 'bootstrap.min.js'],
        'Popper.js': ['popper.js'],
        'Font Awesome': ['fontawesome', 'font-awesome'],
    }
    
    for lib, patterns in js_libs.items():
        if any(pattern in script_content or pattern in inline_js for pattern in patterns):
            libraries.append(lib)
    
    return libraries if libraries else ["Not Detected"]

def detect_css_frameworks(html: str, soup: BeautifulSoup) -> List[str]:
    """CSS framework tespiti"""
    frameworks = []
    
    links = soup.find_all('link', {'rel': 'stylesheet'})
    css_content = ' '.join([tag.get('href', '') for tag in links]).lower()
    
    html_classes = ' '.join([' '.join(tag.get('class', [])) for tag in soup.find_all() if tag.get('class')])
    
    css_frameworks = {
        'Bootstrap': ['bootstrap', 'btn-', 'container-', 'row', 'col-'],
        'Tailwind CSS': ['tailwind', 'bg-', 'text-', 'p-', 'm-', 'w-', 'h-'],
        'Bulma': ['bulma', 'is-', 'has-'],
        'Foundation': ['foundation', 'grid-'],
        'Semantic UI': ['semantic-ui', 'ui '],
        'Materialize': ['materialize'],
        'UIKit': ['uikit'],
        'Pure CSS': ['pure-css', 'pure-'],
    }
    
    for framework, patterns in css_frameworks.items():
        if any(pattern in css_content or pattern in html_classes for pattern in patterns):
            frameworks.append(framework)
    
    return frameworks if frameworks else ["Not Detected"]

def detect_cms(html: str, headers: Dict, soup: BeautifulSoup) -> List[str]:
    """CMS tespiti"""
    cms_list = []
    html_lower = html.lower()
    
    cms_patterns = {
        'WordPress': ['wp-content', 'wp-includes', 'wp-admin', 'wordpress'],
        'Drupal': ['drupal', 'sites/all', 'sites/default', 'drupal.js'],
        'Joomla': ['joomla', 'option=com_', 'joomla.org'],
        'Magento': ['magento', 'mage/cookies.js', 'skin/frontend'],
        'Shopify': ['shopify', 'shopifycdn', 'shopify.com'],
        'Wix': ['wix.com', 'wixstatic', 'wix-code'],
        'Squarespace': ['squarespace', 'sqsp', 'squarespace.com'],
        'Ghost': ['ghost', 'casper', 'ghost.org'],
        'Webflow': ['webflow', 'webflow.com'],
        'TYPO3': ['typo3', 'typo3conf'],
        'Concrete5': ['concrete5', 'c5'],
    }
    
    for cms, patterns in cms_patterns.items():
        if any(pattern in html_lower for pattern in patterns):
            cms_list.append(cms)
    
    return cms_list if cms_list else ["Not Detected"]

def detect_ecommerce(html: str, soup: BeautifulSoup) -> List[str]:
    """E-ticaret platform tespiti"""
    platforms = []
    html_lower = html.lower()
    
    ecommerce_patterns = {
        'Shopify': ['shopify', 'shopifycdn'],
        'WooCommerce': ['woocommerce', 'wc-'],
        'Magento': ['magento', 'mage'],
        'PrestaShop': ['prestashop'],
        'BigCommerce': ['bigcommerce'],
        'OpenCart': ['opencart'],
        'Stripe': ['stripe'],
        'PayPal': ['paypal'],
        'Square': ['squareup'],
    }
    
    for platform, patterns in ecommerce_patterns.items():
        if any(pattern in html_lower for pattern in patterns):
            platforms.append(platform)
    
    return platforms if platforms else ["Not Detected"]

def detect_cdn_services(headers: Dict, html: str) -> List[str]:
    """CDN servis tespiti"""
    cdns = []
    html_lower = html.lower()
    
    server = headers.get('Server', '').lower()
    via = headers.get('Via', '').lower()
    cf_ray = headers.get('CF-Ray', '')
    
    cdn_patterns = {
        'Cloudflare': [
            lambda: 'cloudflare' in server,
            lambda: cf_ray,
            lambda: 'cloudflare' in html_lower,
        ],
        'AWS CloudFront': [
            lambda: 'cloudfront' in server,
            lambda: 'cloudfront' in via,
            lambda: headers.get('X-Amz-Cf-Id'),
        ],
        'Fastly': [
            lambda: 'fastly' in server,
            lambda: 'fastly' in via,
        ],
        'KeyCDN': [
            lambda: 'keycdn' in server,
        ],
        'MaxCDN': [
            lambda: 'maxcdn' in html_lower,
        ],
        'Akamai': [
            lambda: 'akamai' in server,
            lambda: headers.get('X-Akamai-Transformed'),
        ],
    }
    
    for cdn, checks in cdn_patterns.items():
        if any(check() for check in checks if callable(check)):
            cdns.append(cdn)
    
    return cdns if cdns else ["Not Detected"]

def detect_analytics(html: str, soup: BeautifulSoup) -> List[str]:
    """Analitik servis tespiti"""
    analytics = []
    html_lower = html.lower()
    
    scripts = soup.find_all('script', src=True)
    script_content = ' '.join([tag.get('src', '') for tag in scripts]).lower()
    
    analytics_patterns = {
        'Google Analytics': ['google-analytics', 'googletagmanager', 'gtag'],
        'Google Tag Manager': ['googletagmanager'],
        'Facebook Pixel': ['facebook.net/tr', 'fbevents.js'],
        'Hotjar': ['hotjar'],
        'Mixpanel': ['mixpanel'],
        'Segment': ['segment.com', 'analytics.js'],
        'Adobe Analytics': ['adobe', 'omniture'],
        'Yandex Metrica': ['yandex', 'metrica'],
    }
    
    for service, patterns in analytics_patterns.items():
        if any(pattern in script_content or pattern in html_lower for pattern in patterns):
            analytics.append(service)
    
    return analytics if analytics else ["Not Detected"]

def analyze_security_headers(headers: Dict) -> Dict:
    """Güvenlik başlıkları analizi"""
    security_headers = {
        'Content-Security-Policy': {
            'present': bool(headers.get('Content-Security-Policy')),
            'value': headers.get('Content-Security-Policy', 'Not Set'),
            'security_level': 'High' if headers.get('Content-Security-Policy') else 'Low'
        },
        'Strict-Transport-Security': {
            'present': bool(headers.get('Strict-Transport-Security')),
            'value': headers.get('Strict-Transport-Security', 'Not Set'),
            'security_level': 'High' if headers.get('Strict-Transport-Security') else 'Low'
        },
        'X-Frame-Options': {
            'present': bool(headers.get('X-Frame-Options')),
            'value': headers.get('X-Frame-Options', 'Not Set'),
            'security_level': 'Medium' if headers.get('X-Frame-Options') else 'Low'
        },
        'X-Content-Type-Options': {
            'present': bool(headers.get('X-Content-Type-Options')),
            'value': headers.get('X-Content-Type-Options', 'Not Set'),
            'security_level': 'Medium' if headers.get('X-Content-Type-Options') else 'Low'
        },
        'X-XSS-Protection': {
            'present': bool(headers.get('X-XSS-Protection')),
            'value': headers.get('X-XSS-Protection', 'Not Set'),
            'security_level': 'Medium' if headers.get('X-XSS-Protection') else 'Low'
        },
        'Referrer-Policy': {
            'present': bool(headers.get('Referrer-Policy')),
            'value': headers.get('Referrer-Policy', 'Not Set'),
            'security_level': 'Medium' if headers.get('Referrer-Policy') else 'Low'
        }
    }
    
    return security_headers

def detect_security_vulnerabilities(html: str, headers: Dict, soup: BeautifulSoup) -> Dict:
    """Güvenlik açığı tespiti"""
    vulnerabilities = {
        "missing_security_headers": [],
        "insecure_practices": [],
        "exposed_information": [],
        "potential_vulnerabilities": []
    }
    
    # Eksik güvenlik başlıkları
    required_headers = {
        'Content-Security-Policy': 'CSP Header Missing - XSS Risk',
        'X-Frame-Options': 'Clickjacking Protection Missing',
        'X-Content-Type-Options': 'MIME Sniffing Protection Missing',
        'Strict-Transport-Security': 'HSTS Missing - MITM Risk',
        'X-XSS-Protection': 'XSS Protection Header Missing'
    }
    
    for header, risk in required_headers.items():
        if not headers.get(header):
            vulnerabilities["missing_security_headers"].append(risk)
    
    # Güvensiz uygulamalar
    html_lower = html.lower()
    if 'http://' in html_lower and 'https://' in html_lower:
        vulnerabilities["insecure_practices"].append("Mixed Content - HTTP resources on HTTPS page")
    
    if soup.find('input', {'type': 'password'}) and not headers.get('Strict-Transport-Security'):
        vulnerabilities["insecure_practices"].append("Password field without HSTS")
    
    # Açığa çıkan bilgiler
    debug_patterns = [
        (r'debug.*true', "Debug mode enabled"),
        (r'error.*trace', "Error traces exposed"),
        (r'stack.*trace', "Stack traces visible"),
        (r'sql.*error', "SQL errors exposed"),
        (r'exception.*details', "Exception details visible")
    ]
    
    for pattern, description in debug_patterns:
        if re.search(pattern, html_lower):
            vulnerabilities["exposed_information"].append(description)
    
    return vulnerabilities

def detect_information_disclosure(html: str, headers: Dict) -> Dict:
    """Bilgi sızıntısı tespiti"""
    disclosures = {
        "server_info": [],
        "technology_disclosure": [],
        "file_exposure": [],
        "debug_information": []
    }
    
    # Server bilgi sızıntısı
    server_header = headers.get('Server', '')
    if re.search(r'/([\d\.]+)', server_header):
        disclosures["server_info"].append(f"Server version exposed: {server_header}")
    
    powered_by = headers.get('X-Powered-By', '')
    if powered_by:
        disclosures["technology_disclosure"].append(f"Technology stack exposed: {powered_by}")
    
    # Dosya yolları
    html_lower = html.lower()
    file_patterns = [
        (r'c:\\[^\s<>"]+', "Windows file paths exposed"),
        (r'/var/www/[^\s<>"]+', "Linux file paths exposed"),
        (r'/home/[^\s<>"]+', "User directories exposed"),
        (r'\.env', "Environment files referenced")
    ]
    
    for pattern, description in file_patterns:
        if re.search(pattern, html_lower):
            disclosures["file_exposure"].append(description)
    
    return disclosures

def analyze_ssl_security(domain: str) -> Dict:
    """SSL/TLS güvenlik analizi"""
    try:
        hostname = urlparse(f"https://{domain}").netloc or domain
        
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                
                return {
                    "ssl_version": ssock.version(),
                    "cipher_suite": cipher[0] if cipher else "Unknown",
                    "cipher_strength": analyze_cipher_security(cipher[0] if cipher else ""),
                    "certificate_issuer": dict(x[0] for x in cert.get('issuer', [])),
                    "certificate_subject": dict(x[0] for x in cert.get('subject', [])),
                    "certificate_expires": cert.get('notAfter', 'Unknown'),
                    "security_assessment": get_ssl_security_level(ssock.version(), cipher[0] if cipher else "")
                }
    except Exception as e:
        return {"error": f"SSL analysis failed: {str(e)}"}

def analyze_cipher_security(cipher: str) -> str:
    """Cipher güvenlik analizi"""
    if not cipher:
        return "Unknown"
    
    cipher_upper = cipher.upper()
    weak_indicators = ['RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT']
    
    if any(weak in cipher_upper for weak in weak_indicators):
        return "Weak"
    elif 'AES' in cipher_upper and ('256' in cipher_upper or 'GCM' in cipher_upper):
        return "Strong"
    else:
        return "Medium"

def get_ssl_security_level(version: str, cipher: str) -> str:
    """SSL güvenlik seviyesi"""
    if not version:
        return "Unknown"
    
    if version in ['TLSv1.3']:
        return "Excellent"
    elif version in ['TLSv1.2'] and analyze_cipher_security(cipher) == "Strong":
        return "Good"
    elif version in ['TLSv1.2']:
        return "Acceptable"
    elif version in ['TLSv1.1', 'TLSv1']:
        return "Weak"
    else:
        return "Poor"

def detect_security_services(headers: Dict, html: str) -> Dict:
    """Güvenlik servisleri tespiti"""
    security_services = {
        "waf": [],
        "ddos_protection": [],
        "bot_protection": [],
        "security_vendor": []
    }
    
    headers_str = str(headers).lower()
    html_lower = html.lower()
    
    # WAF tespiti
    waf_indicators = {
        'Cloudflare': ['cf-ray', 'cloudflare'],
        'AWS WAF': ['x-amzn-requestid', 'awselb'],
        'Incapsula': ['incap_ses', 'incapsula'],
        'Akamai': ['akamai'],
        'Sucuri': ['sucuri'],
        'ModSecurity': ['mod_security'],
        'F5 BIG-IP': ['bigip', 'f5'],
        'Barracuda': ['barracuda'],
    }
    
    for waf, indicators in waf_indicators.items():
        if any(indicator in headers_str or indicator in html_lower for indicator in indicators):
            security_services["waf"].append(waf)
    
    return security_services

def analyze_cookie_security(headers: Dict) -> Dict:
    """Cookie güvenlik analizi"""
    cookies = headers.get('Set-Cookie', '')
    if not cookies:
        return {"status": "No cookies detected"}
    
    cookie_analysis = {
        "secure_flag": "Secure" in cookies,
        "httponly_flag": "HttpOnly" in cookies,
        "samesite_attribute": "SameSite" in cookies,
        "security_score": 0,
        "recommendations": []
    }
    
    # Güvenlik skoru hesapla
    if cookie_analysis["secure_flag"]:
        cookie_analysis["security_score"] += 40
    else:
        cookie_analysis["recommendations"].append("Add Secure flag to cookies")
    
    if cookie_analysis["httponly_flag"]:
        cookie_analysis["security_score"] += 30
    else:
        cookie_analysis["recommendations"].append("Add HttpOnly flag to prevent XSS")
    
    if cookie_analysis["samesite_attribute"]:
        cookie_analysis["security_score"] += 30
    else:
        cookie_analysis["recommendations"].append("Add SameSite attribute for CSRF protection")
    
    cookie_analysis["security_level"] = get_security_level(cookie_analysis["security_score"])
    
    return cookie_analysis

def get_security_level(score: int) -> str:
    """Güvenlik seviyesi"""
    if score >= 90:
        return "Excellent"
    elif score >= 70:
        return "Good"
    elif score >= 50:
        return "Fair"
    else:
        return "Poor"

# WordPress Özel Analiz Fonksiyonları

def is_wordpress_site(html: str, headers: Dict, soup: BeautifulSoup) -> bool:
    """WordPress site kontrolü"""
    html_lower = html.lower()
    indicators = [
        'wp-content/' in html_lower,
        'wp-includes/' in html_lower,
        'wp-admin/' in html_lower,
        'wp-json/' in html_lower,
        soup.find('meta', {'name': 'generator', 'content': re.compile(r'wordpress', re.I)}),
        'xmlrpc.php' in html_lower
    ]
    
    return sum(bool(indicator) for indicator in indicators) >= 2

def enhanced_wordpress_analysis(domain: str, html: str, headers: Dict, soup: BeautifulSoup) -> Dict:
    """Detaylı WordPress analizi"""
    base_url = f"https://{domain}" if not domain.startswith(('http://', 'https://')) else domain
    
    wp_analysis = {
        "detection_confidence": calculate_wp_confidence(html, headers, soup),
        "version_info": detect_wordpress_version(base_url, html, soup),
        "theme_info": detect_wordpress_theme(base_url, html, soup),
        "plugins": detect_wordpress_plugins(base_url, html, soup),
        "users": enumerate_wordpress_users(base_url),
        "api_endpoints": check_wordpress_api(base_url),
        "security_issues": check_wordpress_security(base_url, html, headers),
        "file_disclosures": check_wordpress_files(base_url),
        "admin_access": check_wordpress_admin(base_url),
        "xmlrpc_status": check_xmlrpc(base_url),
        "directory_listing": check_wp_directories(base_url),
        "wp_config_exposure": check_wp_config(base_url),
        "debug_info": check_wp_debug(html)
    }
    
    return wp_analysis

def calculate_wp_confidence(html: str, headers: Dict, soup: BeautifulSoup) -> Dict:
    """WordPress tespit güven skoru"""
    confidence = 0
    methods = []
    html_lower = html.lower()
    
    # Güçlü göstergeler (30 puan)
    strong_indicators = [
        ('wp-content/' in html_lower, "wp-content directory found"),
        ('wp-includes/' in html_lower, "wp-includes directory found"),
        ('wp-admin/' in html_lower, "wp-admin directory found"),
        (soup.find('meta', {'name': 'generator', 'content': re.compile(r'wordpress', re.I)}), "WordPress generator meta tag"),
        ('wp-json/' in html_lower, "WordPress REST API endpoint found")
    ]
    
    for condition, method in strong_indicators:
        if condition:
            confidence += 30
            methods.append(method)
    
    # Orta göstergeler (15 puan)
    medium_indicators = [
        ('xmlrpc.php' in html_lower, "XML-RPC endpoint found"),
        ('wp-login.php' in html_lower, "WordPress login page found"),
        ('wp-cron.php' in html_lower, "WordPress cron found")
    ]
    
    for condition, method in medium_indicators:
        if condition:
            confidence += 15
            methods.append(method)
    
    return {
        "score": min(100, confidence),
        "methods": methods,
        "certainty": "High" if confidence >= 60 else "Medium" if confidence >= 30 else "Low"
    }

def detect_wordpress_version(base_url: str, html: str, soup: BeautifulSoup) -> Dict:
    """WordPress versiyon tespiti"""
    version_info = {
        "version": "Unknown",
        "detection_methods": [],
        "vulnerability_status": "Unknown",
        "latest_version": "6.4.2",  # 2024 latest
        "update_required": False
    }
    
    try:
        # Generator meta tag kontrolü
        generator = soup.find('meta', {'name': 'generator'})
        if generator and 'wordpress' in generator.get('content', '').lower():
            version_match = re.search(r'wordpress\s+([\d\.]+)', generator.get('content', ''), re.I)
            if version_match:
                version_info["version"] = version_match.group(1)
                version_info["detection_methods"].append("Generator meta tag")
        
        # readme.html kontrolü
        try:
            readme_url = f"{base_url}/readme.html"
            response = requests.get(readme_url, timeout=10, verify=False)
            if response.status_code == 200:
                readme_match = re.search(r'version\s+([\d\.]+)', response.text, re.I)
                if readme_match:
                    version_info["version"] = readme_match.group(1)
                    version_info["detection_methods"].append("readme.html file")
        except:
            pass
        
        # RSS feed kontrolü
        try:
            rss_url = f"{base_url}/feed/"
            response = requests.get(rss_url, timeout=10, verify=False)
            if response.status_code == 200:
                rss_match = re.search(r'generator.*wordpress\s+([\d\.]+)', response.text, re.I)
                if rss_match:
                    if version_info["version"] == "Unknown":
                        version_info["version"] = rss_match.group(1)
                        version_info["detection_methods"].append("RSS feed")
        except:
            pass
        
        # Versiyon güvenlik durumu
        if version_info["version"] != "Unknown":
            version_info["update_required"] = is_wordpress_outdated(version_info["version"])
            version_info["vulnerability_status"] = check_wordpress_vulnerabilities(version_info["version"])
        
    except Exception as e:
        version_info["error"] = str(e)
    
    return version_info

def detect_wordpress_theme(base_url: str, html: str, soup: BeautifulSoup) -> Dict:
    """WordPress tema tespiti"""
    theme_info = {
        "theme_name": "Unknown",
        "theme_version": "Unknown",
        "detection_methods": [],
        "theme_path": None,
        "vulnerabilities": []
    }
    
    try:
        # CSS dosyalarından tema tespiti
        links = soup.find_all('link', {'rel': 'stylesheet'})
        for link in links:
            href = link.get('href', '')
            if 'wp-content/themes/' in href:
                theme_match = re.search(r'/wp-content/themes/([^/]+)', href)
                if theme_match:
                    theme_info["theme_name"] = theme_match.group(1)
                    theme_info["theme_path"] = f"/wp-content/themes/{theme_match.group(1)}"
                    theme_info["detection_methods"].append("CSS stylesheet path")
                    break
        
        # style.css'den versiyon bilgisi
        if theme_info["theme_name"] != "Unknown":
            try:
                style_url = f"{base_url}/wp-content/themes/{theme_info['theme_name']}/style.css"
                response = requests.get(style_url, timeout=10, verify=False)
                if response.status_code == 200:
                    version_match = re.search(r'Version:\s*([\d\.]+)', response.text)
                    if version_match:
                        theme_info["theme_version"] = version_match.group(1)
                        theme_info["detection_methods"].append("style.css header")
            except:
                pass
        
    except Exception as e:
        theme_info["error"] = str(e)
    
    return theme_info

def detect_wordpress_plugins(base_url: str, html: str, soup: BeautifulSoup) -> Dict:
    """WordPress plugin tespiti"""
    plugins_info = {
        "detected_plugins": [],
        "plugin_count": 0,
        "detection_methods": [],
        "vulnerable_plugins": []
    }
    
    try:
        html_lower = html.lower()
        
        # Script ve CSS dosyalarından plugin tespiti
        scripts = soup.find_all('script', src=True)
        links = soup.find_all('link', rel='stylesheet')
        
        all_resources = []
        for script in scripts:
            all_resources.append(script.get('src', ''))
        for link in links:
            all_resources.append(link.get('href', ''))
        
        plugins = set()
        for resource in all_resources:
            if 'wp-content/plugins/' in resource:
                plugin_match = re.search(r'/wp-content/plugins/([^/]+)', resource)
                if plugin_match:
                    plugins.add(plugin_match.group(1))
        
        # Bilinen plugin imzaları
        known_plugins = {
            'yoast': 'Yoast SEO',
            'akismet': 'Akismet Anti-Spam',
            'jetpack': 'Jetpack',
            'woocommerce': 'WooCommerce',
            'contact-form-7': 'Contact Form 7',
            'elementor': 'Elementor',
            'wordfence': 'Wordfence Security',
            'wp-super-cache': 'WP Super Cache',
            'all-in-one-seo': 'All in One SEO',
            'google-analytics': 'Google Analytics'
        }
        
        for plugin_slug in plugins:
            plugin_name = known_plugins.get(plugin_slug, plugin_slug.replace('-', ' ').title())
            plugins_info["detected_plugins"].append({
                "name": plugin_name,
                "slug": plugin_slug,
                "path": f"/wp-content/plugins/{plugin_slug}/"
            })
        
        # HTML içerikten plugin tespiti
        for plugin_key, plugin_name in known_plugins.items():
            if plugin_key in html_lower:
                if not any(p['slug'] == plugin_key for p in plugins_info["detected_plugins"]):
                    plugins_info["detected_plugins"].append({
                        "name": plugin_name,
                        "slug": plugin_key,
                        "detection_method": "HTML content analysis"
                    })
        
        plugins_info["plugin_count"] = len(plugins_info["detected_plugins"])
        
    except Exception as e:
        plugins_info["error"] = str(e)
    
    return plugins_info

def enumerate_wordpress_users(base_url: str) -> Dict:
    """WordPress kullanıcı numaralandırma"""
    users_info = {
        "users_found": [],
        "enumeration_methods": [],
        "total_users": 0,
        "security_risk": "Unknown"
    }
    
    try:
        # wp-json API kullanıcı numaralandırma
        api_url = f"{base_url}/wp-json/wp/v2/users"
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        
        try:
            response = requests.get(api_url, headers=headers, timeout=10, verify=False)
            if response.status_code == 200:
                users_data = response.json()
                for user in users_data:
                    users_info["users_found"].append({
                        "id": user.get("id"),
                        "username": user.get("slug"),
                        "display_name": user.get("name"),
                        "url": user.get("url", ""),
                        "description": user.get("description", "")
                    })
                users_info["enumeration_methods"].append("REST API (/wp-json/wp/v2/users)")
                users_info["security_risk"] = "High - User enumeration possible via REST API"
        except:
            pass
        
        # Author sitemap kontrolü
        try:
            sitemap_url = f"{base_url}/wp-sitemap-users-1.xml"
            response = requests.get(sitemap_url, headers=headers, timeout=10, verify=False)
            if response.status_code == 200:
                users_info["enumeration_methods"].append("User sitemap (/wp-sitemap-users-1.xml)")
        except:
            pass
        
        # Author sayfa numaralandırma
        try:
            for i in range(1, 6):  # İlk 5 kullanıcıyı kontrol et
                author_url = f"{base_url}/?author={i}"
                response = requests.get(author_url, headers=headers, timeout=10, verify=False, allow_redirects=False)
                if response.status_code in [200, 301, 302]:
                    # Redirect ederse kullanıcı adını çıkar
                    if 'Location' in response.headers:
                        location = response.headers['Location']
                        username_match = re.search(r'/author/([^/]+)', location)
                        if username_match:
                            username = username_match.group(1)
                            if not any(u.get('username') == username for u in users_info["users_found"]):
                                users_info["users_found"].append({
                                    "id": i,
                                    "username": username,
                                    "method": "Author enumeration"
                                })
            
            if len(users_info["users_found"]) > 0:
                users_info["enumeration_methods"].append("Author page enumeration")
        except:
            pass
        
        users_info["total_users"] = len(users_info["users_found"])
        
        if users_info["total_users"] > 0 and users_info["security_risk"] == "Unknown":
            users_info["security_risk"] = "Medium - User enumeration possible"
        
    except Exception as e:
        users_info["error"] = str(e)
    
    return users_info

def check_wordpress_api(base_url: str) -> Dict:
    """WordPress API endpoint kontrolü"""
    api_info = {
        "rest_api_enabled": False,
        "xmlrpc_enabled": False,
        "api_endpoints": [],
        "security_issues": []
    }
    
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        
        # REST API kontrolü
        rest_endpoints = [
            "/wp-json/",
            "/wp-json/wp/v2/",
            "/wp-json/wp/v2/users",
            "/wp-json/wp/v2/posts",
            "/wp-json/wp/v2/pages"
        ]
        
        for endpoint in rest_endpoints:
            try:
                url = f"{base_url}{endpoint}"
                response = requests.get(url, headers=headers, timeout=10, verify=False)
                if response.status_code == 200:
                    api_info["rest_api_enabled"] = True
                    api_info["api_endpoints"].append({
                        "endpoint": endpoint,
                        "status": "accessible",
                        "response_size": len(response.content)
                    })
            except:
                pass
        
        # XML-RPC kontrolü
        try:
            xmlrpc_url = f"{base_url}/xmlrpc.php"
            response = requests.get(xmlrpc_url, headers=headers, timeout=10, verify=False)
            if response.status_code == 200 and 'XML-RPC server accepts POST requests only' in response.text:
                api_info["xmlrpc_enabled"] = True
                api_info["security_issues"].append("XML-RPC enabled - Potential brute force risk")
        except:
            pass
        
        # API güvenlik değerlendirmesi
        if api_info["rest_api_enabled"]:
            api_info["security_issues"].append("REST API enabled - Check user enumeration")
        
    except Exception as e:
        api_info["error"] = str(e)
    
    return api_info

def check_wordpress_security(base_url: str, html: str, headers: Dict) -> Dict:
    """WordPress güvenlik kontrolü"""
    security_issues = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": [],
        "security_score": 100
    }
    
    try:
        # Debug bilgileri kontrolü
        if 'wp_debug' in html.lower() or 'debug' in html.lower():
            security_issues["high"].append("Debug information potentially exposed")
            security_issues["security_score"] -= 20
        
        # Directory listing kontrolü
        directories = ['/wp-content/', '/wp-content/uploads/', '/wp-content/themes/', '/wp-content/plugins/']
        for directory in directories:
            try:
                url = f"{base_url}{directory}"
                response = requests.get(url, timeout=10, verify=False)
                if response.status_code == 200 and 'Index of' in response.text:
                    security_issues["medium"].append(f"Directory listing enabled: {directory}")
                    security_issues["security_score"] -= 10
            except:
                pass
        
        # Güvenlik başlıkları
        if not headers.get('X-Frame-Options'):
            security_issues["medium"].append("X-Frame-Options header missing")
            security_issues["security_score"] -= 5
        
        if not headers.get('Content-Security-Policy'):
            security_issues["medium"].append("Content Security Policy missing")
            security_issues["security_score"] -= 10
        
        # WordPress versiyon sızıntısı
        if re.search(r'wordpress\s+[\d\.]+', html, re.I):
            security_issues["low"].append("WordPress version disclosed")
            security_issues["security_score"] -= 5
        
    except Exception as e:
        security_issues["error"] = str(e)
    
    return security_issues

def check_wordpress_files(base_url: str) -> Dict:
    """WordPress dosya sızıntısı kontrolü"""
    file_disclosures = {
        "exposed_files": [],
        "sensitive_files": [],
        "backup_files": []
    }
    
    # Kontrol edilecek dosyalar
    sensitive_files = [
        'wp-config.php',
        'wp-config.php.bak',
        'wp-config.bak',
        'wp-config.txt',
        'readme.html',
        'license.txt',
        'wp-admin/install.php',
        '.htaccess',
        'wp-config.php~',
        'wp-config.php.save',
        'wp-config.php.swp'
    ]
    
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        
        for file in sensitive_files:
            try:
                url = f"{base_url}/{file}"
                response = requests.get(url, headers=headers, timeout=10, verify=False)
                
                if response.status_code == 200:
                    if 'wp-config' in file:
                        file_disclosures["sensitive_files"].append({
                            "file": file,
                            "status": "accessible",
                            "risk": "Critical - Database credentials exposed"
                        })
                    elif '.bak' in file or '~' in file or '.save' in file:
                        file_disclosures["backup_files"].append({
                            "file": file,
                            "status": "accessible",
                            "risk": "High - Backup file exposed"
                        })
                    else:
                        file_disclosures["exposed_files"].append({
                            "file": file,
                            "status": "accessible",
                            "size": len(response.content)
                        })
            except:
                pass
                
    except Exception as e:
        file_disclosures["error"] = str(e)
    
    return file_disclosures

def check_wordpress_admin(base_url: str) -> Dict:
    """WordPress admin paneli kontrolü"""
    admin_info = {
        "admin_accessible": False,
        "login_page_accessible": False,
        "admin_url": f"{base_url}/wp-admin/",
        "login_url": f"{base_url}/wp-login.php",
        "security_measures": []
    }
    
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        
        # wp-admin kontrolü
        admin_response = requests.get(admin_info["admin_url"], headers=headers, timeout=10, verify=False)
        if admin_response.status_code == 200:
            admin_info["admin_accessible"] = True
        elif admin_response.status_code == 302:
            admin_info["admin_accessible"] = True
            admin_info["security_measures"].append("Admin redirects to login")
        
        # wp-login.php kontrolü
        login_response = requests.get(admin_info["login_url"], headers=headers, timeout=10, verify=False)
        if login_response.status_code == 200:
            admin_info["login_page_accessible"] = True
            
            # Login sayfası analizi
            if 'captcha' in login_response.text.lower():
                admin_info["security_measures"].append("CAPTCHA protection detected")
            
            if 'two-factor' in login_response.text.lower() or '2fa' in login_response.text.lower():
                admin_info["security_measures"].append("Two-factor authentication detected")
                
    except Exception as e:
        admin_info["error"] = str(e)
    
    return admin_info

def check_xmlrpc(base_url: str) -> Dict:
    """XML-RPC kontrolü"""
    xmlrpc_info = {
        "enabled": False,
        "methods_available": [],
        "security_risk": "Low"
    }
    
    try:
        xmlrpc_url = f"{base_url}/xmlrpc.php"
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        
        # GET request
        response = requests.get(xmlrpc_url, headers=headers, timeout=10, verify=False)
        
        if response.status_code == 200:
            if 'XML-RPC server accepts POST requests only' in response.text:
                xmlrpc_info["enabled"] = True
                xmlrpc_info["security_risk"] = "High - XML-RPC enabled (brute force risk)"
                
    except Exception as e:
        xmlrpc_info["error"] = str(e)
    
    return xmlrpc_info

def check_wp_directories(base_url: str) -> Dict:
    """WordPress dizin listesi kontrolü"""
    directory_info = {
        "directory_listing_enabled": [],
        "protected_directories": [],
        "risk_level": "Low"
    }
    
    directories = [
        '/wp-content/',
        '/wp-content/uploads/',
        '/wp-content/themes/',
        '/wp-content/plugins/',
        '/wp-includes/',
        '/wp-admin/css/',
        '/wp-admin/js/'
    ]
    
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        
        for directory in directories:
            try:
                url = f"{base_url}{directory}"
                response = requests.get(url, headers=headers, timeout=10, verify=False)
                
                if response.status_code == 200 and 'Index of' in response.text:
                    directory_info["directory_listing_enabled"].append(directory)
                    directory_info["risk_level"] = "Medium"
                elif response.status_code == 403:
                    directory_info["protected_directories"].append(directory)
            except:
                pass
                
    except Exception as e:
        directory_info["error"] = str(e)
    
    return directory_info

def check_wp_config(base_url: str) -> Dict:
    """wp-config.php sızıntısı kontrolü"""
    config_info = {
        "wp_config_exposed": False,
        "backup_files_found": [],
        "risk_level": "Low"
    }
    
    config_files = [
        'wp-config.php',
        'wp-config.php.bak',
        'wp-config.bak',
        'wp-config.txt',
        'wp-config.php~',
        'wp-config.php.save',
        'wp-config.php.swp',
        'wp-config.old'
    ]
    
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        
        for config_file in config_files:
            try:
                url = f"{base_url}/{config_file}"
                response = requests.get(url, headers=headers, timeout=10, verify=False)
                
                if response.status_code == 200:
                    # İçerikte DB bilgileri var mı kontrol et
                    if 'DB_PASSWORD' in response.text or 'DB_USER' in response.text:
                        config_info["wp_config_exposed"] = True
                        config_info["backup_files_found"].append({
                            "file": config_file,
                            "size": len(response.content),
                            "contains_db_creds": True
                        })
                        config_info["risk_level"] = "Critical"
                    else:
                        config_info["backup_files_found"].append({
                            "file": config_file,
                            "size": len(response.content),
                            "contains_db_creds": False
                        })
            except:
                pass
                
    except Exception as e:
        config_info["error"] = str(e)
    
    return config_info

def check_wp_debug(html: str) -> Dict:
    """WordPress debug bilgileri kontrolü"""
    debug_info = {
        "debug_enabled": False,
        "debug_traces": [],
        "sql_queries_exposed": False,
        "error_messages": []
    }
    
    html_lower = html.lower()
    
    # Debug göstergeleri
    debug_patterns = [
        (r'wp_debug.*true', "WP_DEBUG enabled"),
        (r'wp_debug_log.*true', "WP_DEBUG_LOG enabled"),
        (r'wp_debug_display.*true', "WP_DEBUG_DISPLAY enabled"),
        (r'query.*time.*seconds', "SQL query timing exposed"),
        (r'fatal error.*wp-', "WordPress fatal errors"),
        (r'warning.*wp-', "WordPress warnings"),
        (r'notice.*wp-', "WordPress notices")
    ]
    
    for pattern, description in debug_patterns:
        if re.search(pattern, html_lower):
            debug_info["debug_enabled"] = True
            debug_info["debug_traces"].append(description)
    
    # SQL sorgu sızıntısı
    sql_patterns = [
        r'select.*from.*wp_',
        r'update.*wp_.*set',
        r'insert.*into.*wp_',
        r'delete.*from.*wp_'
    ]
    
    for pattern in sql_patterns:
        if re.search(pattern, html_lower):
            debug_info["sql_queries_exposed"] = True
            break
    
    return debug_info

def is_wordpress_outdated(version: str) -> bool:
    """WordPress versiyonunun güncel olup olmadığını kontrol et"""
    try:
        current_version = [int(x) for x in version.split('.')]
        latest_version = [6, 4, 2]  # 2024 latest version
        
        return current_version < latest_version
    except:
        return True

def check_wordpress_vulnerabilities(version: str) -> str:
    """WordPress versiyon güvenlik açığı kontrolü"""
    try:
        version_parts = [int(x) for x in version.split('.')]
        major, minor = version_parts[0], version_parts[1] if len(version_parts) > 1 else 0
        
        # Bilinen kritik güvenlik açıkları
        if major < 5:
            return "Critical - Very outdated version with known vulnerabilities"
        elif major == 5 and minor < 8:
            return "High - Outdated version with security issues"
        elif major == 6 and minor < 4:
            return "Medium - Update recommended for security patches"
        else:
            return "Good - Recent version"
    except:
        return "Unknown - Could not parse version"

def analyze_technology_security(technologies: Dict) -> Dict:
    """Teknoloji güvenlik analizi"""
    security_analysis = {
        "vulnerable_technologies": [],
        "outdated_components": [],
        "security_recommendations": [],
        "overall_risk": "Low"
    }
    
    # Bilinen güvenlik açığı olan teknolojiler
    vulnerable_techs = {
        'jQuery': {'versions': ['1.x', '2.x', '<3.5.0'], 'risk': 'XSS vulnerabilities'},
        'Apache': {'versions': ['<2.4.50'], 'risk': 'Remote code execution'},
        'nginx': {'versions': ['<1.20.0'], 'risk': 'Security bypass'},
        'PHP': {'versions': ['<7.4'], 'risk': 'Multiple vulnerabilities'}
    }
    
    risk_score = 0
    
    for category, tech_list in technologies.items():
        if isinstance(tech_list, list):
            for tech in tech_list:
                if any(vuln_tech in tech for vuln_tech in vulnerable_techs.keys()):
                    for vuln_tech, details in vulnerable_techs.items():
                        if vuln_tech in tech:
                            security_analysis["vulnerable_technologies"].append({
                                "technology": tech,
                                "category": category,
                                "risk": details['risk'],
                                "recommendation": f"Update {vuln_tech} to latest version"
                            })
                            risk_score += 20
    
    # WordPress özel kontrol
    if "WordPress Analysis" in technologies:
        wp_data = technologies["WordPress Analysis"]
        if wp_data.get("security_issues", {}).get("critical"):
            risk_score += 30
        if wp_data.get("security_issues", {}).get("high"):
            risk_score += 20
    
    # Risk seviyesi belirleme
    if risk_score >= 50:
        security_analysis["overall_risk"] = "Critical"
    elif risk_score >= 30:
        security_analysis["overall_risk"] = "High"
    elif risk_score >= 10:
        security_analysis["overall_risk"] = "Medium"
    
    return security_analysis

def calculate_security_score(analysis: Dict) -> Dict:
    """Genel güvenlik skoru hesaplama"""
    score = 100
    issues = []
    recommendations = []
    
    # Security Headers kontrolü
    security_headers = analysis.get("Security Headers", {})
    missing_headers = sum(1 for header_info in security_headers.values() 
                         if isinstance(header_info, dict) and not header_info.get('present', False))
    score -= missing_headers * 8
    
    if missing_headers > 0:
        issues.append(f"{missing_headers} critical security headers missing")
        recommendations.append("Implement missing security headers")
    
    # SSL/TLS kontrolü
    ssl_info = analysis.get("SSL/TLS Security", {})
    ssl_level = ssl_info.get("security_assessment", "Unknown")
    if ssl_level == "Poor":
        score -= 30
        issues.append("Poor SSL/TLS configuration")
    elif ssl_level == "Weak":
        score -= 20
        issues.append("Weak SSL/TLS configuration")
    
    # WordPress güvenlik skoru
    if "WordPress Analysis" in analysis:
        wp_security = analysis["WordPress Analysis"].get("security_issues", {})
        wp_score = wp_security.get("security_score", 100)
        score = min(score, wp_score)
        
        if wp_security.get("critical"):
            issues.extend(wp_security["critical"])
            recommendations.append("Fix critical WordPress security issues")
        
        if wp_security.get("high"):
            issues.extend(wp_security["high"])
    
    # Güvenlik servisleri bonus
    security_services = analysis.get("Security Services", {})
    if security_services.get("waf"):
        score += 5
        recommendations.append("WAF detected - Good security practice")
    
    # Cookie güvenlik
    cookie_security = analysis.get("Cookie Security", {})
    if isinstance(cookie_security, dict) and cookie_security.get("security_score", 0) < 70:
        score -= 10
        issues.append("Insecure cookie configuration")
        recommendations.append("Implement secure cookie flags")
    
    # Güvenlik açıkları
    vulnerabilities = analysis.get("Security Vulnerabilities", {})
    if vulnerabilities.get("missing_security_headers"):
        score -= len(vulnerabilities["missing_security_headers"]) * 5
    
    if vulnerabilities.get("insecure_practices"):
        score -= len(vulnerabilities["insecure_practices"]) * 10
        issues.extend(vulnerabilities["insecure_practices"])
    
    # Bilgi sızıntısı
    info_disclosure = analysis.get("Information Disclosure", {})
    total_disclosures = sum(len(disclosures) for disclosures in info_disclosure.values() 
                           if isinstance(disclosures, list))
    score -= total_disclosures * 5
    
    # Final score
    final_score = max(0, score)
    
    return {
        "overall_score": final_score,
        "security_grade": get_security_grade(final_score),
        "critical_issues": issues[:5],  # En kritik 5 sorun
        "recommendations": recommendations[:5],  # En önemli 5 öneri
        "risk_level": get_risk_level(final_score),
        "score_breakdown": {
            "security_headers": security_headers,
            "ssl_tls": ssl_level,
            "wordpress_security": wp_security.get("security_score", "N/A") if "WordPress Analysis" in analysis else "N/A",
            "information_disclosure": f"{total_disclosures} issues found",
            "overall_assessment": get_security_assessment(final_score)
        }
    }

def get_security_grade(score: int) -> str:
    """Güvenlik notu hesaplama"""
    if score >= 90:
        return "A+"
    elif score >= 85:
        return "A"
    elif score >= 80:
        return "A-"
    elif score >= 75:
        return "B+"
    elif score >= 70:
        return "B"
    elif score >= 65:
        return "B-"
    elif score >= 60:
        return "C+"
    elif score >= 55:
        return "C"
    elif score >= 50:
        return "C-"
    elif score >= 40:
        return "D"
    else:
        return "F"

def get_risk_level(score: int) -> str:
    """Risk seviyesi"""
    if score >= 80:
        return "Low Risk"
    elif score >= 60:
        return "Medium Risk"
    elif score >= 40:
        return "High Risk"
    else:
        return "Critical Risk"

def get_security_assessment(score: int) -> str:
    """Güvenlik değerlendirmesi"""
    if score >= 90:
        return "Excellent security posture"
    elif score >= 80:
        return "Good security with minor improvements needed"
    elif score >= 70:
        return "Acceptable security with several improvements needed"
    elif score >= 60:
        return "Below average security, immediate attention required"
    elif score >= 40:
        return "Poor security posture, significant vulnerabilities present"
    else:
        return "Critical security issues, immediate remediation required"

# Yardımcı fonksiyonlar

def safe_request(url: str, headers: Dict = None, timeout: int = 10) -> Optional[requests.Response]:
    """Güvenli HTTP isteği"""
    try:
        default_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        if headers:
            default_headers.update(headers)
            
        response = requests.get(url, headers=default_headers, timeout=timeout, verify=False, allow_redirects=True)
        return response if response.status_code < 500 else None
    except:
        return None

def extract_domain(url: str) -> str:
    """URL'den domain çıkarma"""
    try:
        parsed = urlparse(url if url.startswith(('http://', 'https://')) else f"https://{url}")
        return parsed.netloc or parsed.path.split('/')[0]
    except:
        return url

def format_results(results: Dict) -> str:
    """Sonuçları formatlama"""
    output = []
    output.append("=" * 80)
    output.append("ENHANCED SECURITY WEB TECHNOLOGY ANALYSIS")
    output.append("=" * 80)
    
    # Genel bilgiler
    if "Web Server" in results:
        output.append(f"\n🖥️  Web Server: {results['Web Server']}")
    
    if "Backend Technologies" in results:
        backend = results['Backend Technologies']
        if backend != ["Not Detected"]:
            output.append(f"⚙️  Backend: {', '.join(backend)}")
    
    # Güvenlik skoru
    if "Security Score" in results:
        score_info = results["Security Score"]
        output.append(f"\n🛡️  SECURITY ASSESSMENT")
        output.append(f"   Overall Score: {score_info['overall_score']}/100")
        output.append(f"   Security Grade: {score_info['security_grade']}")
        output.append(f"   Risk Level: {score_info['risk_level']}")
        
        if score_info.get('critical_issues'):
            output.append(f"\n❌ Critical Issues:")
            for issue in score_info['critical_issues']:
                output.append(f"   • {issue}")
    
    # WordPress analizi
    if "WordPress Analysis" in results:
        wp_data = results["WordPress Analysis"]
        output.append(f"\n🔍 WORDPRESS ANALYSIS")
        
        if "version_info" in wp_data:
            version = wp_data["version_info"]
            output.append(f"   Version: {version.get('version', 'Unknown')}")
            if version.get('update_required'):
                output.append(f"   ⚠️  Update Required: {version.get('vulnerability_status', '')}")
        
        if "users" in wp_data and wp_data["users"].get("users_found"):
            users = wp_data["users"]
            output.append(f"   👥 Users Found: {users['total_users']}")
            for user in users["users_found"][:3]:  # İlk 3 kullanıcı
                output.append(f"      • {user.get('username', 'N/A')} (ID: {user.get('id', 'N/A')})")
    
    # Güvenlik başlıkları
    if "Security Headers" in results:
        headers = results["Security Headers"]
        missing = [name for name, info in headers.items() 
                  if isinstance(info, dict) and not info.get('present', False)]
        if missing:
            output.append(f"\n🚨 Missing Security Headers:")
            for header in missing[:5]:
                output.append(f"   • {header}")
    
    return "\n".join(output)

# Note: main.py has its own safe_web_technologies wrapper function
# This module only provides the core detect_web_technologies function

# Main function for standalone usage
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python web_technologies.py <domain>")
        print("Example: python web_technologies.py example.com")
        sys.exit(1)
    
    domain = sys.argv[1]
    print(f"Analyzing {domain}...")
    
    try:
        results = detect_web_technologies(domain)
        
        if "Error" in results:
            print(f"❌ Error: {results['Error']}")
        else:
            print(format_results(results))
            
            # JSON çıktısı da kaydet
            with open(f"{extract_domain(domain)}_security_analysis.json", 'w') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            print(f"\n📄 Detailed results saved to {extract_domain(domain)}_security_analysis.json")
            
    except KeyboardInterrupt:
        print("\n⏹️  Analysis interrupted by user")
    except Exception as e:
        print(f"❌ Unexpected error: {str(e)}")

"""
KULLANIM ÖRNEKLERİ:

1. main.py'den kullanım (önerilen):
   from modules.web_technologies import detect_web_technologies
   results = detect_web_technologies("example.com")

2. Terminal'den kullanım:
   python modules/web_technologies.py example.com

3. Detaylı analiz için:
   from modules.web_technologies import detect_web_technologies
   results = detect_web_technologies("example.com")

4. Sadece WordPress analizi:
   from modules.web_technologies import enhanced_wordpress_analysis
   wp_results = enhanced_wordpress_analysis("wordpress-site.com", html, headers, soup)

ÖZELLİKLER:
✅ Kapsamlı teknoloji tespiti (Backend, Frontend, JS, CSS)
✅ Güvenlik açığı analizi
✅ WordPress özel detaylı analiz
✅ Kullanıcı numaralandırma (wp-json API)
✅ Plugin ve tema tespiti
✅ SSL/TLS güvenlik analizi
✅ Güvenlik başlıkları kontrolü
✅ Cookie güvenlik analizi
✅ Bilgi sızıntısı tespiti
✅ WAF ve güvenlik servisi tespiti
✅ Genel güvenlik skoru (0-100)
✅ Detaylı rapor çıktısı
✅ main.py entegrasyonu

WORDPRESS ÖZELLİKLERİ:
🔍 Version tespiti (generator, readme.html, RSS)
👥 Kullanıcı numaralandırma (REST API, author pages)
🔌 Plugin tespiti (script/css analizi)
🎨 Tema tespiti ve versiyon bilgisi
🛡️ Güvenlik açığı kontrolü
📁 Dosya sızıntısı kontrolü (wp-config backup'ları)
🔐 Admin panel erişim kontrolü
📡 XML-RPC durum kontrolü
📂 Directory listing kontrolü
🐛 Debug bilgi sızıntısı tespiti

Bu modül main.py ile uyumlu şekilde tasarlanmıştır ve mevcut detect_web_technologies() 
fonksiyonunu güvenlik odaklı özelliklerle genişletir.
"""