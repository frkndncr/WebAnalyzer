# modules/web_technologies.py - Enhanced web technologies detection
import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from typing import Dict, List, Optional
import json

def detect_web_technologies(domain: str) -> Dict:
    """
    Enhanced detection of backend, frontend, CDN, and other web technologies.
    
    Args:
        domain (str): Target domain
        
    Returns:
        Dict: Comprehensive technology analysis
    """
    try:
        # Ensure proper URL format
        if not domain.startswith(('http://', 'https://')):
            url = f"https://{domain}"
        else:
            url = domain
            
        # Custom headers to avoid blocking
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        }
        
        response = requests.get(url, headers=headers, timeout=30, allow_redirects=True)
        response.raise_for_status()
        
        html_content = response.text
        response_headers = response.headers
        
        # Parse HTML for deeper analysis
        soup = BeautifulSoup(html_content, 'html.parser')
        
        return {
            "Web Server": detect_web_server(response_headers),
            "Backend Technologies": detect_backend_technologies(html_content, response_headers, soup),
            "Frontend Technologies": detect_frontend_technologies(html_content, soup),
            "JavaScript Libraries": detect_js_libraries(html_content, soup),
            "CSS Frameworks": detect_css_frameworks(html_content, soup),
            "Content Management System": detect_cms(html_content, response_headers, soup),
            "E-commerce Platform": detect_ecommerce(html_content, soup),
            "CDN & Cloud Services": detect_cdn_services(response_headers, html_content),
            "Analytics & Tracking": detect_analytics(html_content, soup),
            "Security Technologies": detect_security_tech(response_headers),
            "Performance & Caching": detect_performance_tech(response_headers),
            "Database Technologies": detect_database_tech(response_headers, html_content),
        }
        
    except requests.exceptions.RequestException as e:
        return {"Error": f"Could not analyze web technologies: {str(e)}"}
    except Exception as e:
        return {"Error": f"Analysis failed: {str(e)}"}

def detect_web_server(headers: Dict) -> str:
    """Enhanced web server detection"""
    server = headers.get('Server', '').lower()
    powered_by = headers.get('X-Powered-By', '').lower()
    
    servers = {
        'nginx': 'Nginx',
        'apache': 'Apache',
        'iis': 'Microsoft IIS',
        'cloudflare': 'Cloudflare',
        'litespeed': 'LiteSpeed',
        'caddy': 'Caddy',
        'traefik': 'Traefik',
        'envoy': 'Envoy Proxy',
    }
    
    for key, name in servers.items():
        if key in server or key in powered_by:
            return name
    
    return server.split('/')[0].title() if server else "Not Detected"

def detect_backend_technologies(html: str, headers: Dict, soup: BeautifulSoup) -> List[str]:
    """Enhanced backend technology detection"""
    technologies = []
    html_lower = html.lower()
    powered_by = headers.get('X-Powered-By', '').lower()
    
    # Framework detection patterns
    patterns = {
        'PHP': [
            lambda: 'php' in powered_by,
            lambda: re.search(r'\.php(\?|"|\s)', html_lower),
            lambda: 'phpsessid' in html_lower,
        ],
        'ASP.NET': [
            lambda: 'asp.net' in powered_by,
            lambda: 'viewstate' in html_lower,
            lambda: 'aspxauth' in html_lower,
            lambda: soup.find('form', {'id': 'aspnetForm'}),
        ],
        'Node.js': [
            lambda: 'express' in headers.get('X-Powered-By', ''),
            lambda: 'node' in headers.get('Server', '').lower(),
        ],
        'Python': [
            lambda: 'django' in html_lower,
            lambda: 'flask' in html_lower,
            lambda: 'pyramid' in html_lower,
            lambda: 'fastapi' in html_lower,
        ],
        'Ruby on Rails': [
            lambda: 'ruby' in powered_by,
            lambda: 'rails' in html_lower,
            lambda: soup.find('meta', {'name': 'csrf-token'}),
        ],
        'Java': [
            lambda: 'servlet' in html_lower,
            lambda: 'jsessionid' in html_lower,
            lambda: 'struts' in html_lower,
            lambda: 'spring' in html_lower,
        ],
        'Go': [
            lambda: 'golang' in html_lower,
            lambda: 'gin-gonic' in html_lower,
        ],
    }
    
    for tech, checks in patterns.items():
        if any(check() for check in checks if callable(check)):
            technologies.append(tech)
    
    return technologies if technologies else ["Not Detected"]

def detect_frontend_technologies(html: str, soup: BeautifulSoup) -> List[str]:
    """Enhanced frontend framework detection"""
    technologies = []
    html_lower = html.lower()
    
    # Check for script tags and meta tags
    scripts = soup.find_all('script', src=True)
    script_content = ' '.join([tag.get('src', '') for tag in scripts]).lower()
    
    patterns = {
        'React': [
            lambda: 'react' in script_content,
            lambda: soup.find('div', {'id': 'react-root'}),
            lambda: 'data-reactroot' in html_lower,
        ],
        'Vue.js': [
            lambda: 'vue' in script_content,
            lambda: 'v-app' in html_lower,
            lambda: soup.find(attrs={'v-cloak': True}),
        ],
        'Angular': [
            lambda: 'angular' in script_content,
            lambda: 'ng-app' in html_lower,
            lambda: soup.find(attrs={'ng-app': True}),
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
    }
    
    for tech, checks in patterns.items():
        if any(check() for check in checks if callable(check)):
            technologies.append(tech)
    
    return technologies if technologies else ["Not Detected"]

def detect_js_libraries(html: str, soup: BeautifulSoup) -> List[str]:
    """Detect JavaScript libraries"""
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
    }
    
    for lib, patterns in js_libs.items():
        if any(pattern in script_content or pattern in inline_js for pattern in patterns):
            libraries.append(lib)
    
    return libraries if libraries else ["Not Detected"]

def detect_css_frameworks(html: str, soup: BeautifulSoup) -> List[str]:
    """Detect CSS frameworks"""
    frameworks = []
    
    # Check link tags and inline styles
    links = soup.find_all('link', {'rel': 'stylesheet'})
    css_content = ' '.join([tag.get('href', '') for tag in links]).lower()
    
    # Check for framework classes in HTML
    html_classes = ' '.join([tag.get('class', []) for tag in soup.find_all() if tag.get('class')])
    
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
    """Detect Content Management Systems"""
    cms_list = []
    html_lower = html.lower()
    
    cms_patterns = {
        'WordPress': ['wp-content', 'wp-includes', 'wordpress'],
        'Drupal': ['drupal', 'sites/all', 'sites/default'],
        'Joomla': ['joomla', 'option=com_'],
        'Magento': ['magento', 'mage/cookies.js'],
        'Shopify': ['shopify', 'shopifycdn'],
        'Wix': ['wix.com', 'wixstatic'],
        'Squarespace': ['squarespace', 'sqsp'],
        'Ghost': ['ghost', 'casper'],
        'Webflow': ['webflow'],
    }
    
    for cms, patterns in cms_patterns.items():
        if any(pattern in html_lower for pattern in patterns):
            cms_list.append(cms)
    
    return cms_list if cms_list else ["Not Detected"]

def detect_ecommerce(html: str, soup: BeautifulSoup) -> List[str]:
    """Detect e-commerce platforms"""
    platforms = []
    html_lower = html.lower()
    
    ecommerce_patterns = {
        'Shopify': ['shopify', 'shopifycdn'],
        'WooCommerce': ['woocommerce', 'wc-'],
        'Magento': ['magento'],
        'PrestaShop': ['prestashop'],
        'BigCommerce': ['bigcommerce'],
        'OpenCart': ['opencart'],
        'Stripe': ['stripe'],
        'PayPal': ['paypal'],
    }
    
    for platform, patterns in ecommerce_patterns.items():
        if any(pattern in html_lower for pattern in patterns):
            platforms.append(platform)
    
    return platforms if platforms else ["Not Detected"]

def detect_cdn_services(headers: Dict, html: str) -> List[str]:
    """Enhanced CDN detection"""
    cdns = []
    html_lower = html.lower()
    
    # Check headers
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
    """Detect analytics and tracking services"""
    analytics = []
    html_lower = html.lower()
    
    # Check script sources
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

def detect_security_tech(headers: Dict) -> List[str]:
    """Detect security technologies"""
    security_tech = []
    
    security_headers = {
        'Content Security Policy': headers.get('Content-Security-Policy'),
        'HSTS': headers.get('Strict-Transport-Security'),
        'X-Frame-Options': headers.get('X-Frame-Options'),
        'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
        'Referrer Policy': headers.get('Referrer-Policy'),
    }
    
    for tech, value in security_headers.items():
        if value:
            security_tech.append(tech)
    
    return security_tech if security_tech else ["Not Detected"]

def detect_performance_tech(headers: Dict) -> Dict[str, str]:
    """Detect performance and caching technologies"""
    return {
        'Compression': headers.get('Content-Encoding', 'Not Detected'),
        'Cache Control': headers.get('Cache-Control', 'Not Detected'),
        'ETag': 'Enabled' if headers.get('ETag') else 'Not Detected',
        'Vary': headers.get('Vary', 'Not Detected'),
    }

def detect_database_tech(headers: Dict, html: str) -> List[str]:
    """Detect database technologies (limited detection)"""
    databases = []
    html_lower = html.lower()
    
    # Limited detection based on common patterns
    db_patterns = {
        'MySQL': ['mysql'],
        'PostgreSQL': ['postgresql', 'postgres'],
        'MongoDB': ['mongodb', 'mongo'],
        'Redis': ['redis'],
        'SQLite': ['sqlite'],
    }
    
    for db, patterns in db_patterns.items():
        if any(pattern in html_lower for pattern in patterns):
            databases.append(db)
    
    return databases if databases else ["Not Detected"]