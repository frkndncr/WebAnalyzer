# modules/seo_analysis.py - Enhanced SEO analysis with comprehensive checks
import requests
from bs4 import BeautifulSoup
import re
import time
import os
import json
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Optional, Tuple

def analyze_advanced_seo(domain: str) -> Dict:
    """
    Perform comprehensive SEO analysis for the given domain.
    Enhanced version with detailed SEO, performance, and accessibility checks.
    """
    try:
        # Ensure proper URL format
        url = f"https://{domain}" if not domain.startswith('http') else domain
        
        # Make request with timing
        start_time = time.time()
        response = requests.get(url, timeout=20, headers={
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }, allow_redirects=True)
        response.raise_for_status()
        load_time = round(time.time() - start_time, 2)
        
        # Parse HTML
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Comprehensive SEO Analysis
        analysis = {
            "Basic SEO": _analyze_basic_seo(soup, response),
            "Content Analysis": _analyze_content(soup),
            "Technical SEO": _analyze_technical_seo(soup, response, url),
            "Social Media": _analyze_social_tags(soup),
            "Analytics & Tracking": _analyze_analytics(response.text),
            "Performance Metrics": _analyze_performance(response, load_time),
            "Mobile & Accessibility": _analyze_mobile_accessibility(soup),
            "Security & Headers": _analyze_security_headers(response),
            "SEO Resources": _check_seo_resources(domain),
            "Schema Markup": _analyze_schema_markup(soup),
            "Link Analysis": _analyze_links(soup, url),
            "Image SEO": _analyze_images(soup),
            "Page Speed Factors": _analyze_page_speed_factors(soup, response)
        }
        
        # Add SEO score
        analysis["SEO Score"] = _calculate_seo_score(analysis)
        
        return analysis
        
    except requests.exceptions.RequestException as e:
        return {"Error": f"Could not analyze domain: {str(e)}"}

def _analyze_basic_seo(soup: BeautifulSoup, response: requests.Response) -> Dict:
    """Analyze basic SEO elements"""
    title = soup.find('title')
    title_text = title.get_text().strip() if title else ""
    
    return {
        "Title": {
            "text": title_text if title_text else "Missing",
            "length": len(title_text),
            "status": "Good" if 30 <= len(title_text) <= 60 else "Too short" if len(title_text) < 30 else "Too long"
        },
        "Meta Description": _analyze_meta_description(soup),
        "Meta Keywords": _get_meta_content(soup, 'name', 'keywords'),
        "Canonical URL": _get_link_href(soup, 'rel', 'canonical'),
        "Meta Robots": _get_meta_content(soup, 'name', 'robots'),
        "Viewport": _get_meta_content(soup, 'name', 'viewport'),
        "Language": soup.find('html').get('lang', 'Not specified') if soup.find('html') else 'Not specified',
        "Charset": _get_charset(soup)
    }

def _analyze_meta_description(soup: BeautifulSoup) -> Dict:
    """Detailed meta description analysis"""
    meta_desc = soup.find('meta', {'name': 'description'})
    if not meta_desc:
        return {"text": "Missing", "length": 0, "status": "Missing"}
    
    desc_text = meta_desc.get('content', '').strip()
    desc_length = len(desc_text)
    
    return {
        "text": desc_text,
        "length": desc_length,
        "status": "Good" if 120 <= desc_length <= 160 else "Too short" if desc_length < 120 else "Too long"
    }

def _analyze_content(soup: BeautifulSoup) -> Dict:
    """Analyze content structure and quality"""
    # Heading structure
    headings = {}
    heading_hierarchy = []
    
    for i in range(1, 7):
        h_tags = soup.find_all(f'h{i}')
        if h_tags:
            headings[f'H{i}'] = {
                'count': len(h_tags),
                'texts': [h.get_text().strip()[:100] for h in h_tags[:3]]  # First 3 headings
            }
            heading_hierarchy.extend([(i, h.get_text().strip()) for h in h_tags])
    
    # Content metrics
    text_content = soup.get_text()
    words = len(text_content.split())
    paragraphs = len(soup.find_all('p'))
    
    return {
        "Headings Structure": headings,
        "Heading Issues": _check_heading_issues(heading_hierarchy),
        "Word Count": words,
        "Word Count Status": "Good" if words >= 300 else "Too short",
        "Paragraphs": paragraphs,
        "Text to HTML Ratio": _calculate_text_html_ratio(soup),
        "Keyword Density": _analyze_keyword_density(text_content)
    }

def _check_heading_issues(headings: List[Tuple[int, str]]) -> List[str]:
    """Check for heading hierarchy issues"""
    issues = []
    
    if not headings:
        issues.append("No headings found")
        return issues
    
    # Check for H1
    h1_count = sum(1 for level, text in headings if level == 1)
    if h1_count == 0:
        issues.append("Missing H1 tag")
    elif h1_count > 1:
        issues.append(f"Multiple H1 tags ({h1_count})")
    
    # Check hierarchy
    prev_level = 0
    for level, text in headings:
        if level > prev_level + 1:
            issues.append(f"Skipped heading level (from H{prev_level} to H{level})")
        prev_level = level
    
    return issues

def _analyze_technical_seo(soup: BeautifulSoup, response: requests.Response, url: str) -> Dict:
    """Analyze technical SEO factors"""
    return {
        "URL Structure": _analyze_url_structure(url),
        "Internal Links": len(soup.find_all('a', href=lambda x: x and not x.startswith(('http', 'mailto:', 'tel:')))),
        "External Links": len(soup.find_all('a', href=lambda x: x and x.startswith('http'))),
        "Broken Links": "Check required",  # Would need additional requests
        "Page Size": f"{len(response.content)} bytes ({round(len(response.content)/1024, 2)} KB)",
        "HTTP Status": response.status_code,
        "Redirects": len(response.history),
        "Structured Data": _count_structured_data(soup),
        "Breadcrumbs": "Found" if soup.find(attrs={'typeof': 'BreadcrumbList'}) or soup.find(class_=re.compile('breadcrumb', re.I)) else "Not Found"
    }

def _analyze_social_tags(soup: BeautifulSoup) -> Dict:
    """Analyze social media optimization tags"""
    # Open Graph tags
    og_tags = {
        'og:title': _get_meta_content(soup, 'property', 'og:title'),
        'og:description': _get_meta_content(soup, 'property', 'og:description'),
        'og:image': _get_meta_content(soup, 'property', 'og:image'),
        'og:url': _get_meta_content(soup, 'property', 'og:url'),
        'og:type': _get_meta_content(soup, 'property', 'og:type'),
        'og:site_name': _get_meta_content(soup, 'property', 'og:site_name')
    }
    
    # Twitter Cards
    twitter_tags = {
        'twitter:card': _get_meta_content(soup, 'name', 'twitter:card'),
        'twitter:title': _get_meta_content(soup, 'name', 'twitter:title'),
        'twitter:description': _get_meta_content(soup, 'name', 'twitter:description'),
        'twitter:image': _get_meta_content(soup, 'name', 'twitter:image'),
        'twitter:site': _get_meta_content(soup, 'name', 'twitter:site')
    }
    
    return {
        "Open Graph": og_tags,
        "Twitter Cards": twitter_tags,
        "Facebook Domain Verification": _get_meta_content(soup, 'name', 'facebook-domain-verification')
    }

def _analyze_analytics(html: str) -> Dict:
    """Enhanced analytics and tracking detection"""
    analytics = {}
    
    # Google Analytics (GA4 and Universal)
    ga4_matches = re.findall(r'gtag\([\'"]config[\'"],\s*[\'"]G-([A-Z0-9]+)[\'"]', html)
    ua_matches = re.findall(r'gtag\([\'"]config[\'"],\s*[\'"]UA-([0-9-]+)[\'"]', html)
    
    analytics["Google Analytics"] = {
        "GA4": ga4_matches if ga4_matches else [],
        "Universal Analytics": ua_matches if ua_matches else []
    }
    
    # Enhanced tracking tools detection
    tracking_tools = {
        "Google Tag Manager": [r'googletagmanager\.com/gtm\.js', r'dataLayer'],
        "Google Ads": [r'googleads\.g\.doubleclick\.net', r'googlesyndication\.com'],
        "Facebook Pixel": [r'connect\.facebook\.net.*fbevents', r'fbq\('],
        "LinkedIn Insight": [r'snap\.licdn\.com', r'_linkedin_partner_id'],
        "TikTok Pixel": [r'analytics\.tiktok\.com', r'ttq\.'],
        "Hotjar": [r'static\.hotjar\.com', r'hjid'],
        "Mixpanel": [r'cdn\.mxpnl\.com', r'mixpanel\.init'],
        "Segment": [r'cdn\.segment\.com', r'analytics\.load'],
        "Intercom": [r'widget\.intercom\.io'],
        "Zendesk": [r'static\.zdassets\.com'],
        "Crisp": [r'client\.crisp\.chat']
    }
    
    for tool, patterns in tracking_tools.items():
        found = any(re.search(pattern, html, re.I) for pattern in patterns)
        analytics[tool] = "Found" if found else "Not Found"
    
    return analytics

def _analyze_performance(response: requests.Response, load_time: float) -> Dict:
    """Analyze performance metrics"""
    headers = response.headers
    
    return {
        "Load Time": f"{load_time}s",
        "Load Time Status": "Excellent" if load_time < 1 else "Good" if load_time < 3 else "Poor",
        "Content Size": f"{round(len(response.content)/1024, 2)} KB",
        "Compression": headers.get('Content-Encoding', 'None'),
        "Server": headers.get('Server', 'Unknown'),
        "Cache Control": headers.get('Cache-Control', 'Not Set'),
        "ETag": "Set" if headers.get('ETag') else "Not Set",
        "Last Modified": headers.get('Last-Modified', 'Not Set')
    }

def _analyze_mobile_accessibility(soup: BeautifulSoup) -> Dict:
    """Analyze mobile and accessibility features"""
    viewport = soup.find('meta', {'name': 'viewport'})
    viewport_content = viewport.get('content', '') if viewport else ''
    
    return {
        "Viewport Meta": "Present" if viewport else "Missing",
        "Viewport Content": viewport_content,
        "Mobile Friendly": "Yes" if 'width=device-width' in viewport_content else "Unknown",
        "Alt Attributes": _check_alt_attributes(soup),
        "ARIA Labels": len(soup.find_all(attrs={'aria-label': True})),
        "Skip Links": len(soup.find_all('a', href='#main')) + len(soup.find_all('a', href='#content'))
    }

def _check_alt_attributes(soup: BeautifulSoup) -> Dict:
    """Check image alt attributes"""
    images = soup.find_all('img')
    total_images = len(images)
    images_with_alt = len([img for img in images if img.get('alt')])
    
    return {
        "Total Images": total_images,
        "Images with Alt": images_with_alt,
        "Missing Alt": total_images - images_with_alt,
        "Alt Coverage": f"{round((images_with_alt/total_images*100), 1)}%" if total_images > 0 else "0%"
    }

def _analyze_security_headers(response: requests.Response) -> Dict:
    """Analyze security headers"""
    headers = response.headers
    
    security_headers = {
        "HSTS": headers.get('Strict-Transport-Security', 'Not Set'),
        "Content Security Policy": headers.get('Content-Security-Policy', 'Not Set'),
        "X-Frame-Options": headers.get('X-Frame-Options', 'Not Set'),
        "X-Content-Type-Options": headers.get('X-Content-Type-Options', 'Not Set'),
        "Referrer-Policy": headers.get('Referrer-Policy', 'Not Set'),
        "X-XSS-Protection": headers.get('X-XSS-Protection', 'Not Set')
    }
    
    # Count set headers
    set_headers = sum(1 for value in security_headers.values() if value != 'Not Set')
    
    return {
        **security_headers,
        "Security Score": f"{set_headers}/6 headers set",
        "Security Status": "Good" if set_headers >= 4 else "Fair" if set_headers >= 2 else "Poor"
    }

def _check_seo_resources(domain: str) -> Dict:
    """Check for important SEO resources"""
    resources = {}
    
    files_to_check = {
        "robots.txt": f"https://{domain}/robots.txt",
        "sitemap.xml": f"https://{domain}/sitemap.xml",
        "humans.txt": f"https://{domain}/humans.txt",
        "ads.txt": f"https://{domain}/ads.txt"
    }
    
    for file_name, url in files_to_check.items():
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                resources[file_name] = "Found"
                if file_name in ["robots.txt", "sitemap.xml"]:
                    _save_seo_file(domain, file_name, response.text)
            else:
                resources[file_name] = "Not Found"
        except:
            resources[file_name] = "Not Found"
    
    return resources

def _analyze_schema_markup(soup: BeautifulSoup) -> Dict:
    """Analyze structured data/schema markup"""
    # JSON-LD
    json_ld = soup.find_all('script', {'type': 'application/ld+json'})
    json_ld_types = []
    
    for script in json_ld:
        try:
            data = json.loads(script.string)
            if isinstance(data, dict) and '@type' in data:
                json_ld_types.append(data['@type'])
            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and '@type' in item:
                        json_ld_types.append(item['@type'])
        except:
            continue
    
    # Microdata
    microdata = len(soup.find_all(attrs={'itemtype': True}))
    
    return {
        "JSON-LD Scripts": len(json_ld),
        "JSON-LD Types": json_ld_types,
        "Microdata Items": microdata,
        "Total Structured Data": len(json_ld) + microdata
    }

def _analyze_links(soup: BeautifulSoup, base_url: str) -> Dict:
    """Analyze link structure"""
    all_links = soup.find_all('a', href=True)
    
    internal_links = []
    external_links = []
    
    base_domain = urlparse(base_url).netloc
    
    for link in all_links:
        href = link.get('href')
        if href.startswith('http'):
            parsed = urlparse(href)
            if parsed.netloc == base_domain:
                internal_links.append(href)
            else:
                external_links.append(href)
        elif not href.startswith(('mailto:', 'tel:', '#')):
            internal_links.append(href)
    
    return {
        "Total Links": len(all_links),
        "Internal Links": len(internal_links),
        "External Links": len(external_links),
        "NoFollow Links": len(soup.find_all('a', rel=lambda x: x and 'nofollow' in x))
    }

def _analyze_images(soup: BeautifulSoup) -> Dict:
    """Analyze image optimization"""
    images = soup.find_all('img')
    
    lazy_loaded = len([img for img in images if img.get('loading') == 'lazy'])
    with_alt = len([img for img in images if img.get('alt')])
    with_title = len([img for img in images if img.get('title')])
    
    return {
        "Total Images": len(images),
        "Lazy Loaded": lazy_loaded,
        "With Alt Text": with_alt,
        "With Title": with_title,
        "Optimization Score": f"{round((lazy_loaded + with_alt) / (len(images) * 2) * 100, 1)}%" if images else "0%"
    }

def _analyze_page_speed_factors(soup: BeautifulSoup, response: requests.Response) -> Dict:
    """Analyze factors affecting page speed"""
    return {
        "CSS Files": len(soup.find_all('link', {'rel': 'stylesheet'})),
        "JavaScript Files": len(soup.find_all('script', src=True)),
        "Inline Styles": len(soup.find_all('style')),
        "Inline Scripts": len(soup.find_all('script', src=lambda x: not x)),
        "Minification": "Unknown",  # Would need content analysis
        "Compression": response.headers.get('Content-Encoding', 'None')
    }

def _calculate_seo_score(analysis: Dict) -> Dict:
    """Calculate overall SEO score"""
    score = 0
    max_score = 100
    
    # Basic SEO (30 points)
    basic_seo = analysis.get("Basic SEO", {})
    title = basic_seo.get("Title", {})
    if title.get("status") == "Good":
        score += 10
    
    meta_desc = basic_seo.get("Meta Description", {})
    if meta_desc.get("status") == "Good":
        score += 10
    
    if basic_seo.get("Canonical URL", "Not Found") != "Not Found":
        score += 5
    
    if basic_seo.get("Viewport", "Not Found") != "Not Found":
        score += 5
    
    # Content (20 points)
    content = analysis.get("Content Analysis", {})
    if content.get("Word Count Status") == "Good":
        score += 10
    
    headings = content.get("Headings Structure", {})
    if "H1" in headings:
        score += 10
    
    # Technical (20 points)
    seo_resources = analysis.get("SEO Resources", {})
    if seo_resources.get("robots.txt") == "Found":
        score += 5
    if seo_resources.get("sitemap.xml") == "Found":
        score += 5
    
    schema = analysis.get("Schema Markup", {})
    if schema.get("Total Structured Data", 0) > 0:
        score += 10
    
    # Performance (15 points)
    performance = analysis.get("Performance Metrics", {})
    if performance.get("Load Time Status") in ["Excellent", "Good"]:
        score += 15
    
    # Security (10 points)
    security = analysis.get("Security & Headers", {})
    if security.get("Security Status") == "Good":
        score += 10
    elif security.get("Security Status") == "Fair":
        score += 5
    
    # Mobile (5 points)
    mobile = analysis.get("Mobile & Accessibility", {})
    if mobile.get("Mobile Friendly") == "Yes":
        score += 5
    
    return {
        "Score": f"{score}/{max_score}",
        "Percentage": f"{round(score/max_score*100, 1)}%",
        "Grade": _get_seo_grade(score/max_score*100)
    }

def _get_seo_grade(percentage: float) -> str:
    """Get SEO grade based on percentage"""
    if percentage >= 90:
        return "A+"
    elif percentage >= 80:
        return "A"
    elif percentage >= 70:
        return "B"
    elif percentage >= 60:
        return "C"
    elif percentage >= 50:
        return "D"
    else:
        return "F"

# Helper functions
def _get_meta_content(soup: BeautifulSoup, attr: str, value: str) -> str:
    """Get meta tag content"""
    meta = soup.find('meta', {attr: value})
    return meta.get('content', '').strip() if meta else "Not Found"

def _get_link_href(soup: BeautifulSoup, attr: str, value: str) -> str:
    """Get link tag href"""
    link = soup.find('link', {attr: value})
    return link.get('href', '').strip() if link else "Not Found"

def _get_charset(soup: BeautifulSoup) -> str:
    """Get page charset"""
    charset_meta = soup.find('meta', attrs={'charset': True})
    if charset_meta:
        return charset_meta.get('charset', 'Unknown')
    
    equiv_meta = soup.find('meta', {'http-equiv': 'Content-Type'})
    if equiv_meta:
        content = equiv_meta.get('content', '')
        charset_match = re.search(r'charset=([^;]+)', content)
        return charset_match.group(1) if charset_match else 'Unknown'
    
    return 'Unknown'

def _analyze_url_structure(url: str) -> Dict:
    """Analyze URL structure"""
    parsed = urlparse(url)
    path_segments = [seg for seg in parsed.path.split('/') if seg]
    
    return {
        "Length": len(url),
        "HTTPS": parsed.scheme == 'https',
        "WWW": parsed.netloc.startswith('www.'),
        "Path Segments": len(path_segments),
        "Parameters": len(parsed.query.split('&')) if parsed.query else 0,
        "SEO Friendly": not bool(parsed.query) and all(seg.replace('-', '').replace('_', '').isalnum() for seg in path_segments)
    }

def _count_structured_data(soup: BeautifulSoup) -> int:
    """Count structured data elements"""
    json_ld = len(soup.find_all('script', {'type': 'application/ld+json'}))
    microdata = len(soup.find_all(attrs={'itemtype': True}))
    return json_ld + microdata

def _calculate_text_html_ratio(soup: BeautifulSoup) -> str:
    """Calculate text to HTML ratio"""
    text_content = soup.get_text()
    html_content = str(soup)
    
    text_length = len(text_content)
    html_length = len(html_content)
    
    if html_length > 0:
        ratio = (text_length / html_length) * 100
        return f"{round(ratio, 1)}%"
    
    return "0%"

def _analyze_keyword_density(text: str) -> Dict:
    """Basic keyword density analysis"""
    words = text.lower().split()
    word_count = len(words)
    
    if word_count == 0:
        return {"status": "No content"}
    
    # Count word frequency
    word_freq = {}
    for word in words:
        if len(word) > 3:  # Skip short words
            word_freq[word] = word_freq.get(word, 0) + 1
    
    # Get top 5 words
    top_words = sorted(word_freq.items(), key=lambda x: x[1], reverse=True)[:5]
    
    return {
        "Top Keywords": [
            {"word": word, "count": count, "density": f"{round((count/word_count)*100, 2)}%"}
            for word, count in top_words
        ]
    }

def _save_seo_file(domain: str, filename: str, content: str):
    """Save SEO files to logs directory"""
    try:
        log_dir = f"logs/{domain}"
        os.makedirs(log_dir, exist_ok=True)
        
        with open(f"{log_dir}/{filename}", 'w', encoding='utf-8') as f:
            f.write(content)
    except Exception:
        pass