import requests
from bs4 import BeautifulSoup
import re
import time
import os

def analyze_advanced_seo(domain):
    """
    Perform advanced SEO, analytics, performance, and security analysis for the given domain.
    """
    try:
        url = f"http://{domain}"
        start_time = time.time()
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        load_time = time.time() - start_time
        html_content = response.text

        # Parse the HTML content
        soup = BeautifulSoup(html_content, "html.parser")

        # SEO and Analysis Results
        analysis = {
            "Meta Tags": {
                "Description": None,
                "Keywords": None,
                "Canonical": None,
            },
            "Open Graph Tags": {},
            "Twitter Tags": {},
            "Verification Tags": {
                "Google": None,
                "Bing": None,
                "Yandex": None,
            },
            "Analytics Tools": {
                "Google Analytics IDs": [],
                "Google Tag Manager": False,
                "Facebook Pixel": False,
                "LinkedIn Insight Tag": False,
                "TikTok Pixel": False,
            },
            "JavaScript Frameworks": [],
            "Structured Data": [],
            "Performance Metrics": {
                "Page Load Time (seconds)": round(load_time, 2),
                "Total Request Size (KB)": None,
            },
            "Security Headers": {},
            "Robots.txt": "Not Found",
            "Sitemap.xml": "Not Found",
        }

        # Meta tags
        meta_description = soup.find("meta", attrs={"name": "description"})
        analysis["Meta Tags"]["Description"] = meta_description.get("content") if meta_description else "Meta description not found"

        meta_keywords = soup.find("meta", attrs={"name": "keywords"})
        analysis["Meta Tags"]["Keywords"] = meta_keywords.get("content") if meta_keywords else "Not Found"

        canonical_tag = soup.find("link", attrs={"rel": "canonical"})
        analysis["Meta Tags"]["Canonical"] = canonical_tag.get("href") if canonical_tag else "Not Found"

        # Open Graph Tags
        og_tags = ["og:title", "og:description", "og:image", "og:url", "og:locale"]
        for tag in og_tags:
            og_tag = soup.find("meta", attrs={"property": tag})
            analysis["Open Graph Tags"][tag] = og_tag.get("content") if og_tag else "Not Found"

        # Twitter Tags
        twitter_tags = ["twitter:card", "twitter:title", "twitter:description", "twitter:image"]
        for tag in twitter_tags:
            twitter_tag = soup.find("meta", attrs={"name": tag})
            analysis["Twitter Tags"][tag] = twitter_tag.get("content") if twitter_tag else "Not Found"

        # Verification Tags
        google_verification = soup.find("meta", attrs={"name": "google-site-verification"})
        analysis["Verification Tags"]["Google"] = google_verification.get("content") if google_verification else "Not Found"

        bing_verification = soup.find("meta", attrs={"name": "msvalidate.01"})
        analysis["Verification Tags"]["Bing"] = bing_verification.get("content") if bing_verification else "Not Found"

        yandex_verification = soup.find("meta", attrs={"name": "yandex-verification"})
        analysis["Verification Tags"]["Yandex"] = yandex_verification.get("content") if yandex_verification else "Not Found"

        # Analytics Tools
        ga_pattern = r"gtag\('config',\s*'([\w-]+)'\)"
        analysis["Analytics Tools"]["Google Analytics IDs"] = re.findall(ga_pattern, html_content)

        if "googletagmanager.com" in html_content:
            analysis["Analytics Tools"]["Google Tag Manager"] = True

        if "connect.facebook.net/en_US/fbevents.js" in html_content:
            analysis["Analytics Tools"]["Facebook Pixel"] = True

        if "snap.licdn.com/li.lms-analytics/insight.min.js" in html_content:
            analysis["Analytics Tools"]["LinkedIn Insight Tag"] = True

        if "analytics.tiktok.com/i18n" in html_content:
            analysis["Analytics Tools"]["TikTok Pixel"] = True

        # JavaScript Framework Detection
        js_frameworks = {
            "React": "react",
            "Vue.js": "vue",
            "Angular": "angular",
            "jQuery": "jquery",
        }
        for name, keyword in js_frameworks.items():
            if keyword in html_content.lower():
                analysis["JavaScript Frameworks"].append(name)

        # Structured Data
        structured_data = soup.find_all("script", attrs={"type": "application/ld+json"})
        analysis["Structured Data"] = [tag.string.strip() for tag in structured_data if tag.string]

        # Security Headers
        security_headers = ["Content-Security-Policy", "Strict-Transport-Security", "X-Content-Type-Options"]
        for header in security_headers:
            analysis["Security Headers"][header] = response.headers.get(header, "Not Found")

        # Performance Metrics
        content_length = response.headers.get("Content-Length")
        if content_length:
            analysis["Performance Metrics"]["Total Request Size (KB)"] = round(int(content_length) / 1024, 2)

        # Check for robots.txt and sitemap.xml
        check_robots_and_sitemap(domain, analysis)

        # Save results to logs folder
        save_results_to_logs(domain, analysis)

        return analysis
    except requests.exceptions.RequestException as e:
        return {"Error": f"Could not fetch the page: {e}"}

def check_robots_and_sitemap(domain, analysis):
    """Check for robots.txt and sitemap.xml"""
    robots_url = f"http://{domain}/robots.txt"
    sitemap_url = f"http://{domain}/sitemap.xml"

    # Check for robots.txt
    try:
        robots_response = requests.get(robots_url)
        robots_response.raise_for_status()
        analysis["Robots.txt"] = "Found"
        save_file("robots.txt", robots_response.text, domain)
    except requests.exceptions.RequestException:
        analysis["Robots.txt"] = "Not Found"
    
    # Check for sitemap.xml
    try:
        sitemap_response = requests.get(sitemap_url)
        sitemap_response.raise_for_status()
        analysis["Sitemap.xml"] = "Found"
        save_file("sitemap.xml", sitemap_response.text, domain)
    except requests.exceptions.RequestException:
        analysis["Sitemap.xml"] = "Not Found"

def save_file(filename, content, domain):
    """Save the robots.txt or sitemap.xml content to a file in the specified domain folder"""
    domain_folder = f"logs/{domain}"
    if not os.path.exists(domain_folder):
        os.makedirs(domain_folder)
    
    file_path = os.path.join(domain_folder, filename)
    with open(file_path, "w") as file:
        file.write(content)
    print(f"{filename} has been saved to {file_path}.")

def save_results_to_logs(domain, analysis):
    """Save the analysis results to a text file"""
    domain_folder = f"logs/{domain}"
    if not os.path.exists(domain_folder):
        os.makedirs(domain_folder)
    
    result_file_path = os.path.join(domain_folder, "seo_analysis_results.txt")
    with open(result_file_path, "w") as file:
        for key, value in analysis.items():
            file.write(f"{key}:\n")
            if isinstance(value, dict):
                for sub_key, sub_value in value.items():
                    file.write(f"  {sub_key}: {sub_value}\n")
            else:
                file.write(f"  {value}\n")
    
    print(f"SEO analysis results have been saved to {result_file_path}.")