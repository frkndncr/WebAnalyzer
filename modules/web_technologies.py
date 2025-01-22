import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

def detect_web_technologies(domain):
    """
    Detect backend, frontend, CDN, and other technologies used by the website.
    """
    try:
        # Ensure the protocol is valid and form the URL
        protocol = "https://" if not domain.startswith("http") else ""
        url = f"{protocol}{domain}"
        response = requests.get(url, timeout=15)
        response.raise_for_status()

        html_content = response.text.lower()
        headers = response.headers

        # Web Server Detection
        server_header = headers.get("Server", "Not Detected")

        # Backend Technologies Detection
        backend_technologies = detect_backend_technologies(html_content, headers)

        # Frontend Technologies Detection
        frontend_technologies = detect_frontend_technologies(html_content)

        # CDN Detection
        cdn = detect_cdn(headers)

        # Compression Detection
        compression = headers.get("Content-Encoding", "Not Detected")

        # Caching Detection
        caching = headers.get("Cache-Control", "Not Detected")

        # Additional Security Information
        set_cookie = headers.get("Set-Cookie", "Not Detected")
        x_cache = headers.get("X-Cache", "Not Detected")

        return {
            "Web Server": server_header,
            "Backend Technologies": backend_technologies or ["Not Detected"],
            "Frontend Technologies": frontend_technologies or ["Not Detected"],
            "Content Delivery Network (CDN)": cdn or "Not Detected",
            "Compression": compression,
            "Caching": caching,
            "Set-Cookie Header": set_cookie,
            "X-Cache Header": x_cache,
        }
    except requests.exceptions.RequestException as e:
        return {"Error": f"Could not analyze web technologies: {e}"}


def detect_backend_technologies(html_content, headers):
    """
    Detect backend technologies based on headers and HTML content.
    """
    backend_technologies = []
    checks = {
        "PHP": lambda: "php" in headers.get("X-Powered-By", "").lower(),
        "WordPress": lambda: "wordpress" in html_content or "wp-content" in html_content,
        "Joomla": lambda: "joomla" in html_content,
        "Django": lambda: "django" in html_content,
        "Flask": lambda: "flask" in html_content,
        "ASP.NET": lambda: "asp.net" in headers.get("X-Powered-By", "").lower(),
        "Node.js": lambda: "node.js" in html_content,
        "Magento": lambda: "magento" in html_content,
        "Shopify": lambda: "shopify" in html_content,
    }

    for tech, check in checks.items():
        if check():
            backend_technologies.append(tech)

    return backend_technologies


def detect_frontend_technologies(html_content):
    """
    Detect frontend technologies based on HTML content.
    """
    frontend_technologies = []
    frameworks = {
        "Bootstrap": "bootstrap",
        "Tailwind CSS": "tailwindcss",
        "React": "react",
        "Angular": "angular",
        "Vue.js": "vue",
        "Svelte": "svelte",
        "Ember.js": "ember",
    }

    for name, keyword in frameworks.items():
        if keyword in html_content:
            frontend_technologies.append(name)

    return frontend_technologies


def detect_cdn(headers):
    """
    Detect CDN services based on headers.
    """
    cdn = None
    cdn_keywords = ["cloudflare", "akamai", "fastly", "aws cloudfront", "azure"]
    for keyword in cdn_keywords:
        if keyword in headers.get("Server", "").lower():
            cdn = keyword.capitalize()
            break
    return cdn