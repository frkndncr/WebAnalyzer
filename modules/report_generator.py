"""
WebAnalyzer - report generator entry points and the remediation library.
The report itself is built in utils.report from the shared scan document.
"""

import os
from typing import Dict, List, Any, Optional

# Pre-defined remediation guidance library for common findings
REMEDIATION_DATABASE = {
    "missing_csp": {
        "title": "Missing Content Security Policy (CSP)",
        "remediation": "Deploy a restrictive Content-Security-Policy HTTP header to prevent Cross-Site Scripting (XSS) and data injection attacks.",
        "code": "# Nginx Configuration\nadd_header Content-Security-Policy \"default-src 'self'; script-src 'self' https://trustedscripts.com; object-src 'none'; frame-ancestors 'none';\" always;\n\n# Apache Configuration\nHeader set Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none';\""
    },
    "missing_hsts": {
        "title": "Missing HTTP Strict Transport Security (HSTS)",
        "remediation": "Enforce HTTPS communication across the domain and all subdomains by enabling HSTS with a 1-year duration.",
        "code": "# Nginx Configuration\nadd_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\n\n# Apache Configuration\nHeader always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\""
    },
    "missing_x_frame_options": {
        "title": "Clickjacking Protection Missing (X-Frame-Options)",
        "remediation": "Prevent clickjacking attacks by forbidding external domains from embedding your application in iframes.",
        "code": "# Nginx Configuration\nadd_header X-Frame-Options \"DENY\" always;\n\n# Apache Configuration\nHeader always set X-Frame-Options \"DENY\""
    },
    "missing_x_content_type_options": {
        "title": "MIME-Sniffing Protection Missing",
        "remediation": "Disable MIME type sniffing to prevent malicious file uploads from executing in the victim's browser.",
        "code": "# Nginx Configuration\nadd_header X-Content-Type-Options \"nosniff\" always;\n\n# Apache Configuration\nHeader always set X-Content-Type-Options \"nosniff\""
    },
    "subdomain_takeover": {
        "title": "Subdomain Takeover Risk",
        "remediation": "Immediate Action Required: Delete the dangling DNS CNAME or NS record pointing to an unallocated third-party cloud provider, or reclaim the cloud resource before an attacker does.",
        "code": "# DNS Command: Remove the dangling CNAME record from your DNS registrar\n# E.g. Remove: sub.example.com CNAME attacker-bucket.s3.amazonaws.com"
    },
    "open_port": {
        "title": "Exposed Network Port",
        "remediation": "Close unnecessary public ports or restrict access using a network firewall (UFW, iptables, AWS Security Groups).",
        "code": "# Linux UFW Firewall\nsudo ufw deny <PORT>/tcp\nsudo ufw reload"
    },
    "cloudflare_bypass": {
        "title": "Direct Origin IP Exposed (WAF Bypass)",
        "remediation": "Configure your origin web server firewall to only accept HTTP/HTTPS traffic originating from Cloudflare IP ranges, rejecting all direct connections.",
        "code": "# Nginx: Restrict access to Cloudflare IP ranges\nset_real_ip_from 173.245.48.0/20;\n# Drop all other direct requests"
    },
    "default": {
        "title": "Security Finding",
        "remediation": "Review the affected component against standard security hardening best practices (OWASP Top 10, CIS Benchmarks).",
        "code": ""
    }
}


def _get_remediation(vuln_type: str, desc: str) -> Dict[str, str]:
    """Resolves actionable remediation guidance based on vulnerability type or description"""
    v_lower = (vuln_type + " " + desc).lower()
    if "csp" in v_lower or "content security policy" in v_lower:
        return REMEDIATION_DATABASE["missing_csp"]
    elif "hsts" in v_lower or "strict-transport-security" in v_lower:
        return REMEDIATION_DATABASE["missing_hsts"]
    elif "frame-options" in v_lower or "clickjacking" in v_lower:
        return REMEDIATION_DATABASE["missing_x_frame_options"]
    elif "content-type" in v_lower or "nosniff" in v_lower:
        return REMEDIATION_DATABASE["missing_x_content_type_options"]
    elif "takeover" in v_lower:
        return REMEDIATION_DATABASE["subdomain_takeover"]
    elif "cloudflare" in v_lower or "direct ip" in v_lower:
        return REMEDIATION_DATABASE["cloudflare_bypass"]
    elif "port" in v_lower:
        return REMEDIATION_DATABASE["open_port"]
    return REMEDIATION_DATABASE["default"]


def generate_executive_report(domain: str, data: Dict[str, Any], **options) -> str:
    """The client-ready HTML report. Built by utils.report so its numbers match every other output."""
    from utils.report import build_report
    return build_report(domain.replace("http://", "").replace("https://", "").split("/")[0], data, **options)


def save_html_report(domain: str, data: Dict[str, Any], output_path: Optional[str] = None, **options) -> str:
    """Generates and writes the report to disk (logs/<domain>/report.html by default)."""
    report_html = generate_executive_report(domain, data, **options)
    if not output_path:
        clean_domain = domain.replace("http://", "").replace("https://", "").split("/")[0]
        output_dir = os.path.join("logs", clean_domain)
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, "report.html")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report_html)
    return output_path
