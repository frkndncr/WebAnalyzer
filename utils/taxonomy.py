"""Map a finding to a CWE and an OWASP Top 10 (2021) category.

A deliberately small, conservative table: a finding is classified only when its
title or description clearly matches. Anything else gets the generic
"CWE-1188 / unclassified" treatment in reports rather than a guess.
"""
import re
from typing import Optional

# (pattern, CWE id, CWE name, OWASP category). The first match wins.
_RULES = [
    (r"strict-transport-security|hsts|plain http|unencrypted|cleartext", 319, "Cleartext Transmission of Sensitive Information", "A02:2021 Cryptographic Failures"),
    (r"\bssl\b|\btls\b|certificate|cipher|weak protocol", 326, "Inadequate Encryption Strength", "A02:2021 Cryptographic Failures"),
    (r"x-frame-options|clickjack|frame-ancestors", 1021, "Improper Restriction of Rendered UI Layers or Frames", "A05:2021 Security Misconfiguration"),
    (r"content-security-policy|\bcsp\b", 693, "Protection Mechanism Failure", "A05:2021 Security Misconfiguration"),
    (r"x-content-type-options|nosniff|mime", 693, "Protection Mechanism Failure", "A05:2021 Security Misconfiguration"),
    (r"referrer-policy|permissions-policy|cross-origin", 693, "Protection Mechanism Failure", "A05:2021 Security Misconfiguration"),
    (r"\bcors\b|access-control-allow-origin", 942, "Permissive Cross-domain Policy with Untrusted Domains", "A05:2021 Security Misconfiguration"),
    (r"cookie.*(secure|httponly|samesite)|(secure|httponly|samesite).*cookie", 614, "Sensitive Cookie Without 'Secure' Attribute", "A05:2021 Security Misconfiguration"),
    (r"\bxss\b|cross-site scripting|innerhtml|dom-based", 79, "Cross-site Scripting", "A03:2021 Injection"),
    (r"sql injection|sqli", 89, "SQL Injection", "A03:2021 Injection"),
    (r"open redirect", 601, "URL Redirection to Untrusted Site", "A01:2021 Broken Access Control"),
    (r"subdomain takeover|dangling", 284, "Improper Access Control", "A05:2021 Security Misconfiguration"),
    (r"api[ _-]?key|secret|password|credential|private key", 798, "Use of Hard-coded Credentials", "A07:2021 Identification and Authentication Failures"),
    (r"directory listing|index of /", 548, "Exposure of Information Through Directory Listing", "A05:2021 Security Misconfiguration"),
    (r"information disclosure|server header|version disclosure|x-powered-by|stack trace|debug", 200, "Exposure of Sensitive Information to an Unauthorized Actor", "A05:2021 Security Misconfiguration"),
    (r"exposed (file|endpoint|admin)|\.git|\.env|backup|sensitive file", 538, "Insertion of Sensitive Information into Externally-Accessible File or Directory", "A05:2021 Security Misconfiguration"),
    (r"outdated|vulnerable (component|library|version)|end[- ]of[- ]life|cve-\d{4}", 1104, "Use of Unmaintained Third Party Components", "A06:2021 Vulnerable and Outdated Components"),
    (r"open port|exposed port|port \d+", 668, "Exposure of Resource to Wrong Sphere", "A05:2021 Security Misconfiguration"),
    (r"origin ip|cloudflare|waf bypass", 668, "Exposure of Resource to Wrong Sphere", "A05:2021 Security Misconfiguration"),
    (r"spf|dmarc|dkim|look-alike|phishing|typosquat", 290, "Authentication Bypass by Spoofing", "A07:2021 Identification and Authentication Failures"),
]
_COMPILED = [(re.compile(p, re.I), cwe, name, owasp) for p, cwe, name, owasp in _RULES]


def classify(title: str, description: str = "") -> Optional[dict]:
    """``{"cwe": "CWE-319", "cwe_name": ..., "owasp": ...}`` or None when nothing matches clearly."""
    text = f"{title} {description}"
    for pattern, cwe, name, owasp in _COMPILED:
        if pattern.search(text):
            return {"cwe": f"CWE-{cwe}", "cwe_name": name, "owasp": owasp}
    return None
