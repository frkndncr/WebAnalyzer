"""Pure, dependency-free analysis helpers for the Advanced Content Scanner.

This security-critical scoring, entropy and classification logic is extracted
here so it can be unit tested (see tests/test_content_analysis.py) without
crawling, network access or BeautifulSoup. ``AdvancedContentScanner`` delegates
to these functions.
"""
import hashlib
import math
from collections import defaultdict

# Severity -> base weight for the composite risk score.
SEVERITY_WEIGHT = {"Critical": 10.0, "High": 7.5, "Medium": 4.0, "Low": 1.5, "Info": 0.5}

# JS finding categories treated as High severity (everything else is Medium).
HIGH_SEVERITY_JS_CATEGORIES = frozenset({
    "DOM XSS", "Open Redirect", "Dynamic Code Execution",
    "Prototype Pollution", "WebSocket Plaintext",
    "Weak / Broken Crypto", "Path Traversal",
    "JSONP Callback Injection", "Server-Side Request Forgery (JS)",
    "Debug / Secret Console Leak", "Taint Flow: Source → Sink",
})


def shannon_entropy(s: str) -> float:
    """Shannon entropy (bits per character) of a string; 0.0 for empty input."""
    if not s:
        return 0.0
    freq = defaultdict(int)
    for c in s:
        freq[c] += 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def risk_score(severity: str, confidence: str, entropy: float = 0) -> float:
    """CVSS-inspired composite risk score in the range [0, 10]."""
    base = SEVERITY_WEIGHT.get(severity, 2.0)
    conf_m = {"HIGH": 1.0, "MEDIUM": 0.7, "LOW": 0.4}.get(confidence, 0.5)
    entr_m = min(entropy / 5.0, 1.0) if entropy > 0 else 1.0
    return round(min(base * conf_m * entr_m + (entr_m * 0.5), 10.0), 2)


def mask_secret(s: str) -> str:
    """Mask a secret for safe display, keeping only its edge characters."""
    if len(s) <= 8:
        return s[:2] + "****"
    return s[:4] + "****" + s[-4:]


def short_hash(s: str) -> str:
    """Stable 10-char hex digest, used to de-duplicate findings."""
    return hashlib.md5(s.encode(errors="replace")).hexdigest()[:10]


def root_domain(netloc: str) -> str:
    """Naive registrable-domain extraction (the last two labels)."""
    parts = netloc.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else netloc


def js_vuln_severity(category: str) -> str:
    """Map a JS vulnerability category to 'High' or 'Medium'."""
    return "High" if category in HIGH_SEVERITY_JS_CATEGORIES else "Medium"
