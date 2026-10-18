"""Pure, dependency-free analysis helpers for the Advanced Content Scanner.

This security-critical scoring, entropy and classification logic is extracted
here so it can be unit tested (see tests/test_content_analysis.py) without
crawling, network access or BeautifulSoup. ``AdvancedContentScanner`` delegates
to these functions.
"""
import hashlib
import math
import re
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


# A pattern match on its own (no taint flow behind it) is a hint, not proof: `eval(` and `__proto__`
# appear in almost every bundled library. Those categories are capped so they do not read as exploits.
_PATTERN_ONLY_CAP = {
    "Dynamic Code Execution": "Low", "Prototype Pollution": "Low",
    "Weak / Broken Crypto": "Medium", "Insecure postMessage": "Medium", "WebSocket Plaintext": "Medium",
}


def js_pattern_severity(category: str) -> str:
    """Severity of a finding that rests on a code pattern only (taint-confirmed flows stay High elsewhere)."""
    return _PATTERN_ONLY_CAP.get(category) or js_vuln_severity(category)


_VENDOR_NAMES = (
    "jquery", "jquery-ui", "jquery-migrate", "jquery.min", "bootstrap", "popper", "lodash", "underscore", "moment", "react",
    "react-dom", "vue", "angular", "core-js", "polyfill", "swiper", "slick", "owl.carousel", "select2", "datatables",
    "chart", "d3", "three", "gsap", "tinymce", "ckeditor", "leaflet", "axios", "backbone", "handlebars", "mustache",
    "modernizr", "require", "hammer", "isotope", "masonry", "imagesloaded", "waypoints", "fancybox", "lightgallery",
    "magnific-popup", "wow", "aos", "videojs", "plyr", "sweetalert", "toastr", "flatpickr", "clipboard", "dompurify",
)
_VENDOR_PATH_PARTS = ("/wp-includes/", "/wp-admin/", "/node_modules/", "/vendor/", "/vendors/", "/bower_components/", "/lib/", "/libs/")
_VENDOR_BANNER = re.compile(r"/\*!?\s*(?:@license\s+)?(?:jQuery|Bootstrap|Lodash|Underscore|Moment|React|Vue|Angular|Popper|Swiper|core-js)\b", re.I)


def is_vendor_script(url: str, head: str = "") -> bool:
    """True for third-party library code (jQuery, Bootstrap, WordPress core, ...): pattern hits inside it are not the site's own bugs."""
    path = (url or "").lower().split("?")[0]
    if any(part in path for part in _VENDOR_PATH_PARTS):
        return True
    stem = path.rsplit("/", 1)[-1]
    stem = re.sub(r"(\.min)?\.js$", "", stem)
    stem = re.sub(r"[-.]v?\d+(\.\d+)*.*$", "", stem)               # jquery-3.3.1 -> jquery
    stem = re.sub(r"\.(bundle|slim|esm|umd|production)$", "", stem)
    if stem in _VENDOR_NAMES:
        return True
    return bool(_VENDOR_BANNER.search(head[:400]))


# ── exposed-path validation ──────────────────────────────────────────────

_HTML = re.compile(r"^\s*(<!doctype|<html|<head|<body)", re.I)


def _json_ok(text):
    try:
        import json
        return isinstance(json.loads(text), (dict, list))
    except ValueError:
        return False


def _has(pattern, flags=0):
    compiled = re.compile(pattern, flags)
    return lambda text: bool(compiled.search(text))


_EXPOSURE_SIGNATURES = {
    "Environment File": _has(r"^[A-Za-z_][A-Za-z0-9_]*\s*=", re.M),
    "Config File": _has(r"(?m)^\s*[\w.\-\"']+\s*[:=]\s*\S"),
    "Git Exposure": _has(r"^ref:\s*refs/|\[core\]", re.M),
    "SVN Exposure": _has(r"(?m)^(dir|file)$"),
    "WordPress Backup": _has(r"DB_PASSWORD|DB_NAME|<\?php"),
    "Database Backup": _has(r"CREATE TABLE|INSERT INTO|DROP TABLE|mysqldump", re.I),
    "Backup File": lambda text: text.startswith("PK"),
    "Password File": _has(r"^[^:\s<]+:\S+", re.M),
    "PHP Info": _has(r"PHP Version|phpinfo\(\)"),
    "Spring Actuator": _has(r'"_links"|"status"|propertySources|"beans"|"contexts"'),
    "Debug Endpoint": _has(r"cmdline|memstats|Werkzeug|Traceback|goroutine", re.I),
    "Apache Status": _has(r"Apache Server Status"),
    "Apache Info": _has(r"Apache Server Information"),
    "Apache Config": _has(r"RewriteEngine|AuthType|<IfModule|Options\s|Header\s", re.I),
    "API Docs": _has(r'swagger|openapi|"paths"|Swagger UI', re.I),
    "Robots File": _has(r"(?im)^\s*(user-agent|disallow|allow|sitemap)\s*:"),
    "Security Contact": _has(r"(?i)contact\s*:"),
    "Flash Policy": _has(r"<cross-domain-policy"),
    "Silverlight Policy": _has(r"<access-policy"),
    "PHP Config": lambda text: _json_ok(text) and ("require" in text or "name" in text),
    "Ruby Config": _has(r"(?m)^\s*(source|gem)\s"),
    "Python Config": _has(r"(?m)^[A-Za-z0-9_.\-]+\s*([=<>~!]=|$)"),
    "Yarn Config": _has(r"(?m)^[\w\-\"]+\s*[\"\w]"),
    "GraphQL Schema": _has(r"__schema|type Query|GraphQL", re.I),
    "GraphQL Playground": _has(r"graphql|playground", re.I),
    "GraphQL IDE": _has(r"graphiql|graphql", re.I),
    "macOS Artifact": lambda text: "Bud1" in text,
    "Error Log": _has(r"\d{4}[-/]\d\d[-/]\d\d|\[(error|warn|notice)\]|GET /|Traceback"),
    "Access Log": _has(r"\d+\.\d+\.\d+\.\d+ .*\"(GET|POST|HEAD) |GET /|POST /"),
}


def similar_to_baseline(text: str, baseline: str) -> bool:
    """True when ``text`` is (nearly) the page a server returns for a path that does not exist (a soft 404)."""
    if not baseline:
        return False
    a, b = " ".join(text.split()), " ".join(baseline.split())
    if a == b:
        return True
    longer = max(len(a), len(b))
    return longer > 0 and abs(len(a) - len(b)) / longer < 0.05 and a[:160] == b[:160]


def assess_exposure(entry: dict, status: int, content_type: str, text: str, baseline: str = "") -> bool:
    """Is this response really the exposed file ``entry`` describes?

    Access-denied answers (401/403) are not exposures, a catch-all "soft 404" page is not
    one either, and a 200 must contain what that kind of file normally contains.
    """
    if status not in (200, 206):
        return False
    body = text or ""
    if len(body.strip()) < 10 or similar_to_baseline(body, baseline):
        return False
    kind = entry.get("type", "")
    if _HTML.match(body) and kind not in ("API Docs", "GraphQL IDE", "GraphQL Playground", "PHP Info", "Apache Status", "Apache Info", "Debug Endpoint"):
        return False                                   # a file type that came back as a web page is the site's error page
    if entry.get("path", "").endswith(".npmrc"):
        return bool(re.search(r"_authToken|registry|_auth", body))
    if entry.get("path", "").endswith("package.json"):
        return _json_ok(body) and '"name"' in body
    if entry.get("path", "").endswith((".json",)):
        return _json_ok(body)
    check = _EXPOSURE_SIGNATURES.get(kind)
    return check(body) if check else not _HTML.match(body)
