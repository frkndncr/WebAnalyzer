"""Known vulnerabilities in the JavaScript libraries a page loads, via OSV.dev.

Passive: one GET of the home page, then queries to the public OSV database (which
sees only a library name and version, never the target). Libraries are found by the
version in their script URL, so only what the page states openly is checked.
"""
import json
import re
from urllib.parse import urlparse

from modules.registry import module
from utils import webprobe

OSV_URL = "https://api.osv.dev/v1/query"
MAX_LIBRARIES = 12
# script file / package name -> npm package name
KNOWN = {
    "jquery": "jquery", "jquery-ui": "jquery-ui", "jqueryui": "jquery-ui", "bootstrap": "bootstrap", "lodash": "lodash",
    "moment": "moment", "handlebars": "handlebars", "underscore": "underscore", "vue": "vue", "angular": "angular",
    "angularjs": "angular", "axios": "axios", "dompurify": "dompurify", "marked": "marked", "socket.io": "socket.io",
    "highlight.js": "highlight.js", "chart.js": "chart.js", "select2": "select2", "tinymce": "tinymce", "ckeditor": "ckeditor4",
}
_VERSION = r"(\d+\.\d+(?:\.\d+)?)"
_PATTERNS = (
    re.compile(rf"/ajax/libs/([\w.\-]+)/{_VERSION}/", re.I),                      # cdnjs
    re.compile(rf"/npm/([\w.\-@]+)@{_VERSION}", re.I),                            # jsdelivr
    re.compile(rf"unpkg\.com/([\w.\-]+)@{_VERSION}", re.I),                       # unpkg
    re.compile(rf"/([\w.\-]+?)[-.]v?{_VERSION}(?:\.min)?\.js", re.I),             # jquery-3.3.1.min.js
)
_SCRIPT_SRC = re.compile(r"""<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']""", re.I)
_QUERY_VERSION = re.compile(rf"/([\w.\-]+?)(?:\.min)?\.js\?ver={_VERSION}", re.I)  # WordPress style
_SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}
_RANK = ("critical", "high", "medium", "low", "info")


def find_libraries(html):
    """``[{"name", "package", "version", "url"}]`` for the known libraries whose version appears in a script URL."""
    found, seen = [], set()
    for src in _SCRIPT_SRC.findall(html):
        candidates = [m.groups() for p in _PATTERNS for m in [p.search(src)] if m] + [m.groups() for m in [_QUERY_VERSION.search(src)] if m]
        for name, version in candidates:
            package = KNOWN.get(name.lower().removesuffix(".min"))
            if package and (package, version) not in seen:
                seen.add((package, version))
                found.append({"name": name, "package": package, "version": version, "url": src})
                break
    return found[:MAX_LIBRARIES]


def osv_query(package, version, post=None):
    """Vulnerabilities OSV knows for an npm package version (a list of OSV records)."""
    payload = {"version": version, "package": {"name": package, "ecosystem": "npm"}}
    if post is not None:
        return post(payload)
    import requests

    response = requests.post(OSV_URL, data=json.dumps(payload), timeout=10, headers={"Content-Type": "application/json", "User-Agent": webprobe.USER_AGENT})
    response.raise_for_status()
    return response.json().get("vulns", [])


def _severity(vuln):
    declared = (vuln.get("database_specific") or {}).get("severity", "")
    return _SEVERITY.get(str(declared).upper(), "medium")


@module("JS Library Vulnerabilities", description="Known CVEs in the JavaScript libraries a page loads (OSV)", group="security", weight="light", order=178)
def js_library_vulns(domain, get=None, query=None, base_url=None):
    domain = webprobe.clean_host(domain)
    if not domain:
        return {"error": "not a valid domain name"}
    response, url = webprobe.fetch(domain, "/", get=get)
    if response is None or response.status_code != 200:
        return {"reachable": False, "libraries": [], "findings": []}
    libraries = find_libraries(webprobe.text(response))
    query = query or osv_query
    findings, report = [], []
    lookup_failed = False
    for lib in libraries:
        try:
            vulns = query(lib["package"], lib["version"])
        except Exception:  # noqa: BLE001 - OSV unreachable: report the libraries, not a failure
            lookup_failed = True
            vulns = []
        ids = sorted({a for v in vulns for a in ([v.get("id")] + list(v.get("aliases") or [])) if a and a.startswith(("CVE-", "GHSA-"))})
        cves = [i for i in ids if i.startswith("CVE-")]
        worst = min((_severity(v) for v in vulns), key=_RANK.index) if vulns else None
        report.append({**lib, "vulnerabilities": len(vulns), "worst": worst, "ids": (cves or ids)[:10]})
        if vulns:
            findings.append({
                "title": f"{lib['package']} {lib['version']} has {len(vulns)} known vulnerabilit{'y' if len(vulns) == 1 else 'ies'}",
                "severity": worst, "location": lib["url"],
                "description": f"OSV lists {len(vulns)} advisory record(s) for {lib['package']} {lib['version']}"
                               + (f", including {', '.join((cves or ids)[:5])}." if ids else "."),
                "recommendation": f"Upgrade {lib['package']} to a patched release and remove unused libraries.",
            })
    return {"reachable": True, "libraries": report, "lookup_failed": lookup_failed, "findings": findings}
