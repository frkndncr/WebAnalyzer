"""Example plugin and a useful check on its own: does the site publish a
security.txt (RFC 9116) so researchers know where to report vulnerabilities?

It is passive (one or two GET requests to the target) and doubles as the
reference for writing a module: register a function, return plain data.
"""
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

from modules.registry import module

PATHS = ("/.well-known/security.txt", "/security.txt")
MAX_BYTES = 64 * 1024
MAX_REDIRECTS = 2
LIST_FIELDS = ("contact", "encryption", "acknowledgments", "policy", "hiring", "canonical", "preferred-languages")


def parse_security_txt(text, now=None):
    """Parse a security.txt body into fields plus a list of problems (pure, no network)."""
    now = now or datetime.now(timezone.utc)
    fields = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, _, value = line.partition(":")
        fields.setdefault(key.strip().lower(), []).append(value.strip())

    issues = []
    if not fields.get("contact"):
        issues.append("Missing the required Contact field")

    expires = None
    expired = None
    if not fields.get("expires"):
        issues.append("Missing the required Expires field")
    else:
        try:
            expires = datetime.fromisoformat(fields["expires"][0].replace("Z", "+00:00"))
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            expired = expires < now
            if expired:
                issues.append("The Expires date has passed")
        except ValueError:
            issues.append("Expires is not a valid ISO 8601 date")

    return {
        "contact": fields.get("contact", []),
        "expires": expires.isoformat() if expires else None,
        "expired": expired,
        "fields": {k: v for k, v in fields.items() if k in LIST_FIELDS or k == "expires"},
        "issues": issues,
    }


def findings_for(found, url, issues):
    """The findings this module reports (the plugin contract: a "findings" list in the result)."""
    if not found:
        return [{
            "title": "No security.txt published",
            "severity": "info",
            "description": "No vulnerability-disclosure contact file was found at /.well-known/security.txt.",
            "recommendation": "Publish a security.txt (RFC 9116) so researchers know how to report a vulnerability.",
        }]
    return [{
        "title": "security.txt problem",
        "severity": "low",
        "description": issue,
        "location": url,
        "recommendation": "Fix the security.txt so it follows RFC 9116 (Contact and a future Expires date are required).",
    } for issue in issues]


def _same_site(host, other):
    strip = lambda h: (h or "").lower().removeprefix("www.")  # noqa: E731
    return strip(host) == strip(other)


def _fetch(domain, path, get):
    """GET ``path`` on ``domain`` over HTTPS, following redirects only within the same site."""
    url = f"https://{domain}{path}"
    for _ in range(MAX_REDIRECTS + 1):
        response = get(url)
        if response.status_code in (301, 302, 307, 308) and response.headers.get("Location"):
            target = urljoin(url, response.headers["Location"])
            parsed = urlparse(target)
            if parsed.scheme != "https" or not _same_site(parsed.hostname, domain):
                return None, url          # never follow a redirect to another host
            url = target
            continue
        return response, url
    return None, url


@module("Security.txt", description="RFC 9116 vulnerability-disclosure contact", group="security", weight="light", order=165)
def security_txt(domain, get=None):
    if get is None:
        import requests

        def get(url):  # noqa: E306
            return requests.get(url, timeout=8, allow_redirects=False, stream=True,
                                headers={"User-Agent": "WebAnalyzer security.txt check"})

    for path in PATHS:
        try:
            response, url = _fetch(domain, path, get)
        except Exception:  # noqa: BLE001 - an unreachable path simply is not a finding
            continue
        if response is None or response.status_code != 200:
            continue
        body = response.raw.read(MAX_BYTES, decode_content=True) if hasattr(response, "raw") and response.raw else response.content[:MAX_BYTES]
        text = body.decode("utf-8", "replace") if isinstance(body, bytes) else str(body)
        if "contact:" not in text.lower():     # an HTML error page served with 200 is not a security.txt
            continue
        parsed = parse_security_txt(text)
        return {"found": True, "url": url, **parsed, "findings": findings_for(True, url, parsed["issues"])}
    return {"found": False, "url": None, "contact": [], "expires": None, "expired": None, "fields": {},
            "issues": ["No security.txt was found at /.well-known/security.txt"],
            "findings": findings_for(False, None, [])}
