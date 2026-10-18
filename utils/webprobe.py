"""Small, safe network helpers shared by the check modules.

Every helper takes the thing that touches the network as an argument (``get``,
``resolve``) so modules are tested with fakes and never need the internet.
Requests never follow redirects on their own, are time limited and read at most
``MAX_BYTES``: a target must not be able to bounce a check to another host, hang
it, or make it download something large.
"""
import re
from typing import Callable, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

USER_AGENT = "WebAnalyzer security check (+https://github.com/frkndncr/WebAnalyzer)"
TIMEOUT = 8
MAX_BYTES = 256 * 1024
REDIRECTS = (301, 302, 303, 307, 308)


def default_get(url: str, method: str = "GET", headers: Optional[dict] = None):
    """One HTTP request, no redirects, streamed. Returns a ``requests.Response``."""
    import requests

    merged = {"User-Agent": USER_AGENT, **(headers or {})}
    return requests.request(method, url, headers=merged, timeout=TIMEOUT, allow_redirects=False, stream=True)


def body(response, limit: int = MAX_BYTES) -> bytes:
    """At most ``limit`` bytes of the response body (works for real responses and test stubs)."""
    raw = getattr(response, "raw", None)
    if raw is not None and hasattr(raw, "read"):
        try:
            data = raw.read(limit, decode_content=True)
            return data if isinstance(data, bytes) else bytes(data or b"")
        except Exception:  # noqa: BLE001 - fall back to what requests buffered
            pass
    content = getattr(response, "content", b"")
    return content[:limit] if isinstance(content, bytes) else str(content).encode()[:limit]


def text(response, limit: int = MAX_BYTES) -> str:
    return body(response, limit).decode("utf-8", "replace")


def _same_site(host: Optional[str], other: str) -> bool:
    strip = lambda h: (h or "").lower().removeprefix("www.")  # noqa: E731
    return strip(host) == strip(other)


def fetch(domain: str, path: str = "/", get: Optional[Callable] = None, method: str = "GET",
          headers: Optional[dict] = None, scheme: str = "https", max_redirects: int = 2) -> Tuple[Optional[object], str]:
    """Request ``path`` on ``domain``. Redirects are followed only within the same site and only to https.

    Returns ``(response, final_url)``; ``response`` is None when a redirect leaves the site or the request fails.
    """
    get = get or default_get
    url = f"{scheme}://{domain}{path}"
    for _ in range(max_redirects + 1):
        try:
            response = get(url, method=method, headers=headers)
        except Exception:  # noqa: BLE001 - an unreachable target is "no answer", not an error
            return None, url
        location = response.headers.get("Location") if response.status_code in REDIRECTS else None
        if not location:
            return response, url
        target = urljoin(url, location)
        parsed = urlparse(target)
        if parsed.scheme != "https" or not _same_site(parsed.hostname, domain):
            return None, url
        url = target
    return None, url


def set_cookie_headers(response) -> List[str]:
    """Every ``Set-Cookie`` header (a plain dict of headers would merge them into one)."""
    stub = getattr(response, "set_cookie_headers", None)
    if stub is not None:
        return list(stub)
    raw_headers = getattr(getattr(response, "raw", None), "headers", None)
    if raw_headers is not None and hasattr(raw_headers, "getlist"):
        return list(raw_headers.getlist("Set-Cookie"))
    value = response.headers.get("Set-Cookie")
    return [value] if value else []


# ─────────────────────────── DNS ───────────────────────────

def resolve(name: str, rtype: str = "A", timeout: float = 5.0) -> Optional[List[str]]:
    """Answers as text. ``[]`` when the name exists but has no such record, ``None`` when it does not exist."""
    import dns.exception
    import dns.resolver

    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout
    try:
        answers = resolver.resolve(name, rtype)
    except dns.resolver.NXDOMAIN:
        return None
    except (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return []
    except Exception:  # noqa: BLE001 - resolver trouble must not fail a scan
        return []
    out = []
    for rdata in answers:
        if rtype == "TXT":
            out.append("".join(part.decode("utf-8", "replace") for part in rdata.strings))
        else:
            out.append(rdata.to_text())
    return out


_HOST = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")


def clean_host(value: str) -> str:
    """A bare lower-case host name, or '' when ``value`` is not one (modules build URLs and DNS names from it)."""
    host = (value or "").strip().lower().rstrip(".")
    return host if _HOST.match(host) and len(host) <= 253 else ""
