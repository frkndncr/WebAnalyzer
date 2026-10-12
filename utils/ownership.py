"""Domain ownership verification for the public demo.

A hosted scanner that anyone can point at any domain is a liability: the
intrusive modules (port scanning, active content testing, takeover probing)
would be launched from the host's IP against third parties who never agreed.
In DEMO_MODE the intrusive ("active") modules therefore only run against a
domain whose owner has proven control by publishing a DNS TXT record. The
passive modules (WHOIS, DNS, headers, certificate and archive lookups, ...)
stay open to everyone.

Proof of control is the ability to publish a record at the domain, so the token
is not a secret and the check needs no accounts, sessions or storage. Only DNS
is used: verifying over HTTP would make the server fetch URLs on hosts chosen by
the caller.

The pure helpers are unit tested; the DNS lookup is injectable.
"""
import hashlib
import hmac
import os
import threading
import time
from typing import Callable, Iterable, List, Optional, Tuple

from utils.safety import normalize_target

# Modules that send intrusive traffic to the target (or to hosts derived from
# it). They require a verified domain in DEMO_MODE; everything else is passive.
ACTIVE_MODULES = frozenset({
    "Advanced Content Scan",   # aggressive crawl plus active injection tests
    "Nmap Zero Day Scan",      # port and service scanning
    "Subdomain Takeover",      # probes every discovered subdomain
    "CloudFlare Bypass",       # probes candidate origin addresses
})

RECORD_PREFIX = "webanalyzer-verify="
RECORD_LABEL = "_webanalyzer"
_POSITIVE_TTL = 600  # seconds a successful check is remembered


def verification_token(domain: str, secret: Optional[str] = None) -> str:
    """Stable per-domain token. Not a secret: control of the domain is the proof."""
    host = normalize_target(domain)
    key = (os.getenv("VERIFY_SECRET", "") if secret is None else secret).encode()
    return hmac.new(key or b"webanalyzer", f"verify:{host}".encode(), hashlib.sha256).hexdigest()[:32]


def split_modules(requested: Iterable[str]) -> Tuple[List[str], List[str]]:
    """``(passive, active)`` from the requested modules, keeping their order."""
    passive, active = [], []
    for name in requested:
        (active if name in ACTIVE_MODULES else passive).append(name)
    return passive, active


def txt_matches(records: Iterable[str], token: str) -> bool:
    """True when any TXT record carries this domain's verification token."""
    wanted = RECORD_PREFIX + token
    return any(wanted == str(r).strip().strip('"') for r in records)


def instructions(domain: str) -> dict:
    """What the owner has to publish."""
    host = normalize_target(domain)
    token = verification_token(host)
    return {
        "domain": host,
        "token": token,
        "record": {
            "type": "TXT",
            "name": f"{RECORD_LABEL}.{host}",
            "value": RECORD_PREFIX + token,
        },
        "note": "Publish the TXT record, wait for DNS to propagate, then check again.",
    }


def lookup_txt(name: str, lifetime: float = 5.0) -> List[str]:
    """TXT strings published at ``name`` (empty when there are none)."""
    import dns.exception
    import dns.resolver

    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=lifetime)
    except (dns.exception.DNSException, OSError):
        return []
    return ["".join(part.decode("utf-8", "replace") for part in rdata.strings) for rdata in answers]


_cache = {}
_cache_lock = threading.Lock()


def clear_cache():
    with _cache_lock:
        _cache.clear()


def is_verified(domain: str, resolver: Callable[[str], List[str]] = lookup_txt, now: Optional[float] = None) -> bool:
    """Whether the owner of ``domain`` has published the verification record.

    Only successes are cached (briefly), so a record the owner has just added is
    picked up on the next check.
    """
    host = normalize_target(domain)
    if not host:
        return False
    now = time.time() if now is None else now
    with _cache_lock:
        verified_at = _cache.get(host)
        if verified_at is not None and now - verified_at < _POSITIVE_TTL:
            return True

    token = verification_token(host)
    for name in (f"{RECORD_LABEL}.{host}", host):
        if txt_matches(resolver(name), token):
            with _cache_lock:
                _cache[host] = now
            return True
    return False
