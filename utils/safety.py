"""Safety guards for running WebAnalyzer as a public/hosted service.

Two protections, both opt-in via the ``DEMO_MODE`` environment variable so
self-hosted users keep full power (e.g. scanning their own internal network)
while a public demo stays safe:

1. SSRF / internal-target blocking — refuse to scan loopback, private,
   link-local, reserved or cloud-metadata targets, so the host cannot be turned
   into an attack proxy against internal infrastructure.
2. Per-client rate limiting — a simple in-memory sliding window.

The hostname/IP classification and the rate limiter are dependency-free and
unit tested in ``tests/test_safety.py``. Only DNS resolution touches the
network, and it fails open on transient errors (an unresolvable name is not an
internal target).
"""
import ipaddress
import os
import socket
import threading
import time
from urllib.parse import urlparse

# Hostnames a hosted instance must never scan.
BLOCKED_HOSTNAMES = frozenset({
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "metadata",
    "metadata.google.internal",
})

# Suffixes that indicate an internal/private name.
BLOCKED_SUFFIXES = (".local", ".internal", ".localhost", ".lan", ".home", ".corp")


def normalize_target(raw):
    """Extract a bare, lower-cased hostname from user input.

    Accepts values with or without a scheme, path or port, e.g.
    ``https://Example.com/login`` -> ``example.com``.
    """
    if not raw or not isinstance(raw, str):
        return ""
    value = raw.strip()
    if not value:
        return ""
    if "://" not in value:
        value = "http://" + value
    host = urlparse(value).hostname or ""
    return host.lower().strip(".")


def is_blocked_ip(ip_str):
    """True if ``ip_str`` is loopback/private/link-local/reserved/etc."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def classify_target(raw, resolve=True):
    """Return ``(allowed: bool, reason: str)`` for a scan target.

    Hostname and literal-IP checks are always applied. When ``resolve`` is
    True, the name is resolved and rejected if *any* resolved address is
    internal. DNS failures fail open (returns allowed) so transient resolver
    problems don't block legitimate scans.
    """
    host = normalize_target(raw)
    if not host:
        return False, "empty or invalid target"

    if host in BLOCKED_HOSTNAMES or host.endswith(BLOCKED_SUFFIXES):
        return False, "internal hostnames are not allowed on this instance"

    # Literal IP address supplied directly.
    try:
        ipaddress.ip_address(host)
        if is_blocked_ip(host):
            return False, "private or reserved IP addresses are not allowed"
        return True, "ok"
    except ValueError:
        pass  # not a literal IP; fall through to DNS resolution

    if resolve:
        try:
            infos = socket.getaddrinfo(host, None)
        except Exception:
            return True, "unresolved"  # fail open on DNS errors
        for info in infos:
            if is_blocked_ip(info[4][0]):
                return False, "target resolves to a private or reserved address"

    return True, "ok"


class RateLimiter:
    """Thread-safe in-memory sliding-window rate limiter.

    Suitable for a single-instance deployment. For multi-instance setups a
    shared store (e.g. Redis) would be needed instead.
    """

    def __init__(self, max_requests, window_seconds):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits = {}
        self._lock = threading.Lock()

    def check(self, key, now=None):
        """Record a hit for ``key`` and return ``(allowed, retry_after)``.

        ``retry_after`` is seconds until the caller may retry (0 when allowed).
        """
        now = time.time() if now is None else now
        with self._lock:
            recent = [t for t in self._hits.get(key, []) if now - t < self.window_seconds]
            if len(recent) >= self.max_requests:
                retry_after = int(self.window_seconds - (now - recent[0])) + 1
                self._hits[key] = recent
                return False, retry_after
            recent.append(now)
            self._hits[key] = recent
            return True, 0


def demo_mode_enabled():
    """True when the instance is running as a locked-down public demo."""
    return os.getenv("DEMO_MODE", "false").strip().lower() in ("1", "true", "yes", "on")
