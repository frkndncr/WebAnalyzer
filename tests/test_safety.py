"""Tests for utils.safety — SSRF target classification and rate limiting.

Network resolution is avoided by passing resolve=False so these stay fast and
deterministic.
"""
import pytest

from utils.safety import (
    normalize_target,
    is_blocked_ip,
    classify_target,
    RateLimiter,
    demo_mode_enabled,
)


# ─────────────────────────── normalize_target ───────────────────────────

@pytest.mark.parametrize("raw,expected", [
    ("example.com", "example.com"),
    ("https://Example.com/login?x=1", "example.com"),
    ("http://sub.example.com:8080/", "sub.example.com"),
    ("  EXAMPLE.com.  ", "example.com"),
    ("", ""),
    (None, ""),
    (12345, ""),
])
def test_normalize_target(raw, expected):
    assert normalize_target(raw) == expected


# ─────────────────────────── is_blocked_ip ───────────────────────────

@pytest.mark.parametrize("ip", [
    "127.0.0.1",        # loopback
    "10.0.0.5",         # private
    "192.168.1.1",      # private
    "172.16.0.1",       # private
    "169.254.169.254",  # link-local (cloud metadata!)
    "0.0.0.0",          # unspecified
    "::1",              # ipv6 loopback
    "fe80::1",          # ipv6 link-local
])
def test_is_blocked_ip_blocks_internal(ip):
    assert is_blocked_ip(ip) is True


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"])
def test_is_blocked_ip_allows_public(ip):
    assert is_blocked_ip(ip) is False


def test_is_blocked_ip_non_ip_is_false():
    assert is_blocked_ip("not-an-ip") is False


# ─────────────────────────── classify_target ───────────────────────────

@pytest.mark.parametrize("target", [
    "localhost",
    "foo.local",
    "service.internal",
    "app.localhost",
    "127.0.0.1",
    "10.1.2.3",
    "169.254.169.254",
    "metadata.google.internal",
])
def test_classify_blocks_internal(target):
    allowed, reason = classify_target(target, resolve=False)
    assert allowed is False
    assert reason


@pytest.mark.parametrize("target", ["8.8.8.8", "1.1.1.1"])
def test_classify_allows_public_literal_ip(target):
    allowed, _reason = classify_target(target, resolve=False)
    assert allowed is True


def test_classify_public_hostname_without_resolution_is_allowed():
    # resolve=False skips DNS; a normal hostname passes the literal checks.
    allowed, _reason = classify_target("example.com", resolve=False)
    assert allowed is True


def test_classify_empty_is_blocked():
    allowed, reason = classify_target("", resolve=False)
    assert allowed is False
    assert "invalid" in reason or "empty" in reason


# ─────────────────────────── RateLimiter ───────────────────────────

def test_rate_limiter_allows_within_limit():
    rl = RateLimiter(max_requests=3, window_seconds=60)
    for _ in range(3):
        allowed, retry = rl.check("client-a", now=1000)
        assert allowed is True
        assert retry == 0


def test_rate_limiter_blocks_over_limit():
    rl = RateLimiter(max_requests=2, window_seconds=60)
    rl.check("client-a", now=1000)
    rl.check("client-a", now=1000)
    allowed, retry = rl.check("client-a", now=1000)
    assert allowed is False
    assert retry > 0


def test_rate_limiter_window_resets():
    rl = RateLimiter(max_requests=1, window_seconds=60)
    assert rl.check("client-a", now=1000)[0] is True
    assert rl.check("client-a", now=1000)[0] is False
    # After the window passes, the client is allowed again.
    assert rl.check("client-a", now=1100)[0] is True


def test_rate_limiter_is_per_key():
    rl = RateLimiter(max_requests=1, window_seconds=60)
    assert rl.check("client-a", now=1000)[0] is True
    assert rl.check("client-b", now=1000)[0] is True  # different key, independent


# ─────────────────────────── demo_mode_enabled ───────────────────────────

@pytest.mark.parametrize("value,expected", [
    ("true", True), ("1", True), ("YES", True), ("on", True),
    ("false", False), ("0", False), ("", False),
])
def test_demo_mode_enabled(monkeypatch, value, expected):
    monkeypatch.setenv("DEMO_MODE", value)
    assert demo_mode_enabled() is expected


def test_demo_mode_default_off(monkeypatch):
    monkeypatch.delenv("DEMO_MODE", raising=False)
    assert demo_mode_enabled() is False
