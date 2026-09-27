"""Tests for modules.content_analysis — pure scoring/entropy/classification
logic extracted from the Advanced Content Scanner."""
import math

import pytest

from modules.content_analysis import (
    shannon_entropy,
    risk_score,
    mask_secret,
    short_hash,
    root_domain,
    js_vuln_severity,
)


# ─────────────────────────── shannon_entropy ───────────────────────────

def test_entropy_empty_is_zero():
    assert shannon_entropy("") == 0.0


def test_entropy_uniform_string_is_zero():
    assert shannon_entropy("aaaaaa") == 0.0


def test_entropy_two_symbols_is_one_bit():
    assert shannon_entropy("ab") == pytest.approx(1.0)


def test_entropy_four_distinct_is_two_bits():
    assert shannon_entropy("abcd") == pytest.approx(2.0)


def test_entropy_random_is_higher_than_repetitive():
    assert shannon_entropy("aB3$xZ9!qW") > shannon_entropy("aaaaaaaaaa")


# ─────────────────────────── risk_score ───────────────────────────

def test_risk_score_critical_high_is_capped_at_10():
    assert risk_score("Critical", "HIGH", entropy=0) == 10.0


def test_risk_score_low_low():
    # base 1.5 * conf 0.4 * entr 1.0 + 0.5 = 1.1
    assert risk_score("Low", "LOW", entropy=0) == 1.1


def test_risk_score_unknown_inputs_use_defaults():
    # base 2.0 (unknown sev) * 0.5 (unknown conf) * 1.0 + 0.5 = 1.5
    assert risk_score("???", "???", entropy=0) == 1.5


def test_risk_score_entropy_scales_result():
    high = risk_score("High", "HIGH", entropy=5.0)   # entr_m = 1.0
    low = risk_score("High", "HIGH", entropy=2.5)    # entr_m = 0.5
    assert high > low


def test_risk_score_never_exceeds_10():
    for sev in ("Critical", "High", "Medium", "Low", "Info", "???"):
        for conf in ("HIGH", "MEDIUM", "LOW", "???"):
            score = risk_score(sev, conf, entropy=10.0)
            assert 0.0 <= score <= 10.0


# ─────────────────────────── mask_secret ───────────────────────────

def test_mask_short_secret():
    assert mask_secret("secret") == "se****"


def test_mask_exactly_eight():
    assert mask_secret("12345678") == "12****"


def test_mask_long_secret_keeps_edges():
    assert mask_secret("abcdefghij") == "abcd****ghij"


# ─────────────────────────── short_hash ───────────────────────────

def test_short_hash_is_deterministic_and_short():
    h1 = short_hash("some-finding")
    h2 = short_hash("some-finding")
    assert h1 == h2
    assert len(h1) == 10
    assert all(c in "0123456789abcdef" for c in h1)


def test_short_hash_differs_by_input():
    assert short_hash("a") != short_hash("b")


# ─────────────────────────── root_domain ───────────────────────────

@pytest.mark.parametrize("netloc,expected", [
    ("www.example.com", "example.com"),
    ("example.com", "example.com"),
    ("a.b.c.d", "c.d"),
    ("localhost", "localhost"),
])
def test_root_domain(netloc, expected):
    assert root_domain(netloc) == expected


# ─────────────────────────── js_vuln_severity ───────────────────────────

@pytest.mark.parametrize("cat", ["DOM XSS", "Open Redirect", "Path Traversal", "Taint Flow: Source → Sink"])
def test_js_severity_high(cat):
    assert js_vuln_severity(cat) == "High"


@pytest.mark.parametrize("cat", ["Info Leak", "Missing Header", "unknown-category"])
def test_js_severity_medium_default(cat):
    assert js_vuln_severity(cat) == "Medium"
