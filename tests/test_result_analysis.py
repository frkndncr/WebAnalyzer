"""Tests for utils.result_analysis — the pure logic behind the dashboard's
recent-scans, vulnerability-stats and recent-alerts endpoints."""
import pytest

from utils.result_analysis import (
    summarize_security_result,
    new_vuln_stats,
    accumulate_vuln_stats,
    extract_alerts,
    sort_and_dedupe_alerts,
    iter_findings,
)


# ─────────────────────────── summarize_security_result ───────────────────────────

def test_summarize_object_score():
    """A dict-shaped security_score is normalised to its overall_score number."""
    res = {"Security Analysis": {"security_score": {"overall_score": 54, "grade": "F"}}}
    score, grade, vulns = summarize_security_result(res)
    assert score == 54
    assert grade == "F"
    assert vulns == 0


def test_summarize_numeric_score():
    res = {"Security Analysis": {"security_score": 87, "security_grade": "B", "vulnerabilities_found": 3}}
    score, grade, vulns = summarize_security_result(res)
    assert score == 87
    assert grade == "B"
    assert vulns == 3


def test_summarize_missing_security_module():
    score, grade, vulns = summarize_security_result({"DNS Records": {}})
    assert score is None
    assert grade is None
    assert vulns == 0


@pytest.mark.parametrize("bad", [None, [], "text", 42])
def test_summarize_non_dict_input_is_safe(bad):
    assert summarize_security_result(bad) == (None, None, 0)


def test_summarize_bool_score_not_treated_as_number():
    # True is an int subclass; it must not be reported as a score of 1.
    res = {"Security Analysis": {"security_score": True}}
    score, _grade, _vulns = summarize_security_result(res)
    assert score is None


# ─────────────────────────── vulnerability stats ───────────────────────────

def test_new_vuln_stats_is_zeroed():
    stats = new_vuln_stats()
    assert stats == {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}


def test_accumulate_counts_both_modules():
    res = {
        "Security Analysis": {"vulnerabilities": [
            {"severity": "High"}, {"severity": "critical"}, {"severity": "high"},
        ]},
        "Advanced Content Scan": {
            "secrets": [{"severity": "medium"}],
            "js_vulnerabilities": [{"severity": "LOW"}, {"severity": "high"}],
            "ssrf_vulnerabilities": [{}],  # missing severity -> defaults to medium
        },
    }
    stats = accumulate_vuln_stats(res, new_vuln_stats())
    assert stats["critical"] == 1
    assert stats["high"] == 4    # 3 explicit + the SSRF entry (defaults to high)
    assert stats["medium"] == 1
    assert stats["low"] == 1
    assert stats["total"] == 7


def test_accumulate_is_additive_across_domains():
    stats = new_vuln_stats()
    accumulate_vuln_stats({"Security Analysis": {"vulnerabilities": [{"severity": "high"}]}}, stats)
    accumulate_vuln_stats({"Security Analysis": {"vulnerabilities": [{"severity": "high"}]}}, stats)
    assert stats["high"] == 2
    assert stats["total"] == 2


def test_accumulate_ignores_malformed():
    stats = accumulate_vuln_stats({"Security Analysis": {"vulnerabilities": ["notadict", None]}}, new_vuln_stats())
    assert stats["total"] == 0


def test_unknown_severity_is_counted_as_info():
    stats = accumulate_vuln_stats(
        {"Security Analysis": {"vulnerabilities": [{"severity": "catastrophic"}]}}, new_vuln_stats()
    )
    assert stats["total"] == 1
    assert stats["info"] == 1


# ─────────────────────────── alerts ───────────────────────────

def test_extract_alerts_shape():
    res = {"Security Analysis": {"vulnerabilities": [
        {"type": "SQL Injection", "severity": "critical", "description": "x" * 200},
    ]}}
    alerts = extract_alerts("example.com", res)
    assert len(alerts) == 1
    a = alerts[0]
    assert a["domain"] == "example.com"
    assert a["title"] == "SQL Injection"
    assert a["severity"] == "CRITICAL"
    assert a["module"] == "Security Analysis"
    assert len(a["description"]) == 120  # truncated


def test_extract_alerts_acs_key_fallback_title():
    res = {"Advanced Content Scan": {"active_vulnerabilities": [{"severity": "high"}]}}
    alerts = extract_alerts("example.com", res)
    assert alerts[0]["title"] == "Active Vulnerabilities"
    assert alerts[0]["module"] == "Advanced Content Scan"


def test_extract_alerts_handles_none_description():
    res = {"Security Analysis": {"vulnerabilities": [{"type": "X", "description": None}]}}
    alerts = extract_alerts("example.com", res)
    assert alerts[0]["description"] == ""


def test_sort_and_dedupe_orders_by_severity():
    alerts = [
        {"domain": "d", "title": "low-one", "severity": "LOW"},
        {"domain": "d", "title": "crit-one", "severity": "CRITICAL"},
        {"domain": "d", "title": "med-one", "severity": "MEDIUM"},
    ]
    ordered = sort_and_dedupe_alerts(alerts)
    assert [a["title"] for a in ordered] == ["crit-one", "med-one", "low-one"]


def test_sort_and_dedupe_removes_duplicates():
    alerts = [
        {"domain": "d", "title": "same", "severity": "HIGH"},
        {"domain": "d", "title": "same", "severity": "HIGH"},
        {"domain": "e", "title": "same", "severity": "HIGH"},
    ]
    result = sort_and_dedupe_alerts(alerts)
    assert len(result) == 2  # (d, same) and (e, same)


def test_sort_and_dedupe_respects_limit():
    alerts = [{"domain": "d", "title": f"t{i}", "severity": "HIGH"} for i in range(30)]
    assert len(sort_and_dedupe_alerts(alerts, limit=15)) == 15


# ─────────────────────────── iter_findings ───────────────────────────

def test_iter_findings_on_empty_is_empty():
    assert list(iter_findings({})) == []
    assert list(iter_findings(None)) == []


# ─────────────── real scanner output, domain normalisation, aggregation ───────────────

from utils.result_analysis import (  # noqa: E402
    count_findings,
    normalize_domain,
    domain_variants,
    latest_per_domain,
    average_score,
)


def test_findings_under_vulnerability_scan_are_counted():
    """The scanner stores findings in Security Analysis.vulnerability_scan."""
    res = {"Security Analysis": {"vulnerability_scan": {"vulnerabilities": [
        {"type": "Open Redirect", "severity": "High"},
        {"type": "Weak Cipher", "severity": "Medium"},
    ]}}}
    stats = accumulate_vuln_stats(res, new_vuln_stats())
    assert stats["high"] == 1 and stats["medium"] == 1 and stats["total"] == 2
    assert count_findings(res) == 2


def test_summarize_counts_real_findings_across_modules():
    res = {
        "Security Analysis": {
            "security_score": {"overall_score": 54, "grade": "F"},
            "vulnerability_scan": {"vulnerabilities": [{"severity": "high"}]},
        },
        "Advanced Content Scan": {"js_vulnerabilities": [{"severity": "high"}, {"severity": "medium"}]},
    }
    score, grade, vulns = summarize_security_result(res)
    assert (score, grade, vulns) == (44, "F", 3)      # 54 minus 10 for the Advanced Content Scan findings


def test_alerts_include_vulnerability_scan_findings():
    res = {"Security Analysis": {"vulnerability_scan": {"vulnerabilities": [
        {"type": "CORS Misconfiguration", "severity": "high", "description": "Wildcard origin"},
    ]}}}
    alerts = extract_alerts("example.com", res)
    assert alerts[0]["title"] == "CORS Misconfiguration"
    assert alerts[0]["severity"] == "HIGH"


@pytest.mark.parametrize("raw,expected", [
    ("https://Example.com/", "example.com"),
    ("example.com", "example.com"),
    ("http://sub.example.com:8080/x", "sub.example.com"),
    ("", ""),
])
def test_normalize_domain(raw, expected):
    assert normalize_domain(raw) == expected


def test_domain_variants_cover_legacy_spellings():
    v = domain_variants("example.com")
    assert v[0] == "example.com"
    assert "https://example.com/" in v and "http://example.com" in v


def test_domain_variants_empty():
    assert domain_variants("") == []


def test_latest_per_domain_merges_spellings_and_keeps_newest():
    rows = [
        {"id": 3, "domain": "https://a.com/", "scan_date": "2026-03"},
        {"id": 2, "domain": "b.com", "scan_date": "2026-02"},
        {"id": 1, "domain": "a.com", "scan_date": "2026-01"},
    ]
    out = latest_per_domain(rows)
    assert [r["name"] for r in out] == ["a.com", "b.com"]
    assert out[0]["id"] == 3  # the newest scan of a.com wins


def test_latest_per_domain_drops_unusable_rows():
    assert latest_per_domain([{"domain": ""}, {"domain": None}]) == []


def test_average_score():
    assert average_score([50, 70, None, "x"]) == 60
    assert average_score([]) is None
    assert average_score([True]) is None


# ─────────────── findings beyond explicit vulnerabilities (parity with the dashboard) ───────────────

from utils.result_analysis import severity_bucket  # noqa: E402

REAL_SHAPE = {
    "Security Analysis": {
        "security_headers": {"headers": {
            "Strict-Transport-Security": {"present": False, "importance": "Critical"},
            "X-Frame-Options": {"present": False, "importance": "High"},
            "X-Content-Type-Options": {"present": True, "importance": "Medium"},
            "Referrer-Policy": {"present": False, "importance": "Low"},
        }},
        "server_information": {"information_disclosure": ["Web server version disclosed"]},
        "http_methods": {"dangerous_methods": ["TRACE"]},
        "cors_policy": {"issues": ["Wildcard origin"]},
        "ssl_analysis": {"ssl_available": False},
    },
    "Advanced Content Scan": {
        "exposed_endpoints": [{"endpoint_type": "Robots File", "status_code": 200, "severity": "Info"}],
    },
    "Subdomain Takeover": {"vulnerable_subdomains": [{"subdomain": "old.x.com"}]},
    "Phishing Domain Protection": {"phishing_domains": [{"domain": "x-c0m.com", "severity": "High"}]},
    "Web Archive Spy": {"secrets": [{"type": "aws_key"}]},
    "CloudFlare Bypass": {"cloudflare_protected": True, "real_ips": [{"ip": "9.9.9.9", "source": "history"}]},
}


def test_security_signals_are_findings():
    titles = [alert["title"] for alert in extract_alerts("x.com", REAL_SHAPE)]
    assert "Missing security header: Strict-Transport-Security" in titles
    assert "Missing security header: X-Frame-Options" in titles
    assert not any("X-Content-Type-Options" in t for t in titles)   # present, so not a finding
    assert "Information disclosure" in titles
    assert "Dangerous HTTP method enabled: TRACE" in titles
    assert "CORS misconfiguration" in titles
    assert "TLS is not available" in titles


def test_other_modules_contribute_findings():
    titles = [alert["title"] for alert in extract_alerts("x.com", REAL_SHAPE)]
    assert "Robots File exposed" in titles
    assert "Subdomain takeover: old.x.com" in titles
    assert "Look-alike domain: x-c0m.com" in titles
    assert "Historical secret: aws_key" in titles
    assert "Origin IP exposed behind CloudFlare" in titles


def test_header_importance_maps_to_severity():
    stats = accumulate_vuln_stats(
        {"Security Analysis": {"security_headers": {"headers": {
            "A": {"present": False, "importance": "Critical"},
            "B": {"present": False, "importance": "High"},
            "C": {"present": False, "importance": "Medium"},
            "D": {"present": False, "importance": "Low"},
        }}}}, new_vuln_stats())
    assert (stats["critical"], stats["high"], stats["medium"], stats["low"]) == (1, 1, 1, 1)


def test_cloudflare_direct_dns_is_not_a_finding():
    res = {"CloudFlare Bypass": {"cloudflare_protected": True, "real_ips": [{"ip": "1.1.1.1", "source": "direct_dns"}]}}
    assert count_findings(res) == 0
    assert count_findings({"CloudFlare Bypass": {"cloudflare_protected": False, "real_ips": [{"ip": "1.1.1.1", "source": "history"}]}}) == 0


def test_count_findings_matches_total_stats():
    assert count_findings(REAL_SHAPE) == accumulate_vuln_stats(REAL_SHAPE, new_vuln_stats())["total"]


@pytest.mark.parametrize("raw,bucket", [
    ("Critical", "critical"), ("HIGH", "high"), ("moderate", "info"), ("Medium", "medium"),
    ("low", "low"), ("Informational", "info"), (None, "info"), ("", "info"),
])
def test_severity_bucket(raw, bucket):
    assert severity_bucket(raw) == bucket
