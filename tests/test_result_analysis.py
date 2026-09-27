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
    assert stats["high"] == 3
    assert stats["medium"] == 2  # one explicit + one defaulted
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


def test_unknown_severity_still_counts_total():
    stats = accumulate_vuln_stats(
        {"Security Analysis": {"vulnerabilities": [{"severity": "catastrophic"}]}}, new_vuln_stats()
    )
    assert stats["total"] == 1
    assert sum(stats[k] for k in ("critical", "high", "medium", "low", "info")) == 0


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
