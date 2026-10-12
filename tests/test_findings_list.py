"""list_findings: the normalised finding list the CLI reports, which must agree
with the counts the dashboard shows."""
import asyncio
import time

import pytest

from modules import registry
from modules.registry import ModuleSpec
from modules.runner import run_modules
from utils.result_analysis import (
    accumulate_vuln_stats, list_findings, new_vuln_stats, severity_rank,
)

RESULTS = {
    "Security Analysis": {
        "security_headers": {"headers": {
            "Strict-Transport-Security": {"present": False, "importance": "Critical"},
            "X-Frame-Options": {"present": False, "importance": "High"},
        }},
        "vulnerability_scan": {"vulnerabilities": [
            {"type": "Open Redirect", "severity": "Medium", "description": "Redirects anywhere", "recommendation": "Validate targets"},
        ]},
    },
    "Advanced Content Scan": {
        "js_vulnerabilities": [
            {"type": "DOM XSS", "severity": "High", "source_url": "https://x.org/a.js", "line": 12,
             "matched_code": "el.innerHTML = location.hash", "recommendation": "Sanitise"},
            {"severity": "High", "source_url": "https://x.org/b.js"},          # no type
        ],
        "secrets": [{"value": "AKIA...", "url": "https://x.org/config.js"}],   # no severity, no type
    },
    "Phishing Domain Protection": {"phishing_domains": [{"domain": "x-0rg.com", "ips": ["1.2.3.4"], "severity": "High"}]},
}


def test_the_list_has_the_same_size_and_severities_as_the_dashboard_counts():
    findings = list_findings(RESULTS)
    stats = accumulate_vuln_stats(RESULTS, new_vuln_stats())
    assert len(findings) == stats["total"]
    for sev in ("critical", "high", "medium", "low", "info"):
        assert sum(1 for f in findings if f["severity"] == sev) == stats[sev]


def test_most_severe_first_then_by_module_and_title():
    order = [f["severity"] for f in list_findings(RESULTS)]
    assert order == sorted(order, key=severity_rank)
    assert order[0] == "critical"


def test_fields_are_normalised():
    xss = next(f for f in list_findings(RESULTS) if f["title"] == "DOM XSS")
    assert xss["module"] == "Advanced Content Scan"
    assert xss["location"] == "https://x.org/a.js:12"
    assert xss["evidence"] == "el.innerHTML = location.hash"
    assert xss["recommendation"] == "Sanitise"


def test_untyped_entries_get_a_sensible_title_and_default_severity():
    findings = list_findings(RESULTS)
    secret = next(f for f in findings if f["location"] == "https://x.org/config.js")
    assert secret["title"] == "Exposed secret" and secret["severity"] == "high"
    untyped = next(f for f in findings if f["location"] == "https://x.org/b.js")
    assert untyped["title"] == "JavaScript issue"


def test_missing_header_findings_carry_a_description():
    hsts = next(f for f in list_findings(RESULTS) if "Strict-Transport-Security" in f["title"])
    assert hsts["severity"] == "critical" and "not set" in hsts["description"]


def test_empty_and_malformed_input():
    assert list_findings({}) == []
    assert list_findings(None) == []
    assert list_findings({"Security Analysis": "oops"}) == []


def test_evidence_is_capped():
    big = {"Advanced Content Scan": {"js_vulnerabilities": [{"type": "x", "severity": "low", "matched_code": "a" * 5000}]}}
    assert len(list_findings(big)[0]["evidence"]) == 500


# ─────────────────────────── per-module timeout ───────────────────────────

@pytest.fixture
def isolated_registry():
    snapshot = dict(registry._REGISTRY)
    yield
    registry._REGISTRY.clear()
    registry._REGISTRY.update(snapshot)


def test_a_slow_module_is_abandoned_and_the_next_one_still_runs(isolated_registry):
    registry.register(ModuleSpec(name="T Slow", run=lambda d: time.sleep(2) or "late"), replace=True)
    registry.register(ModuleSpec(name="T Quick", run=lambda d: "fast"), replace=True)
    async def timed():
        started = time.time()
        out = await run_modules("x.org", ["T Slow", "T Quick"], timeout=0.2)
        return out, time.time() - started

    # Measured inside the loop: asyncio.run itself still joins the worker thread on
    # shutdown, which is why the CLI exits with os._exit after a timeout.
    out, elapsed = asyncio.run(timed())
    assert out["T Slow"] == {"error": "timed out after 0.2s"}
    assert out["T Quick"] == "fast"
    assert elapsed < 1.0                      # did not wait for the slow module to finish


def test_a_module_raising_its_own_timeout_is_not_mislabelled_without_a_limit(isolated_registry):
    def raises(domain):
        raise TimeoutError("socket timed out")

    registry.register(ModuleSpec(name="T Raises", run=raises), replace=True)
    out = asyncio.run(run_modules("x.org", ["T Raises"]))
    assert out["T Raises"] == {"error": "socket timed out"}


def test_asyncio_run_does_not_wait_for_an_abandoned_module(isolated_registry):
    """Regression: with the loop's default executor, asyncio.run() joined the slow
    worker thread on shutdown, so the CLI hung until the module finished."""
    registry.register(ModuleSpec(name="T Slow2", run=lambda d: time.sleep(2)), replace=True)
    started = time.time()
    out = asyncio.run(run_modules("x.org", ["T Slow2"], timeout=0.2))
    assert out["T Slow2"]["error"].startswith("timed out")
    assert time.time() - started < 1.0

