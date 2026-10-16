"""The client report and the CWE/OWASP mapping behind it."""
import re

from utils import formats, report
from utils.taxonomy import classify

RESULTS = {
    "Security Analysis": {
        "security_score": {"overall_score": 54, "grade": "F"},
        "security_headers": {"headers": {"Strict-Transport-Security": {"present": False, "importance": "Critical"}}},
        "vulnerability_scan": {"vulnerabilities": [
            {"type": "Open Redirect", "severity": "Medium", "description": "Redirects <b>anywhere</b>", "recommendation": "Validate targets"},
        ]},
    },
    "Advanced Content Scan": {"js_vulnerabilities": [
        {"type": "DOM XSS", "severity": "High", "source_url": "https://x.org/a.js", "line": 12, "matched_code": "el.innerHTML = location.hash"}]},
    "DNS Records": {"error": "resolver down"},
}


def make(**options):
    return report.build_report("x.org", RESULTS, **options)


def test_report_matches_the_shared_finding_counts():
    doc = formats.build_document([{"domain": "x.org", "results": RESULTS}], include_results=False)
    html_out = make()
    total = doc["targets"][0]["summary"]["total"]
    assert f"<b>{total}</b> finding(s)" in html_out
    assert html_out.count('class="finding"') == total


def test_report_has_cover_summary_details_and_appendix():
    out = make(client="Acme Corp", author="C4 Software Studio", title="Q4 Assessment")
    for text in ("Q4 Assessment", "Prepared for Acme Corp", "by C4 Software Studio", "1. Executive summary",
                 "2. Findings overview", "3. Findings in detail", "Appendix A. Modules", "WA-001"):
        assert text in out
    assert "Failed" in out                                  # the DNS module error is shown, not hidden


def test_everything_user_controlled_is_escaped():
    out = make(client='<script>alert(1)</script>', author='"><img src=x onerror=1>', title="<i>t</i>")
    assert "<script>alert(1)</script>" not in out and "<img src=x" not in out and "<i>t</i>" not in out
    assert "&lt;script&gt;" in out
    assert "<b>anywhere</b>" not in out                      # a finding description is escaped too


def test_findings_are_classified_and_never_get_a_made_up_cvss():
    out = make()
    assert "CWE-319" in out and "CWE-79" in out and "CWE-601" in out
    assert not re.search(r"CVSS:\d", out) and "No CVSS vector is calculated" in out


def test_clean_scan_reads_as_clean():
    out = report.build_report("clean.org", {"DNS Records": {"A": ["1.2.3.4"]}})
    assert "No findings were reported" in out and "<b>0</b> finding(s)" in out


def test_taxonomy_is_conservative():
    assert classify("Missing security header: Strict-Transport-Security")["cwe"] == "CWE-319"
    assert classify("Missing X-Frame-Options")["owasp"].startswith("A05")
    assert classify("Reflected XSS in search")["cwe"] == "CWE-79"
    assert classify("Something entirely unrelated") is None
    assert classify("CSRF token missing") is None            # not guessed as a hard-coded credential


def test_generate_executive_report_still_works_for_the_api_and_main():
    from modules.report_generator import generate_executive_report
    assert "Security Assessment Report" in generate_executive_report("https://x.org/path", RESULTS)
