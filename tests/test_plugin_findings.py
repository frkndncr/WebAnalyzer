"""Plugins can report findings by returning {"findings": [...]}: the platform counts
them like any other, without core code knowing the plugin."""
from modules.plugins import security_txt as st
from utils.result_analysis import (
    accumulate_vuln_stats, count_findings, extract_alerts, list_findings, new_vuln_stats,
)

PLUGIN = {"My Plugin": {"findings": [
    {"title": "Open admin panel", "severity": "High", "description": "Reachable without login",
     "location": "https://x.org/admin", "recommendation": "Restrict access"},
    {"type": "Old library", "severity": "low"},
    {"title": "Needs a look"},                      # no severity -> info
]}}


def test_plugin_findings_are_counted_with_their_severity():
    stats = accumulate_vuln_stats(PLUGIN, new_vuln_stats())
    assert (stats["high"], stats["low"], stats["info"], stats["total"]) == (1, 1, 1, 3)
    assert count_findings(PLUGIN) == 3


def test_plugin_findings_are_normalised_and_attributed_to_the_plugin():
    findings = list_findings(PLUGIN)
    admin = next(f for f in findings if f["title"] == "Open admin panel")
    assert admin["module"] == "My Plugin" and admin["severity"] == "high"
    assert admin["location"] == "https://x.org/admin" and admin["recommendation"] == "Restrict access"
    assert next(f for f in findings if f["title"] == "Old library")["severity"] == "low"      # `type` works as a title


def test_plugin_findings_appear_in_alerts_with_a_real_title():
    titles = {a["title"] for a in extract_alerts("x.org", PLUGIN)}
    assert "Open admin panel" in titles and "Old library" in titles


def test_malformed_plugin_findings_are_ignored():
    junk = {"P": {"findings": ["text", None, {"severity": "high"}, {"title": ""}, 5]}}
    assert count_findings(junk) == 0
    assert count_findings({"P": {"findings": "not a list"}}) == 0
    assert count_findings({"P": ["findings"]}) == 0


def test_modules_with_dedicated_handling_do_not_double_count():
    """A builtin module that also happens to carry a `findings` key must not be counted twice."""
    res = {"Security Analysis": {"findings": [{"title": "X", "severity": "high"}],
                                 "vulnerability_scan": {"vulnerabilities": [{"type": "Real", "severity": "high"}]}}}
    assert [f["title"] for f in list_findings(res)] == ["Real"]


def test_results_without_plugins_are_unchanged():
    res = {"DNS Records": {"A": ["1.2.3.4"]}, "Domain Information": {"Domain": "x.org"}}
    assert count_findings(res) == 0


# ─────────────────────────── the Security.txt plugin uses the contract ───────────────────────────

class Resp:
    def __init__(self, status=200, body=""):
        self.status_code, self.content, self.headers, self.raw = status, body.encode(), {}, None


GOOD = "Contact: mailto:a@b.c\nExpires: 2099-01-01T00:00:00Z\n"


def run(table):
    return st.security_txt("example.org", get=lambda url: table[url])


def test_a_missing_file_is_reported_as_an_informational_finding():
    out = run({f"https://example.org{p}": Resp(404) for p in st.PATHS})
    assert [f["severity"] for f in out["findings"]] == ["info"]
    assert out["findings"][0]["title"] == "No security.txt published"
    assert count_findings({"Security.txt": out}) == 1


def test_a_valid_file_reports_nothing():
    out = run({"https://example.org/.well-known/security.txt": Resp(200, GOOD)})
    assert out["found"] is True and out["findings"] == []
    assert count_findings({"Security.txt": out}) == 0


def test_problems_in_the_file_become_low_findings_with_a_location():
    out = run({"https://example.org/.well-known/security.txt": Resp(200, "Contact: mailto:a@b.c\nExpires: 2020-01-01T00:00:00Z\n")})
    assert [f["description"] for f in out["findings"]] == ["The Expires date has passed"]
    found = list_findings({"Security.txt": out})[0]
    assert found["severity"] == "low" and found["location"].endswith("/.well-known/security.txt")
