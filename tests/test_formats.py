"""Output formats: the structured document, exit-code logic, and SARIF that
GitHub Code Scanning will accept (checked against the spec's required fields)."""
import json

import pytest

from utils import formats as f

RESULTS = {
    "Security Analysis": {
        "security_score": {"overall_score": 54, "grade": "F"},
        "security_headers": {"headers": {
            "Strict-Transport-Security": {"present": False, "importance": "Critical"},
        }},
        "vulnerability_scan": {"vulnerabilities": [
            {"type": "Open Redirect", "severity": "Medium", "description": "Redirects | anywhere", "recommendation": "Validate targets"},
        ]},
    },
    "Advanced Content Scan": {
        "js_vulnerabilities": [
            {"type": "DOM XSS", "severity": "High", "source_url": "https://x.org/a.js", "line": 12,
             "matched_code": "el.innerHTML = location.hash", "recommendation": "Sanitise input"},
        ],
    },
    "Phishing Domain Protection": {"phishing_domains": [
        {"domain": "x-0rg.com", "severity": "High"}, {"domain": "xorg.net", "severity": "High"}]},
    "DNS Records": {"error": "resolver down"},
    "GEO Analysis": {},
}

SCAN = {"domain": "x.org", "scanned_at": "2026-10-12T10:00:00+00:00", "duration_seconds": 4.2, "results": RESULTS}


@pytest.fixture
def doc():
    return f.build_document([SCAN], generated_at="2026-10-12T10:00:01+00:00")


# ─────────────────────────── the document ───────────────────────────

def test_document_summarises_each_target(doc):
    target = doc["targets"][0]
    assert doc["tool"]["name"] == "WebAnalyzer"
    assert target["domain"] == "x.org" and target["score"] == 33 and target["grade"] == "F"   # 54 minus 21 for the other modules' findings
    assert target["summary"]["total"] == len(target["findings"]) == 5
    assert target["summary"]["critical"] == 1 and target["summary"]["high"] == 3 and target["summary"]["medium"] == 1


def test_module_status_distinguishes_ok_error_and_empty(doc):
    modules = doc["targets"][0]["modules"]
    assert modules["Security Analysis"] == "ok"
    assert modules["DNS Records"] == "error"
    assert modules["GEO Analysis"] == "empty"


def test_results_can_be_left_out(doc):
    slim = f.build_document([SCAN], include_results=False)
    assert "results" not in slim["targets"][0] and "results" in doc["targets"][0]


def test_the_document_is_json_serialisable(doc):
    assert json.loads(json.dumps(doc))["targets"][0]["domain"] == "x.org"


# ─────────────────────────── exit-code logic ───────────────────────────

@pytest.mark.parametrize("threshold,expected", [
    ("none", False), ("critical", True), ("high", True), ("medium", True), ("low", True), ("info", True),
])
def test_exceeds_with_a_critical_finding_present(doc, threshold, expected):
    assert f.exceeds(doc, threshold) is expected


def test_exceeds_respects_the_threshold():
    only_medium = f.build_document([{"domain": "x.org", "results": {
        "Security Analysis": {"vulnerability_scan": {"vulnerabilities": [{"type": "t", "severity": "Medium"}]}}}}])
    assert f.worst_severity(only_medium) == "medium"
    assert f.exceeds(only_medium, "medium") is True
    assert f.exceeds(only_medium, "high") is False
    assert f.exceeds(only_medium, "critical") is False


def test_no_findings_never_exceeds():
    empty = f.build_document([{"domain": "x.org", "results": {}}])
    assert f.worst_severity(empty) is None
    assert all(f.exceeds(empty, t) is False for t in ("critical", "high", "medium", "low", "info", "none"))


def test_failed_modules_are_counted(doc):
    assert f.failed_modules(doc) == 1


# ─────────────────────────── JSON Lines ───────────────────────────

def test_jsonl_has_one_object_per_target():
    two = f.build_document([SCAN, {**SCAN, "domain": "y.org"}])
    lines = f.to_jsonl_lines(two)
    assert [line["domain"] for line in lines] == ["x.org", "y.org"]
    assert all(line["tool"]["name"] == "WebAnalyzer" for line in lines)


# ─────────────────────────── SARIF ───────────────────────────

def test_sarif_has_the_required_structure(doc):
    sarif = f.to_sarif(doc)
    assert sarif["version"] == "2.1.0" and sarif["$schema"].endswith("sarif-2.1.0.json")
    run = sarif["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "WebAnalyzer" and driver["version"] and driver["informationUri"].startswith("https://")
    assert len(run["results"]) == 5


def test_every_result_points_at_a_defined_rule_and_has_the_fields_github_needs(doc):
    run = f.to_sarif(doc)["runs"][0]
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    for result in run["results"]:
        assert result["ruleId"] in rule_ids
        assert result["level"] in {"error", "warning", "note"}
        assert result["message"]["text"]
        assert result["partialFingerprints"]["webanalyzer/v1"]
        loc = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert "://" in loc


def test_rules_carry_the_numeric_security_severity_github_uses_to_rank_alerts(doc):
    rules = {r["id"]: r for r in f.to_sarif(doc)["runs"][0]["tool"]["driver"]["rules"]}
    xss = rules["WA/advanced-content-scan/dom-xss"]
    assert xss["properties"]["security-severity"] == "8.0" and xss["defaultConfiguration"]["level"] == "error"
    hsts = rules["WA/security-analysis/missing-security-header-strict-transport-security"]
    assert hsts["properties"]["security-severity"] == "9.5"
    redirect = rules["WA/security-analysis/open-redirect"]
    assert redirect["defaultConfiguration"]["level"] == "warning"


def test_levels_map_from_severity():
    assert [f._SARIF_LEVEL[s] for s in f.SEVERITIES] == ["error", "error", "warning", "note", "note"]


def test_a_finding_with_a_url_and_line_gets_a_region(doc):
    results = f.to_sarif(doc)["runs"][0]["results"]
    xss = next(r for r in results if r["ruleId"].endswith("dom-xss"))
    physical = xss["locations"][0]["physicalLocation"]
    assert physical["artifactLocation"]["uri"] == "https://x.org/a.js"
    assert physical["region"] == {"startLine": 12}


def test_a_finding_without_a_location_falls_back_to_the_domain(doc):
    results = f.to_sarif(doc)["runs"][0]["results"]
    hsts = next(r for r in results if "strict-transport" in r["ruleId"])
    assert hsts["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "https://x.org"
    assert "region" not in hsts["locations"][0]["physicalLocation"]


def test_per_item_titles_share_one_rule(doc):
    """Two look-alike domains are two results of one rule, not two rules."""
    run = f.to_sarif(doc)["runs"][0]
    lookalike = [r for r in run["results"] if "look-alike" in r["ruleId"]]
    assert len(lookalike) == 2 and len({r["ruleId"] for r in lookalike}) == 1
    assert len([r for r in run["tool"]["driver"]["rules"] if "look-alike" in r["id"]]) == 1
    assert {r["message"]["text"] for r in lookalike} == {"Look-alike domain: x-0rg.com", "Look-alike domain: xorg.net"}


def test_fingerprints_are_stable_and_distinguish_findings(doc):
    first = [r["partialFingerprints"]["webanalyzer/v1"] for r in f.to_sarif(doc)["runs"][0]["results"]]
    again = [r["partialFingerprints"]["webanalyzer/v1"] for r in f.to_sarif(
        f.build_document([SCAN], generated_at="a later time"))["runs"][0]["results"]]
    assert first == again                  # unaffected by when it ran
    assert len(set(first)) == len(first)   # but distinct per finding


def test_sarif_with_no_findings_is_still_valid():
    sarif = f.to_sarif(f.build_document([{"domain": "x.org", "results": {}}]))
    assert sarif["runs"][0]["results"] == [] and sarif["runs"][0]["tool"]["driver"]["rules"] == []


def test_the_sarif_document_serialises(doc):
    assert json.loads(json.dumps(f.to_sarif(doc)))["version"] == "2.1.0"


# ─────────────────────────── Markdown and text ───────────────────────────

def test_markdown_has_a_table_and_escapes_pipes(doc):
    md = f.to_markdown(doc)
    assert md.startswith("# WebAnalyzer report")
    assert "| Severity | Finding | Module | Location |" in md
    assert "| CRITICAL |" in md
    assert "Security score: **33/100 (F)**" in md
    assert "Modules that failed: DNS Records" in md


def test_markdown_truncates_long_tables():
    many = {"Advanced Content Scan": {"js_vulnerabilities": [{"type": f"Issue {i}", "severity": "low"} for i in range(60)]}}
    md = f.to_markdown(f.build_document([{"domain": "x.org", "results": many}]), limit=10)
    assert "and 50 more" in md and md.count("| LOW |") == 10


def test_markdown_for_a_clean_scan():
    assert "No findings." in f.to_markdown(f.build_document([{"domain": "x.org", "results": {}}]))


def test_text_summary_lists_findings_most_severe_first(doc):
    text = f.to_text(doc)
    lines = text.splitlines()
    assert lines[0].startswith("x.org  score 33/100 (F)  findings 5")
    assert lines[1].lstrip().startswith("CRITICAL")
    assert "modules that failed: DNS Records" in text
