"""Fewer false positives in the existing modules: vendor JS, soft-404 'exposed files',
look-alike domains and takeover severity."""
import asyncio

import pytest

from modules.content_analysis import assess_exposure, is_vendor_script, js_pattern_severity, similar_to_baseline
from modules.phishing_detector import PhishingDetector, severity_for
from utils.result_analysis import list_findings


# ───────────────────────── vendor scripts and pattern severity ─────────────────────────

@pytest.mark.parametrize("url", [
    "https://x.org/wp-includes/js/jquery/jquery.min.js?ver=3.7.1",
    "https://x.org/assets/jquery-3.3.1.min.js",
    "https://x.org/js/bootstrap.bundle.min.js",
    "https://x.org/static/vendor/anything.js",
    "https://x.org/js/lodash.js",
    "https://x.org/js/moment-2.29.4.min.js",
])
def test_library_code_is_recognised(url):
    assert is_vendor_script(url) is True


@pytest.mark.parametrize("url", ["https://x.org/js/app.js", "https://x.org/static/checkout.min.js", "https://x.org/main.4f3a.js"])
def test_the_sites_own_code_is_not_vendor_code(url):
    assert is_vendor_script(url) is False


def test_a_license_banner_marks_a_renamed_library():
    assert is_vendor_script("https://x.org/js/bundle.js", "/*! jQuery v3.6.0 | (c) OpenJS Foundation */") is True


def test_eval_and_proto_alone_are_low_not_high():
    assert js_pattern_severity("Dynamic Code Execution") == "Low"
    assert js_pattern_severity("Prototype Pollution") == "Low"
    assert js_pattern_severity("Insecure postMessage") == "Medium"
    assert js_pattern_severity("DOM XSS") == "High"            # patterns with a user-controlled source stay high
    assert js_pattern_severity("Open Redirect") == "High"


# ───────────────────────── exposed paths ─────────────────────────

ENV = {"path": "/.env", "type": "Environment File", "severity": "Critical"}
SQL = {"path": "/backup.sql", "type": "Database Backup", "severity": "Critical"}
PKG = {"path": "/package.json", "type": "NPM Config", "severity": "Medium"}


def test_access_denied_is_not_an_exposure():
    assert assess_exposure(ENV, 403, "text/html", "Forbidden - you do not have access") is False
    assert assess_exposure(ENV, 401, "", "Unauthorized") is False


def test_a_real_env_file_is_an_exposure_and_a_web_page_is_not():
    assert assess_exposure(ENV, 200, "text/plain", "APP_KEY=base64:abc\nDB_PASSWORD=secret\n") is True
    assert assess_exposure(ENV, 200, "text/html", "<!doctype html><html><body>Welcome back!</body></html>") is False
    assert assess_exposure(ENV, 200, "text/plain", "Sorry, nothing to see on this page.") is False


def test_a_catch_all_page_is_recognised_as_a_soft_404():
    page = "<html><body>Our shop - page not found. Browse the catalogue instead.</body></html>"
    assert assess_exposure(SQL, 200, "text/html", page, baseline=page) is False
    assert similar_to_baseline(page + " ", page) is True and similar_to_baseline("something else entirely", page) is False


def test_database_backup_needs_sql_content():
    assert assess_exposure(SQL, 200, "application/sql", "CREATE TABLE users (id int);\nINSERT INTO users VALUES (1);") is True
    assert assess_exposure(SQL, 200, "text/plain", "This is just some text that is long enough.") is False


def test_package_json_must_be_json_with_a_name():
    assert assess_exposure(PKG, 200, "application/json", '{"name": "shop", "dependencies": {}}') is True
    assert assess_exposure(PKG, 200, "text/html", "<html>nope</html>") is False
    assert assess_exposure(PKG, 200, "application/json", '{"unrelated": 1}') is False


def test_documentation_pages_may_legitimately_be_html():
    docs = {"path": "/swagger-ui.html", "type": "API Docs", "severity": "Medium"}
    assert assess_exposure(docs, 200, "text/html", "<!doctype html><html><title>Swagger UI</title></html>") is True


# ───────────────────────── look-alike domains ─────────────────────────

@pytest.mark.parametrize("kind,same,mx,expected", [
    ("omission", True, True, "Info"),           # resolves to the target's own addresses: defensive registration
    ("omission", False, True, "High"),          # can receive mail as you
    ("keyword", False, False, "High"),          # login-example.com
    ("omission", False, False, "Medium"),
])
def test_lookalike_severity_follows_what_it_can_be_used_for(kind, same, mx, expected):
    assert severity_for(kind, same, mx) == expected


def lookup_for(table):
    return lambda name, rtype="A": table.get((name, rtype), [])


def run_detector(domain, table):
    return asyncio.run(PhishingDetector(domain, lookup=lookup_for(table), write_output=False).run())


def test_ip_addresses_are_skipped_not_scanned_for_typos():
    result = asyncio.run(PhishingDetector("182.93.78.18", lookup=lookup_for({}), write_output=False).run())
    assert result["skipped"] and result["phishing_domains"] == [] and result["total_candidates_scanned"] == 0


def test_live_lookalikes_get_a_severity_and_the_owners_own_registrations_are_info():
    table = {
        ("example.org", "A"): ["192.0.2.1"],
        ("exampl.org", "A"): ["192.0.2.1"],                      # same addresses as the target
        ("exmple.org", "A"): ["203.0.113.5"],                    # somebody else's server
        ("exmple.org", "MX"): ["mail.evil.test."],
        ("login-example.org", "A"): ["203.0.113.9"],             # credential-lure wording
        ("xample.org", "A"): ["203.0.113.7"],                    # registered, nothing special
    }
    result = run_detector("example.org", table)
    by_domain = {d["domain"]: d for d in result["phishing_domains"]}
    assert by_domain["exampl.org"]["severity"] == "Info" and by_domain["exampl.org"]["same_as_target"] is True
    assert by_domain["exmple.org"]["severity"] == "High" and by_domain["exmple.org"]["has_mx"] is True
    assert by_domain["login-example.org"]["severity"] == "High"
    assert by_domain["xample.org"]["severity"] == "Medium"


def test_homoglyph_domains_are_looked_up_as_punycode():
    table = {("example.org", "A"): ["192.0.2.1"], ("еxample.org".encode("idna").decode(), "A"): ["203.0.113.5"]}    # Cyrillic е
    result = run_detector("example.org", table)
    hit = next(d for d in result["phishing_domains"] if d["kind"] == "homoglyph")
    assert hit["punycode"].startswith("xn--") and hit["domain"] == "еxample.org"


def test_info_lookalikes_do_not_count_as_risk_findings():
    res = {"Phishing Domain Protection": {"phishing_domains": [
        {"domain": "a.org", "severity": "Info"}, {"domain": "b.org", "severity": "High"}]}}
    assert [f["severity"] for f in list_findings(res)] == ["high", "info"]


# ───────────────────────── subdomain takeover severity ─────────────────────────

def test_takeover_severity_follows_the_modules_confidence_when_none_is_given():
    res = {"Subdomain Takeover": {"vulnerable_subdomains": [
        {"subdomain": "a.x.org", "confidence": "High"},
        {"subdomain": "b.x.org", "confidence": "Medium"},
        {"subdomain": "c.x.org", "confidence": "Low"},
        {"subdomain": "d.x.org"},
        {"subdomain": "e.x.org", "confidence": "Low", "severity": "Critical"},
    ]}}
    got = {f["title"]: f["severity"] for f in list_findings(res)}
    assert got == {"Subdomain takeover: a.x.org": "high", "Subdomain takeover: b.x.org": "medium",
                   "Subdomain takeover: c.x.org": "low", "Subdomain takeover: d.x.org": "high",
                   "Subdomain takeover: e.x.org": "critical"}
