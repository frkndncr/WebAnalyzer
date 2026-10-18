"""Tests for utils.ownership: which modules need a verified domain, the DNS TXT
proof, and that a failed check is never cached."""
import pytest

from utils import ownership as o


@pytest.fixture(autouse=True)
def fresh_cache():
    o.clear_cache()
    yield
    o.clear_cache()


# ─────────────────────────── module classification ───────────────────────────

def test_the_intrusive_modules_are_the_active_ones():
    assert o.active_modules() == {
        "Advanced Content Scan", "Nmap Zero Day Scan", "Subdomain Takeover", "CloudFlare Bypass",
        "Exposed Files", "Cloud Storage", "DNS Zone Transfer",
    }


def test_split_keeps_order_and_separates_active():
    passive, active = o.split_modules(["DNS Records", "Nmap Zero Day Scan", "SEO Analysis", "Subdomain Takeover"])
    assert passive == ["DNS Records", "SEO Analysis"]
    assert active == ["Nmap Zero Day Scan", "Subdomain Takeover"]


def test_unknown_modules_are_treated_as_passive():
    assert o.split_modules(["Something New"]) == (["Something New"], [])


# ─────────────────────────── token and instructions ───────────────────────────

def test_token_is_stable_and_per_domain():
    assert o.verification_token("example.com") == o.verification_token("example.com")
    assert o.verification_token("example.com") != o.verification_token("example.org")


def test_token_ignores_scheme_case_and_path():
    assert o.verification_token("https://Example.com/login") == o.verification_token("example.com")


def test_a_secret_changes_the_token():
    assert o.verification_token("example.com", secret="a") != o.verification_token("example.com", secret="b")


def test_instructions_name_the_record_to_publish():
    info = o.instructions("https://Example.com/")
    assert info["domain"] == "example.com"
    assert info["record"]["type"] == "TXT"
    assert info["record"]["name"] == "_webanalyzer.example.com"
    assert info["record"]["value"] == "webanalyzer-verify=" + info["token"]


# ─────────────────────────── TXT matching ───────────────────────────

def test_txt_matches_exact_value_even_when_quoted():
    token = o.verification_token("example.com")
    assert o.txt_matches([f"webanalyzer-verify={token}"], token)
    assert o.txt_matches([f'"webanalyzer-verify={token}"'], token)
    assert o.txt_matches(["v=spf1 -all", f"webanalyzer-verify={token}"], token)


def test_txt_does_not_match_a_token_for_another_domain_or_a_partial_value():
    token = o.verification_token("example.com")
    other = o.verification_token("example.org")
    assert not o.txt_matches([f"webanalyzer-verify={other}"], token)
    assert not o.txt_matches([f"webanalyzer-verify={token}extra"], token)
    assert not o.txt_matches([f"prefix webanalyzer-verify={token}"], token)
    assert not o.txt_matches([], token)


# ─────────────────────────── verification ───────────────────────────

def make_resolver(records_by_name, calls=None):
    def resolver(name):
        if calls is not None:
            calls.append(name)
        return records_by_name.get(name, [])
    return resolver


def test_verified_when_the_record_is_published_under_the_label():
    token = o.verification_token("example.com")
    resolver = make_resolver({"_webanalyzer.example.com": [f"webanalyzer-verify={token}"]})
    assert o.is_verified("example.com", resolver=resolver)


def test_verified_when_the_record_is_on_the_apex():
    token = o.verification_token("example.com")
    assert o.is_verified("example.com", resolver=make_resolver({"example.com": [f"webanalyzer-verify={token}"]}))


def test_not_verified_without_a_record_or_with_someone_elses_token():
    assert not o.is_verified("example.com", resolver=make_resolver({}))
    wrong = o.verification_token("example.org")
    assert not o.is_verified("example.com", resolver=make_resolver({"example.com": [f"webanalyzer-verify={wrong}"]}))


def test_empty_input_is_never_verified():
    assert not o.is_verified("", resolver=make_resolver({}))


def test_a_failed_check_is_not_cached_so_a_new_record_is_seen_immediately():
    token = o.verification_token("example.com")
    records = {}
    resolver = make_resolver(records)
    assert not o.is_verified("example.com", resolver=resolver)
    records["_webanalyzer.example.com"] = [f"webanalyzer-verify={token}"]
    assert o.is_verified("example.com", resolver=resolver)


def test_a_success_is_cached_briefly_and_then_rechecked():
    token = o.verification_token("example.com")
    calls = []
    resolver = make_resolver({"_webanalyzer.example.com": [f"webanalyzer-verify={token}"]}, calls)
    assert o.is_verified("example.com", resolver=resolver, now=1000)
    first = len(calls)
    assert o.is_verified("example.com", resolver=resolver, now=1100)      # cached: no new lookups
    assert len(calls) == first
    assert o.is_verified("example.com", resolver=resolver, now=1000 + 601)  # expired: looks again
    assert len(calls) > first


def test_removing_the_record_revokes_verification_after_the_cache_expires():
    token = o.verification_token("example.com")
    records = {"_webanalyzer.example.com": [f"webanalyzer-verify={token}"]}
    resolver = make_resolver(records)
    assert o.is_verified("example.com", resolver=resolver, now=1000)
    records.clear()
    assert not o.is_verified("example.com", resolver=resolver, now=1000 + 601)
