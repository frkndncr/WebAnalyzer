"""HTTP-level tests: reading data must never start a scan, and every path that
does start one must go through the demo guards (SSRF block + rate limit).

These import the real FastAPI app, so they are skipped where the API
dependencies are not installed (CI installs them via requirements.txt).
"""
import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

import api  # noqa: E402
from utils.safety import RateLimiter  # noqa: E402

PUBLIC = "example.org"
READ_ENDPOINTS = ["/api/network-map/{d}", "/api/threat-intel/{d}"]


@pytest.fixture
def client(monkeypatch):
    """A client with the scan runner replaced by a spy and no stored results."""
    started = []
    runs = []

    async def fake_runner(domain, modules, functions):
        started.append(domain)
        runs.append((domain, list(modules)))

    monkeypatch.setattr(api, "run_scan_background", fake_runner)
    monkeypatch.setattr(api, "load_results_from_file_or_db", lambda d: None)
    monkeypatch.setattr(api, "_SCAN_RATE_LIMITER", RateLimiter(max_requests=100, window_seconds=60))
    api.ACTIVE_SCANS.clear()
    c = TestClient(api.app)
    c.started = started
    c.runs = runs
    yield c
    api.ACTIVE_SCANS.clear()


@pytest.mark.parametrize("template", READ_ENDPOINTS)
@pytest.mark.parametrize("demo", ["true", "false"])
def test_plain_get_never_starts_a_scan(client, monkeypatch, template, demo):
    monkeypatch.setenv("DEMO_MODE", demo)
    r = client.get(template.format(d=PUBLIC))
    assert r.status_code == 200
    body = r.json()
    assert body["has_data"] is False
    assert body["is_scanning"] is False
    assert client.started == []
    assert PUBLIC not in api.ACTIVE_SCANS


@pytest.mark.parametrize("template", READ_ENDPOINTS)
@pytest.mark.parametrize("target", ["127.0.0.1", "169.254.169.254", "localhost", "10.0.0.5"])
def test_explicit_scan_of_internal_target_is_blocked_in_demo_mode(client, monkeypatch, template, target):
    monkeypatch.setenv("DEMO_MODE", "true")
    r = client.get(template.format(d=target) + "?scan=true")
    assert r.status_code == 403
    assert client.started == []
    assert target not in api.ACTIVE_SCANS


@pytest.mark.parametrize("template", READ_ENDPOINTS)
def test_force_is_guarded_too(client, monkeypatch, template):
    monkeypatch.setenv("DEMO_MODE", "true")
    assert client.get(template.format(d="127.0.0.1") + "?force=true").status_code == 403
    assert client.started == []


@pytest.mark.parametrize("template", READ_ENDPOINTS)
def test_explicit_scan_of_public_target_starts_once(client, monkeypatch, template):
    monkeypatch.setenv("DEMO_MODE", "true")
    r = client.get(template.format(d=PUBLIC) + "?scan=true")
    assert r.status_code == 200
    assert r.json()["is_scanning"] is True
    assert client.started == [PUBLIC]


def test_self_hosted_mode_still_allows_internal_targets(client, monkeypatch):
    monkeypatch.setenv("DEMO_MODE", "false")
    r = client.get("/api/network-map/192.168.1.10?scan=true")
    assert r.status_code == 200
    assert client.started == ["192.168.1.10"]


def test_explicit_scans_are_rate_limited_in_demo_mode(client, monkeypatch):
    monkeypatch.setenv("DEMO_MODE", "true")
    monkeypatch.setattr(api, "_SCAN_RATE_LIMITER", RateLimiter(max_requests=1, window_seconds=60))
    assert client.get("/api/network-map/a.example.org?scan=true").status_code == 200
    second = client.get("/api/network-map/b.example.org?scan=true")
    assert second.status_code == 429
    assert "Retry-After" in second.headers
    assert client.started == ["a.example.org"]


def test_in_progress_scan_reports_progress_without_a_flag(client):
    api.ACTIVE_SCANS[PUBLIC] = {"total": 16, "completed": 7, "current_module": "Subdomain Discovery", "results": {}}
    body = client.get(f"/api/network-map/{PUBLIC}").json()
    assert body["is_scanning"] is True
    assert body["scan_progress"] == {"total": 16, "completed": 7, "current_module": "Subdomain Discovery"}
    assert client.started == []


def test_existing_results_are_served_without_any_flag(client, monkeypatch):
    stored = {"Security Analysis": {"security_score": {"overall_score": 61, "grade": "D"}}}
    monkeypatch.setattr(api, "load_results_from_file_or_db", lambda d: stored)
    body = client.get(f"/api/threat-intel/{PUBLIC}").json()
    assert body["has_data"] is True
    assert body["is_scanning"] is False
    assert client.started == []


def test_post_scan_remains_guarded(client, monkeypatch):
    monkeypatch.setenv("DEMO_MODE", "true")
    blocked = client.post("/api/scan", json={"domain": "127.0.0.1", "modules": ["DNS Records"]})
    assert blocked.status_code == 403
    ok = client.post("/api/scan", json={"domain": PUBLIC, "modules": ["DNS Records"]})
    assert ok.status_code == 200


# ─────────────────────────── database status in the health check ───────────────────────────

def test_health_reports_database_status_without_a_host(client, monkeypatch):
    pytest.importorskip("mysql.connector")
    from database import db_manager as dbm

    monkeypatch.setattr(dbm.db_manager, "status",
                        lambda: {"connected": False, "error": "too_many_connections", "retry_in": 12})
    body = client.get("/api/system-health").json()
    assert body["api_status"] == "online"
    assert body["database"] == {"connected": False, "error": "too_many_connections", "retry_in": 12}


def test_health_stays_up_when_the_status_probe_itself_fails(client, monkeypatch):
    pytest.importorskip("mysql.connector")
    from database import db_manager as dbm

    def boom():
        raise RuntimeError("probe exploded")

    monkeypatch.setattr(dbm.db_manager, "status", boom)
    body = client.get("/api/system-health").json()
    assert body["api_status"] == "online"
    assert body["database"]["connected"] is False


# ─────────────────────────── ownership verification for the active modules ───────────────────────────

from utils.ownership import ACTIVE_MODULES  # noqa: E402

PASSIVE_ONLY = ["DNS Records", "SEO Analysis"]
MIXED = ["DNS Records", "Nmap Zero Day Scan", "SEO Analysis", "Subdomain Takeover"]


@pytest.fixture
def demo(client, monkeypatch):
    """Demo mode, with the domain NOT verified unless a test says otherwise."""
    monkeypatch.setenv("DEMO_MODE", "true")
    monkeypatch.setattr(api, "is_verified", lambda d: False)
    return client


def test_unverified_domain_runs_only_the_passive_modules(demo):
    r = demo.post("/api/scan", json={"domain": PUBLIC, "modules": MIXED})
    assert r.status_code == 200
    body = r.json()
    assert body["modules"] == ["DNS Records", "SEO Analysis"]
    assert body["skipped"] == ["Nmap Zero Day Scan", "Subdomain Takeover"]
    assert body["verification"]["record"]["name"] == f"_webanalyzer.{PUBLIC}"
    assert demo.runs == [(PUBLIC, ["DNS Records", "SEO Analysis"])]


def test_progress_total_counts_only_what_will_run(demo):
    demo.post("/api/scan", json={"domain": PUBLIC, "modules": MIXED})
    assert api.ACTIVE_SCANS[PUBLIC]["total"] == 2
    assert api.ACTIVE_SCANS[PUBLIC]["skipped"] == ["Nmap Zero Day Scan", "Subdomain Takeover"]


def test_asking_only_for_active_modules_is_refused_with_instructions(demo):
    r = demo.post("/api/scan", json={"domain": PUBLIC, "modules": ["Nmap Zero Day Scan"]})
    assert r.status_code == 403
    detail = r.json()["detail"]
    assert detail["code"] == "verification_required"
    assert detail["verification"]["record"]["type"] == "TXT"
    assert demo.runs == []


def test_verified_domain_runs_everything(demo, monkeypatch):
    monkeypatch.setattr(api, "is_verified", lambda d: True)
    r = demo.post("/api/scan", json={"domain": PUBLIC, "modules": MIXED})
    assert r.json()["modules"] == MIXED
    assert r.json()["skipped"] == []
    assert r.json()["verification"] is None


def test_passive_only_requests_never_need_a_dns_lookup(demo, monkeypatch):
    def boom(d):
        raise AssertionError("no verification lookup should happen")
    monkeypatch.setattr(api, "is_verified", boom)
    assert demo.post("/api/scan", json={"domain": PUBLIC, "modules": PASSIVE_ONLY}).status_code == 200


def test_self_hosted_mode_is_unrestricted_and_does_not_look_anything_up(client, monkeypatch):
    monkeypatch.setenv("DEMO_MODE", "false")

    def boom(d):
        raise AssertionError("self-hosted must not require verification")
    monkeypatch.setattr(api, "is_verified", boom)
    r = client.post("/api/scan", json={"domain": PUBLIC, "modules": MIXED})
    assert r.json()["modules"] == MIXED and r.json()["skipped"] == []


@pytest.mark.parametrize("template", READ_ENDPOINTS)
def test_the_get_scan_paths_skip_active_modules_when_unverified(demo, template):
    assert demo.get(template.format(d=PUBLIC) + "?scan=true").status_code == 200
    _domain, modules = demo.runs[0]
    assert not set(modules) & ACTIVE_MODULES
    assert len(modules) == len(api.MODULE_NAMES) - len(ACTIVE_MODULES)


@pytest.mark.parametrize("template", READ_ENDPOINTS)
def test_the_get_scan_paths_run_everything_when_verified(demo, monkeypatch, template):
    monkeypatch.setattr(api, "is_verified", lambda d: True)
    demo.get(template.format(d=PUBLIC) + "?scan=true")
    assert demo.runs[0][1] == list(api.MODULE_NAMES)


@pytest.mark.parametrize("url,body", [
    ("/api/scan/section", {"domain": PUBLIC, "section": "overview"}),
    ("/api/scan/acs-all", {"domain": PUBLIC}),
])
def test_the_content_scanner_endpoints_need_verification_in_demo_mode(demo, monkeypatch, url, body):
    r = demo.post(url, json=body)
    assert r.status_code == 403
    assert r.json()["detail"]["code"] == "verification_required"
    monkeypatch.setattr(api, "is_verified", lambda d: True)
    assert demo.post(url, json=body).status_code == 200


def test_every_scan_path_is_covered_by_a_test_here():
    """If a new route starts scans, this list must grow with it."""
    import inspect
    source = inspect.getsource(api)
    assert source.count("add_task(run_scan_background") == 3
    assert source.count("await require_verified(") == 2


# ─────────────────────────── GET /api/verify ───────────────────────────

def test_verify_reports_state_and_the_record_to_publish(demo, monkeypatch):
    body = demo.get(f"/api/verify/{PUBLIC}").json()
    assert body["verified"] is False and body["required"] is True
    assert body["record"]["name"] == f"_webanalyzer.{PUBLIC}"
    assert body["record"]["value"].startswith("webanalyzer-verify=")
    assert set(body["active_modules"]) == set(ACTIVE_MODULES)
    monkeypatch.setattr(api, "is_verified", lambda d: True)
    assert demo.get(f"/api/verify/{PUBLIC}").json()["verified"] is True


def test_verify_normalises_the_input(demo):
    assert demo.get("/api/verify/Example.ORG").json()["domain"] == "example.org"


def test_verify_refuses_internal_names_in_demo_mode(demo):
    assert demo.get("/api/verify/localhost").status_code == 403
    assert demo.get("/api/verify/10.0.0.5").status_code == 403


def test_verify_is_rate_limited_in_demo_mode(demo, monkeypatch):
    monkeypatch.setattr(api, "_VERIFY_RATE_LIMITER", RateLimiter(max_requests=1, window_seconds=60))
    assert demo.get(f"/api/verify/{PUBLIC}").status_code == 200
    second = demo.get(f"/api/verify/{PUBLIC}")
    assert second.status_code == 429 and "Retry-After" in second.headers


def test_health_says_whether_this_is_a_demo(client, monkeypatch):
    pytest.importorskip("mysql.connector")
    from database import db_manager as dbm
    monkeypatch.setattr(dbm.db_manager, "status", lambda: {"connected": True, "error": None, "retry_in": 0})
    monkeypatch.setenv("DEMO_MODE", "true")
    assert client.get("/api/system-health").json()["demo_mode"] is True
    monkeypatch.setenv("DEMO_MODE", "false")
    assert client.get("/api/system-health").json()["demo_mode"] is False
