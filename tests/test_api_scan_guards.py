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

    async def fake_runner(domain, modules, functions):
        started.append(domain)

    monkeypatch.setattr(api, "run_scan_background", fake_runner)
    monkeypatch.setattr(api, "load_results_from_file_or_db", lambda d: None)
    monkeypatch.setattr(api, "_SCAN_RATE_LIMITER", RateLimiter(max_requests=100, window_seconds=60))
    api.ACTIVE_SCANS.clear()
    c = TestClient(api.app)
    c.started = started
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
