"""The shared module runner: threads vs the event loop, results passing, error
isolation, and the Attack Path Planner regression."""
import asyncio

import pytest

from modules import registry
from modules.registry import ModuleSpec
from modules.runner import run_module, run_modules


@pytest.fixture(autouse=True)
def isolated_registry():
    snapshot = dict(registry._REGISTRY)
    yield
    registry._REGISTRY.clear()
    registry._REGISTRY.update(snapshot)


def add(name, fn, **options):
    registry.register(ModuleSpec(name=name, run=fn, **options), replace=True)


def test_a_sync_module_runs_off_the_event_loop():
    import threading
    seen = {}

    def work(domain):
        seen["worker"] = threading.current_thread() is not threading.main_thread()
        return domain.upper()

    add("T Sync", work)
    assert asyncio.run(run_module(registry.get("T Sync"), "example.org")) == "EXAMPLE.ORG"
    assert seen["worker"] is True


def test_a_coroutine_module_is_awaited():
    async def work(domain):
        await asyncio.sleep(0)
        return {"d": domain}

    add("T Async", work)
    assert asyncio.run(run_module(registry.get("T Async"), "x.org")) == {"d": "x.org"}


def test_a_sync_function_returning_an_awaitable_is_awaited():
    async def inner(domain):
        return "inner:" + domain

    add("T Awaitable", lambda d: inner(d))
    assert asyncio.run(run_module(registry.get("T Awaitable"), "x.org")) == "inner:x.org"


def test_runs_in_loop_modules_are_called_on_the_loop_thread():
    import threading
    seen = {}

    def work(domain):
        seen["main"] = threading.current_thread() is threading.main_thread()
        return 1

    add("T Loop", work, runs_in_loop=True)
    asyncio.run(run_module(registry.get("T Loop"), "x.org"))
    assert seen["main"] is True


def test_needs_results_modules_receive_what_ran_before():
    add("T First", lambda d: {"found": 3})
    add("T Second", lambda d, results: {"saw": results.get("T First")}, needs_results=True)
    out = asyncio.run(run_modules("x.org", ["T First", "T Second"]))
    assert out["T Second"] == {"saw": {"found": 3}}


def test_a_failing_module_does_not_stop_the_others():
    def boom(domain):
        raise RuntimeError("it broke")

    add("T Boom", boom)
    add("T Fine", lambda d: "fine")
    out = asyncio.run(run_modules("x.org", ["T Boom", "T Fine"]))
    assert out["T Boom"] == {"error": "it broke"}
    assert out["T Fine"] == "fine"


def test_unknown_names_are_skipped_and_order_is_kept():
    add("T One", lambda d: 1)
    add("T Two", lambda d: 2)
    out = asyncio.run(run_modules("x.org", ["T Two", "Does Not Exist", "T One"]))
    assert list(out) == ["T Two", "T One"]


def test_progress_callbacks_fire_in_order():
    add("T One", lambda d: 1)
    add("T Two", lambda d: 2)
    events = []
    asyncio.run(run_modules("x.org", ["T One", "T Two"],
                            on_start=lambda n: events.append(("start", n)),
                            on_done=lambda n, r: events.append(("done", n, r))))
    assert events == [("start", "T One"), ("done", "T One", 1), ("start", "T Two"), ("done", "T Two", 2)]


def test_attack_path_planner_now_sees_the_other_modules_findings(tmp_path, monkeypatch):
    """Regression: the planner used to be called without the scan results (its
    special case compared against the wrong name), so every domain got the same
    generic recon-only path no matter what the scan found."""
    from modules import builtin
    builtin.register_builtin_modules()
    monkeypatch.chdir(tmp_path)
    findings = {
        "DNS Records": {"A": ["1.2.3.4"]},
        "Subdomain Discovery": ["a.x.org", "b.x.org"],
    }
    result = asyncio.run(run_module(registry.get("Attack Path Planner"), "x.org", findings))
    labels = [n["label"] for n in result["graph"]["nodes"]]
    assert "DNS Mapping Discovered" in labels
    assert "Subdomains Found (2)" in labels


def test_attack_path_planner_without_findings_is_the_generic_path(tmp_path, monkeypatch):
    from modules import builtin
    builtin.register_builtin_modules()
    monkeypatch.chdir(tmp_path)
    result = asyncio.run(run_module(registry.get("Attack Path Planner"), "x.org", {}))
    assert [n["id"] for n in result["graph"]["nodes"]] == ["entry"]


def test_the_planner_unwraps_a_saved_results_file(tmp_path, monkeypatch):
    import json
    from modules import builtin
    builtin.register_builtin_modules()
    monkeypatch.chdir(tmp_path)
    folder = tmp_path / "logs" / "x.org"
    folder.mkdir(parents=True)
    (folder / "results.json").write_text(json.dumps(
        {"domain": "x.org", "results": {"Subdomain Discovery": ["a.x.org"]}}))
    result = asyncio.run(run_module(registry.get("Attack Path Planner"), "x.org", {}))
    assert "Subdomains Found (1)" in [n["label"] for n in result["graph"]["nodes"]]
