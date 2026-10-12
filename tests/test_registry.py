"""The module registry: registration rules, ordering, plugin discovery that
isolates failures, and the catalogue of built-in modules."""
import pytest

from modules import registry
from modules.registry import ModuleSpec, discover_plugins, module, register


@pytest.fixture(autouse=True)
def isolated_registry():
    """Every test starts from, and leaves behind, the same registry contents."""
    snapshot = dict(registry._REGISTRY)
    yield
    registry._REGISTRY.clear()
    registry._REGISTRY.update(snapshot)


def fn(domain):
    return {"domain": domain}


# ─────────────────────────── registration ───────────────────────────

def test_register_and_lookup():
    spec = register(ModuleSpec(name="Probe A", run=fn, description="d", group="security", weight="light"))
    assert registry.get("Probe A") is spec
    assert "Probe A" in registry.names()


def test_duplicate_names_are_refused_unless_replacing():
    register(ModuleSpec(name="Probe B", run=fn))
    with pytest.raises(ValueError, match="already registered"):
        register(ModuleSpec(name="Probe B", run=fn))
    replacement = register(ModuleSpec(name="Probe B", run=fn, description="new"), replace=True)
    assert registry.get("Probe B") is replacement


@pytest.mark.parametrize("kwargs,message", [
    ({"name": ""}, "invalid module name"),
    ({"name": "../etc"}, "invalid module name"),
    ({"name": "x" * 80}, "invalid module name"),
    ({"name": "Ok", "group": "evil"}, "group must be one of"),
    ({"name": "Ok", "weight": "huge"}, "weight must be one of"),
    ({"name": "Ok", "run": "not callable"}, "run must be callable"),
])
def test_bad_registrations_are_rejected(kwargs, message):
    params = {"name": "Ok", "run": fn, **kwargs}
    with pytest.raises(ValueError, match=message):
        register(ModuleSpec(**params))


def test_the_decorator_registers_and_returns_the_function():
    @module("Decorated", description="via decorator", group="recon", weight="light")
    def decorated(domain):
        return 1

    assert decorated("x") == 1
    spec = registry.get("Decorated")
    assert spec.run is decorated and spec.description == "via decorator"


def test_listing_is_ordered_by_order_then_name():
    register(ModuleSpec(name="Zeta", run=fn, order=1))
    register(ModuleSpec(name="Alpha", run=fn, order=1))
    register(ModuleSpec(name="Late", run=fn, order=9999))
    names = registry.names()
    assert names.index("Alpha") < names.index("Zeta") < names.index("Late")


def test_active_names_and_catalogue_shape():
    register(ModuleSpec(name="Intrusive", run=fn, active=True, group="offensive", weight="heavy"))
    assert "Intrusive" in registry.active_names()
    entry = next(m for m in registry.catalogue() if m["name"] == "Intrusive")
    assert set(entry) == {"name", "description", "group", "weight", "active"}   # nothing callable leaks out
    assert entry["active"] is True


# ─────────────────────────── built-in modules ───────────────────────────

def builtin_names():
    from modules import builtin
    builtin.register_builtin_modules()
    return [spec[0] for spec in builtin._BUILTIN]


def test_the_sixteen_builtin_modules_are_registered_in_a_stable_order():
    expected = builtin_names()
    assert len(expected) == 16
    listed = [n for n in registry.names() if n in set(expected)]
    assert listed == expected


def test_builtin_activity_flags():
    builtin_names()
    assert registry.active_names() >= {
        "Advanced Content Scan", "Nmap Zero Day Scan", "Subdomain Takeover", "CloudFlare Bypass"}
    assert registry.get("Attack Path Planner").needs_results is True
    assert registry.get("Domain Information").active is False


def test_every_builtin_spec_is_valid():
    for name in builtin_names():
        spec = registry.get(name)
        assert callable(spec.run) and spec.group in registry.GROUPS and spec.weight in registry.WEIGHTS


def test_presets_only_reference_real_modules():
    from modules import builtin
    builtin_names()
    for names in builtin.PRESETS.values():
        assert set(names) <= set(registry.names())


# ─────────────────────────── plugin discovery ───────────────────────────

GOOD = """
from modules.registry import module

@module("Plugin Good", description="loaded from a file", group="recon", weight="light")
def good(domain):
    return {"ok": domain}
"""


def test_a_dropped_in_file_becomes_a_module(tmp_path):
    (tmp_path / "good.py").write_text(GOOD)
    outcomes = discover_plugins([str(tmp_path)])
    assert outcomes == [(str(tmp_path / "good.py"), None)]
    assert registry.get("Plugin Good").run("example.org") == {"ok": "example.org"}


def test_a_broken_plugin_is_reported_and_does_not_stop_the_others(tmp_path):
    (tmp_path / "a_broken.py").write_text("this is not python (")
    (tmp_path / "b_raises.py").write_text("raise RuntimeError('boom')")
    (tmp_path / "c_good.py").write_text(GOOD)
    outcomes = dict(discover_plugins([str(tmp_path)]))
    assert "SyntaxError" in outcomes[str(tmp_path / "a_broken.py")]
    assert "RuntimeError: boom" in outcomes[str(tmp_path / "b_raises.py")]
    assert outcomes[str(tmp_path / "c_good.py")] is None
    assert registry.get("Plugin Good") is not None


def test_a_plugin_cannot_silently_replace_a_builtin(tmp_path):
    builtin_names()
    original = registry.get("DNS Records")
    (tmp_path / "evil.py").write_text(
        "from modules.registry import module\n"
        "@module('DNS Records')\n"
        "def fake(domain):\n"
        "    return 'owned'\n")
    outcome = dict(discover_plugins([str(tmp_path)]))
    assert "already registered" in outcome[str(tmp_path / "evil.py")]
    assert registry.get("DNS Records") is original


def test_private_files_and_other_extensions_are_ignored(tmp_path):
    (tmp_path / "_helper.py").write_text(GOOD)
    (tmp_path / "notes.txt").write_text(GOOD)
    assert discover_plugins([str(tmp_path)]) == []
    assert registry.get("Plugin Good") is None


def test_missing_directories_are_skipped(tmp_path):
    assert discover_plugins([str(tmp_path / "nope")]) == []


def test_extra_directories_come_from_the_environment(tmp_path, monkeypatch):
    (tmp_path / "from_env.py").write_text(GOOD)
    monkeypatch.setenv("WEBANALYZER_PLUGIN_DIRS", str(tmp_path))
    paths = [p for p, _ in discover_plugins()]
    assert str(tmp_path / "from_env.py") in paths


def test_the_shipped_example_plugin_is_loaded_by_discovery():
    import sys
    registry.unregister("Security.txt")
    sys.modules.pop("modules.plugins.security_txt", None)    # force a fresh import
    outcomes = dict(discover_plugins())
    shipped = [p for p in outcomes if p.endswith("security_txt.py")]
    assert shipped and outcomes[shipped[0]] is None
    assert registry.get("Security.txt") is not None


def test_a_plugin_file_is_executed_only_once_even_if_discovery_runs_twice(tmp_path):
    (tmp_path / "once.py").write_text(GOOD)
    assert discover_plugins([str(tmp_path)])[0][1] is None
    assert discover_plugins([str(tmp_path)])[0][1] is None        # no "already registered" error


def test_importing_the_shipped_plugin_directly_after_discovery_is_safe():
    discover_plugins()
    from modules.plugins import security_txt          # noqa: F401  (must not raise)
    assert registry.get("Security.txt") is not None
