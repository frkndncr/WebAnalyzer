"""The command line: output formats, exit codes, module selection and the
dispatch between the new subcommands and the legacy interface.

Real modules are never run: tests register fake ones, so there is no network.
"""
import io
import json
import sys
import time
import types

import pytest

import cli
from modules import builtin  # noqa: F401  (register the built-ins before any test swaps one out)
from modules import registry
from modules.registry import ModuleSpec


@pytest.fixture(autouse=True)
def isolated_registry():
    snapshot = dict(registry._REGISTRY)
    cli._abandoned_threads = False
    yield
    registry._REGISTRY.clear()
    registry._REGISTRY.update(snapshot)
    cli._abandoned_threads = False


def add(name, fn, **options):
    registry.register(ModuleSpec(name=name, run=fn, **options), replace=True)


def run(argv, stdin=""):
    out, err = io.StringIO(), io.StringIO()
    code = cli.main(argv, stdout=out, stderr=err, stdin=io.StringIO(stdin))
    return code, out.getvalue(), err.getvalue()


HIGH = {"js_vulnerabilities": [{"type": "DOM XSS", "severity": "High", "source_url": "https://a.org/x.js", "line": 3}]}


@pytest.fixture
def fakes():
    """Quiet modules, plus one named like a real one that reports a high finding."""
    add("T Quick", lambda d: {"domain": d, "ok": True})
    add("Advanced Content Scan", lambda d: HIGH, active=True)
    return None


# ─────────────────────────── small commands ───────────────────────────

def test_version():
    code, out, _ = run(["version"])
    assert code == 0 and out.strip() == f"WebAnalyzer {cli.VERSION}"


def test_the_version_flag(capsys):
    assert cli.main(["--version"]) == 0
    assert cli.VERSION in capsys.readouterr().out


def test_modules_lists_the_registry(fakes):
    code, out, _ = run(["modules"])
    assert code == 0 and "Domain Information" in out and "T Quick" in out and "ACTIVE" in out


def test_modules_json_is_the_catalogue(fakes):
    code, out, _ = run(["modules", "--json"])
    names = [m["name"] for m in json.loads(out)]
    assert code == 0 and "T Quick" in names and names == list(registry.names())


def test_no_command_prints_help():
    code, out, _ = run([])
    assert code == 0 and "scan" in out


def test_an_unknown_subcommand_is_a_usage_error():
    code, _, _ = run(["frobnicate"])
    assert code == cli.EXIT_USAGE


# ─────────────────────────── scan: output ───────────────────────────

def test_text_output(fakes):
    code, out, err = run(["scan", "a.org", "-m", "T Quick"])
    assert code == 0 and out.startswith("a.org") and "authorized" in err and "[ok]" in err


def test_json_output_is_a_valid_document(fakes):
    code, out, _ = run(["scan", "a.org", "-m", "T Quick,Advanced Content Scan", "-f", "json"])
    doc = json.loads(out)
    target = doc["targets"][0]
    assert code == 0 and doc["tool"]["name"] == "WebAnalyzer"
    assert target["domain"] == "a.org" and target["summary"]["high"] == 1
    assert target["modules"] == {"T Quick": "ok", "Advanced Content Scan": "ok"}
    assert target["results"]["T Quick"]["ok"] is True


def test_no_results_flag_slims_the_json(fakes):
    _, out, _ = run(["scan", "a.org", "-m", "T Quick", "-f", "json", "--no-results"])
    assert "results" not in json.loads(out)["targets"][0]


def test_sarif_output(fakes):
    code, out, _ = run(["scan", "a.org", "-m", "Advanced Content Scan", "-f", "sarif"])
    sarif = json.loads(out)
    assert code == 0 and sarif["version"] == "2.1.0"
    result = sarif["runs"][0]["results"][0]
    assert result["ruleId"] == "WA/advanced-content-scan/dom-xss" and result["level"] == "error"
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 3


def test_jsonl_has_one_line_per_target(fakes):
    _, out, _ = run(["scan", "a.org", "b.org", "-m", "T Quick", "-f", "jsonl"])
    lines = [json.loads(line) for line in out.strip().splitlines()]
    assert [line["domain"] for line in lines] == ["a.org", "b.org"]


def test_markdown_output(fakes):
    _, out, _ = run(["scan", "a.org", "-m", "Advanced Content Scan", "-f", "markdown"])
    assert out.startswith("# WebAnalyzer report") and "DOM XSS" in out


def test_output_file_is_written_and_stdout_stays_empty(fakes, tmp_path):
    target = tmp_path / "out.sarif"
    code, out, err = run(["scan", "a.org", "-m", "T Quick", "-f", "sarif", "-o", str(target)])
    assert code == 0 and out == "" and json.loads(target.read_text(encoding="utf-8"))["version"] == "2.1.0"
    assert f"wrote {target}" in err


def test_quiet_silences_stderr(fakes):
    _, _, err = run(["scan", "a.org", "-m", "T Quick", "-q"])
    assert err == ""


def test_summary_file_is_appended_not_overwritten(fakes, tmp_path):
    summary = tmp_path / "summary.md"
    summary.write_text("existing step output\n", encoding="utf-8")
    code, out, _ = run(["scan", "a.org", "-m", "Advanced Content Scan", "-f", "sarif", "--summary", str(summary), "-q"])
    text = summary.read_text(encoding="utf-8")
    assert code == 0 and text.startswith("existing step output") and "# WebAnalyzer report" in text and "DOM XSS" in text
    assert json.loads(out)["version"] == "2.1.0"          # the main output is unaffected


# ─────────────────────────── scan: targets ───────────────────────────

def test_targets_are_normalised_and_deduplicated(fakes):
    _, out, _ = run(["scan", "https://A.org/login", "a.org", "B.ORG", "-m", "T Quick", "-f", "jsonl"])
    assert [json.loads(line)["domain"] for line in out.strip().splitlines()] == ["a.org", "b.org"]


def test_targets_from_stdin(fakes):
    _, out, _ = run(["scan", "-", "-m", "T Quick", "-f", "jsonl"], stdin="a.org\n# a comment\n\nb.org\n")
    assert [json.loads(line)["domain"] for line in out.strip().splitlines()] == ["a.org", "b.org"]


def test_targets_from_a_list_file(fakes, tmp_path):
    listing = tmp_path / "domains.txt"
    listing.write_text("a.org\n# skip\nb.org\n", encoding="utf-8")
    _, out, _ = run(["scan", "--list", str(listing), "-m", "T Quick", "-f", "jsonl"])
    assert len(out.strip().splitlines()) == 2


def test_no_targets_is_a_usage_error(fakes):
    code, _, err = run(["scan", "-m", "T Quick"])
    assert code == cli.EXIT_USAGE and "no targets" in err


def test_concurrent_scans_all_complete(fakes):
    _, out, _ = run(["scan", "a.org", "b.org", "c.org", "-m", "T Quick", "-c", "3", "-f", "jsonl", "-q"])
    assert len(out.strip().splitlines()) == 3


# ─────────────────────────── scan: module selection ───────────────────────────

def test_unknown_module_is_rejected_with_a_suggestion(fakes):
    code, _, err = run(["scan", "a.org", "-m", "Security Analysys"])
    assert code == cli.EXIT_USAGE and "did you mean 'Security Analysis'" in err


def test_module_names_are_case_insensitive(fakes):
    code, out, _ = run(["scan", "a.org", "-m", "t quick", "-f", "json", "-q"])
    assert code == 0 and list(json.loads(out)["targets"][0]["modules"]) == ["T Quick"]


def test_passive_excludes_intrusive_modules(fakes):
    code, out, err = run(["scan", "a.org", "-m", "T Quick,Advanced Content Scan", "--passive", "-f", "json"])
    assert code == 0 and list(json.loads(out)["targets"][0]["modules"]) == ["T Quick"]
    assert "--passive skips the intrusive modules: Advanced Content Scan" in err


def test_passive_with_only_intrusive_modules_is_a_usage_error(fakes):
    code, _, err = run(["scan", "a.org", "-m", "Advanced Content Scan", "--passive"])
    assert code == cli.EXIT_USAGE and "no modules to run" in err


def test_presets_resolve_to_real_modules():
    from argparse import Namespace
    registry_ = cli._load_modules()
    quick = cli._select_modules(Namespace(modules=None, preset="quick", passive=False, quiet=True), registry_, io.StringIO())
    assert quick == ["Domain Information", "DNS Records", "GEO Analysis"]
    full = cli._select_modules(Namespace(modules=None, preset="full", passive=False, quiet=True), registry_, io.StringIO())
    assert full == list(registry_.names())
    passive_full = cli._select_modules(Namespace(modules=None, preset="full", passive=True, quiet=True), registry_, io.StringIO())
    assert not set(passive_full) & set(registry_.active_names())


# ─────────────────────────── exit codes ───────────────────────────

@pytest.mark.parametrize("threshold,code", [("none", 0), ("critical", 0), ("high", 1), ("medium", 1), ("info", 1)])
def test_fail_on(fakes, threshold, code):
    got, _, _ = run(["scan", "a.org", "-m", "Advanced Content Scan", "--fail-on", threshold, "-q"])
    assert got == code


def test_fail_on_with_a_clean_scan_passes(fakes):
    code, _, _ = run(["scan", "a.org", "-m", "T Quick", "--fail-on", "info", "-q"])
    assert code == 0


def test_exit_3_when_no_module_produced_anything():
    def boom(domain):
        raise RuntimeError("no network")
    add("T Boom", boom)
    code, _, err = run(["scan", "a.org", "-m", "T Boom"])
    assert code == cli.EXIT_NOTHING and "every module failed" in err


def test_a_failing_module_alongside_a_working_one_is_not_fatal(fakes):
    def boom(domain):
        raise RuntimeError("down")
    add("T Boom", boom)
    code, out, _ = run(["scan", "a.org", "-m", "T Quick,T Boom", "-f", "json", "-q"])
    assert code == 0 and json.loads(out)["targets"][0]["modules"]["T Boom"] == "error"


def test_a_timeout_is_reported_and_flags_the_process_for_a_hard_exit():
    add("T Slow", lambda d: time.sleep(1.5))
    add("T Quick", lambda d: 1)
    code, out, _ = run(["scan", "a.org", "-m", "T Slow,T Quick", "--timeout", "0.2", "-f", "json", "-q"])
    modules = json.loads(out)["targets"][0]["results"]
    assert code == 0 and modules["T Slow"]["error"].startswith("timed out after")
    assert cli._abandoned_threads is True


# ─────────────────────────── verify ───────────────────────────

def test_verify_prints_the_record_without_checking_dns():
    code, out, _ = run(["verify", "https://Example.org/", "--no-check"])
    assert code == 0 and "_webanalyzer.example.org" in out and "webanalyzer-verify=" in out


def test_verify_exit_code_follows_the_dns_result(monkeypatch):
    from utils import ownership
    monkeypatch.setattr(ownership, "is_verified", lambda d: True)
    assert run(["verify", "example.org"])[0] == 0
    monkeypatch.setattr(ownership, "is_verified", lambda d: False)
    code, out, _ = run(["verify", "example.org"])
    assert code == 1 and "not verified yet" in out


def test_verify_json(monkeypatch):
    from utils import ownership
    monkeypatch.setattr(ownership, "is_verified", lambda d: False)
    data = json.loads(run(["verify", "example.org", "--json"])[1])
    assert data["verified"] is False and data["record"]["type"] == "TXT"


def test_verify_rejects_an_empty_domain():
    assert run(["verify", "  ", "--no-check"])[0] == cli.EXIT_USAGE


# ─────────────────────────── entry-point dispatch ───────────────────────────

def test_subcommands_go_to_the_new_cli(monkeypatch):
    called = {}
    monkeypatch.setattr(sys, "argv", ["webanalyzer", "version"])
    monkeypatch.setitem(sys.modules, "main", types.SimpleNamespace(run_cli=lambda: called.setdefault("legacy", True)))
    with pytest.raises(SystemExit) as exit_info:
        cli.entry()
    assert exit_info.value.code == 0 and "legacy" not in called


@pytest.mark.parametrize("argv", [[], ["-u", "example.com"], ["-l", "domains.txt", "-m", "all"]])
def test_legacy_usage_still_goes_to_the_old_cli(monkeypatch, argv):
    called = {}
    monkeypatch.setattr(sys, "argv", ["webanalyzer", *argv])
    monkeypatch.setitem(sys.modules, "main", types.SimpleNamespace(run_cli=lambda: called.setdefault("legacy", True)))
    cli.entry()
    assert called == {"legacy": True}


def test_after_a_timeout_the_process_exits_without_waiting_for_the_worker(monkeypatch):
    exited = {}
    monkeypatch.setattr(sys, "argv", ["webanalyzer", "version"])
    cli._abandoned_threads = True

    def fake_exit(code):                 # the real os._exit never returns
        exited["code"] = code
        raise SystemExit(code)

    monkeypatch.setattr(cli.os, "_exit", fake_exit)
    with pytest.raises(SystemExit):
        cli.entry()
    assert exited == {"code": 0}
