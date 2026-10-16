"""Change detection between two scans, and the `diff` / `--baseline` CLI paths."""
import io
import json

from utils import diff as d


def finding(title, severity="high", module="Security Analysis", location=""):
    return {"title": title, "severity": severity, "module": module, "location": location,
            "description": "", "evidence": "", "recommendation": ""}


def doc(findings, domain="x.org", results=None):
    target = {"domain": domain, "findings": findings}
    if results is not None:
        target["results"] = results
    return {"targets": [target]}


OLD = doc([finding("Missing HSTS"), finding("Open Redirect", "medium", location="https://x.org/r")],
          results={"Subdomain Discovery": ["a.x.org"], "Nmap Zero Day Scan": {"port_scan": {"open_ports": [80, 443]}}})
NEW = doc([finding("Missing HSTS"), finding("Exposed .env", "critical", location="https://x.org/.env")],
          results={"Subdomain Discovery": {"subdomains": ["a.x.org", "dev.x.org"]}, "Nmap Zero Day Scan": {"port_scan": {"open_ports": [80, 443, 3306]}}})


def test_new_resolved_and_unchanged_are_told_apart():
    t = d.diff_documents(OLD, NEW)["targets"]["x.org"]
    assert [f["title"] for f in t["new"]] == ["Exposed .env"]
    assert [f["title"] for f in t["resolved"]] == ["Open Redirect"]
    assert t["unchanged"] == 1


def test_recon_changes_are_reported():
    t = d.diff_documents(OLD, NEW)["targets"]["x.org"]
    assert t["subdomains"] == {"added": ["dev.x.org"], "removed": []}
    assert t["open_ports"] == {"added": ["3306"], "removed": []}


def test_a_target_missing_from_the_baseline_counts_everything_as_new():
    other = doc([finding("A")], domain="y.org")
    t = d.diff_documents(OLD, other)["targets"]["y.org"]
    assert t["baseline_found"] is False and len(t["new"]) == 1


def test_gating_only_looks_at_new_findings():
    assert d.exceeds_new(OLD, NEW, "high") is True            # the new critical
    assert d.exceeds_new(OLD, OLD, "low") is False            # nothing new, even though old findings exist
    assert d.exceeds_new(OLD, NEW, "none") is False


def test_a_changed_location_is_a_new_finding():
    moved = doc([finding("Open Redirect", "medium", location="https://x.org/other")])
    assert len(d.diff_documents(OLD, moved)["targets"]["x.org"]["new"]) == 1


def test_markdown_and_text_summaries_mention_the_changes():
    result = d.diff_documents(OLD, NEW)
    md, txt = d.to_markdown(result), d.to_text(result)
    assert "1 new" in md and "Exposed .env" in md and "dev.x.org" in md
    assert "+ CRITICAL" in txt and "- MEDIUM" in txt


def test_cli_diff_exit_code_and_errors(tmp_path):
    import cli
    old, new = tmp_path / "old.json", tmp_path / "new.json"
    old.write_text(json.dumps(OLD))
    new.write_text(json.dumps(NEW))
    out, err = io.StringIO(), io.StringIO()
    assert cli.main(["diff", str(old), str(new), "--fail-on-new", "high"], stdout=out, stderr=err) == cli.EXIT_FINDINGS
    assert "Exposed .env" in out.getvalue()
    assert cli.main(["diff", str(old), str(old), "--fail-on-new", "low"], stdout=io.StringIO(), stderr=err) == cli.EXIT_OK
    bad = tmp_path / "bad.json"
    bad.write_text("{}")
    assert cli.main(["diff", str(old), str(bad)], stdout=io.StringIO(), stderr=err) == cli.EXIT_USAGE
    assert cli.main(["diff", str(old), str(tmp_path / "missing.json")], stdout=io.StringIO(), stderr=err) == cli.EXIT_USAGE
