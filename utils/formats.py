"""Output formats for scan results: JSON, JSON Lines, SARIF 2.1.0, Markdown, text.

Everything here is a pure function of the scan data (no network, no files), so
it is unit tested directly. The same finding definition as the dashboard is used
(``utils.result_analysis.list_findings``), so counts agree everywhere.

A *scan* is ``{"domain", "scanned_at", "duration_seconds", "results"}`` where
``results`` maps module names to what they produced.
"""
import hashlib
import re
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional

from utils.result_analysis import (
    list_findings, severity_rank, summarize_security_result,
)
from utils.version import VERSION

SEVERITIES = ("critical", "high", "medium", "low", "info")
INFORMATION_URI = "https://github.com/frkndncr/WebAnalyzer"

# SARIF levels and GitHub's numeric "security-severity" (0-10) per severity.
_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
_SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.5"}

# Modules whose finding titles end in a per-item suffix ("Look-alike domain: x.com"):
# the part before the colon identifies the rule, the rest belongs in the message.
_VARIABLE_TITLE_MODULES = {"Subdomain Takeover", "Phishing Domain Protection", "Web Archive Spy"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(text).lower()).strip("-") or "finding"


def _counts(findings: Iterable[dict]) -> Dict[str, int]:
    counts = {sev: 0 for sev in SEVERITIES}
    total = 0
    for f in findings:
        counts[f["severity"]] += 1
        total += 1
    counts["total"] = total
    return counts


def _module_status(data) -> str:
    if isinstance(data, dict) and data.get("error"):
        return "error"
    if data in (None, "", [], {}):
        return "empty"
    return "ok"


# ─────────────────────────── the document ───────────────────────────

def build_document(scans: List[dict], include_results: bool = True, generated_at: Optional[str] = None) -> dict:
    """The structured result of one or more scans (also the base of every other format)."""
    targets = []
    for scan in scans:
        results = scan.get("results") or {}
        findings = list_findings(results)
        score, grade, _ = summarize_security_result(results)
        target = {
            "domain": scan["domain"],
            "scanned_at": scan.get("scanned_at"),
            "duration_seconds": scan.get("duration_seconds"),
            "score": score,
            "grade": grade,
            "summary": _counts(findings),
            "modules": {name: _module_status(data) for name, data in results.items()},
            "findings": findings,
        }
        if include_results:
            target["results"] = results
        targets.append(target)
    return {
        "tool": {"name": "WebAnalyzer", "version": VERSION, "uri": INFORMATION_URI},
        "generated_at": generated_at or _now(),
        "targets": targets,
    }


def worst_severity(doc: dict) -> Optional[str]:
    """The most severe finding level in the document, or None when there are none."""
    worst = None
    for target in doc["targets"]:
        for f in target["findings"]:
            if worst is None or severity_rank(f["severity"]) < severity_rank(worst):
                worst = f["severity"]
    return worst


def exceeds(doc: dict, threshold: str) -> bool:
    """True when any finding is at least as severe as ``threshold`` ('none' never fails)."""
    if threshold == "none":
        return False
    worst = worst_severity(doc)
    return worst is not None and severity_rank(worst) <= severity_rank(threshold)


def failed_modules(doc: dict) -> int:
    return sum(1 for t in doc["targets"] for status in t["modules"].values() if status == "error")


# ─────────────────────────── JSON Lines ───────────────────────────

def to_jsonl_lines(doc: dict) -> List[dict]:
    """One object per target, for pipes (jq, log shippers)."""
    return [{"tool": doc["tool"], "generated_at": doc["generated_at"], **target} for target in doc["targets"]]


# ─────────────────────────── SARIF ───────────────────────────

def _rule_id(finding: dict) -> str:
    title = finding["title"]
    if finding["module"] in _VARIABLE_TITLE_MODULES:
        title = title.split(":")[0]
    return f"WA/{_slug(finding['module'])}/{_slug(title)}"


def _rule_name(finding: dict) -> str:
    title = finding["title"]
    return title.split(":")[0] if finding["module"] in _VARIABLE_TITLE_MODULES else title


def _location(finding: dict, domain: str) -> dict:
    """A SARIF physicalLocation: the finding's URL (and line) or the scanned domain."""
    location = finding.get("location") or ""
    line = None
    match = re.match(r"^(.*):(\d+)$", location)
    if match and "://" in match.group(1):
        location, line = match.group(1), int(match.group(2))
    uri = location if "://" in location else f"https://{domain}"
    physical = {"artifactLocation": {"uri": uri}}
    if line:
        physical["region"] = {"startLine": line}
    return {"physicalLocation": physical}


def to_sarif(doc: dict) -> dict:
    """SARIF 2.1.0, ready for GitHub Code Scanning (github/codeql-action/upload-sarif)."""
    rules: Dict[str, dict] = {}
    results = []
    for target in doc["targets"]:
        domain = target["domain"]
        for f in target["findings"]:
            rule_id = _rule_id(f)
            rules.setdefault(rule_id, {
                "id": rule_id,
                "name": _rule_name(f),
                "shortDescription": {"text": _rule_name(f)},
                "fullDescription": {"text": f["recommendation"] or f["description"] or _rule_name(f)},
                "help": {"text": f["recommendation"] or "See the finding details."},
                "defaultConfiguration": {"level": _SARIF_LEVEL[f["severity"]]},
                "properties": {
                    "tags": ["security", _slug(f["module"])],
                    "security-severity": _SECURITY_SEVERITY[f["severity"]],
                    "precision": "medium",
                },
            })
            message = f["title"] + (f" - {f['description']}" if f["description"] else "")
            fingerprint = hashlib.sha256(f"{domain}|{rule_id}|{f['title']}|{f['location']}".encode()).hexdigest()[:32]
            results.append({
                "ruleId": rule_id,
                "level": _SARIF_LEVEL[f["severity"]],
                "message": {"text": message},
                "locations": [_location(f, domain)],
                "partialFingerprints": {"webanalyzer/v1": fingerprint},
                "properties": {
                    "domain": domain,
                    "module": f["module"],
                    "severity": f["severity"],
                    "recommendation": f["recommendation"],
                    "evidence": f["evidence"],
                },
            })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "WebAnalyzer",
                "version": doc["tool"]["version"],
                "informationUri": INFORMATION_URI,
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }


# ─────────────────────────── Markdown ───────────────────────────

def _cell(text: str, limit: int = 90) -> str:
    text = " ".join(str(text).split()).replace("|", "\\|")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def to_markdown(doc: dict, limit: int = 40) -> str:
    """A summary for pull-request comments and the GitHub Actions job summary."""
    lines = ["# WebAnalyzer report", ""]
    for target in doc["targets"]:
        s = target["summary"]
        score = f"{target['score']}/100 ({target['grade']})" if target["score"] is not None else "n/a"
        lines += [
            f"## {target['domain']}",
            "",
            f"Security score: **{score}** · findings: **{s['total']}** "
            f"(critical {s['critical']}, high {s['high']}, medium {s['medium']}, low {s['low']}, info {s['info']})",
            "",
        ]
        failed = [name for name, status in target["modules"].items() if status == "error"]
        if failed:
            lines += [f"> Modules that failed: {', '.join(failed)}", ""]
        if target["findings"]:
            lines += ["| Severity | Finding | Module | Location |", "|---|---|---|---|"]
            for f in target["findings"][:limit]:
                lines.append(f"| {f['severity'].upper()} | {_cell(f['title'])} | {_cell(f['module'])} | {_cell(f['location'] or '-', 60)} |")
            if len(target["findings"]) > limit:
                lines += ["", f"_…and {len(target['findings']) - limit} more (see the JSON or SARIF output)._"]
            lines.append("")
        else:
            lines += ["No findings.", ""]
    lines.append(f"_Generated by WebAnalyzer {doc['tool']['version']}. Only scan systems you are authorized to test._")
    return "\n".join(lines) + "\n"


# ─────────────────────────── plain text ───────────────────────────

def to_text(doc: dict, limit: int = 50) -> str:
    """A compact terminal summary."""
    out = []
    for target in doc["targets"]:
        s = target["summary"]
        score = f"{target['score']}/100 ({target['grade']})" if target["score"] is not None else "n/a"
        out.append(f"{target['domain']}  score {score}  findings {s['total']} "
                   f"[critical {s['critical']} high {s['high']} medium {s['medium']} low {s['low']} info {s['info']}]")
        for f in target["findings"][:limit]:
            where = f"  {f['location']}" if f["location"] else ""
            out.append(f"  {f['severity'].upper():8} {f['title']}  ({f['module']}){where}")
        if len(target["findings"]) > limit:
            out.append(f"  ... and {len(target['findings']) - limit} more")
        failed = [name for name, status in target["modules"].items() if status == "error"]
        if failed:
            out.append(f"  modules that failed: {', '.join(failed)}")
        out.append("")
    return "\n".join(out).rstrip() + "\n"
