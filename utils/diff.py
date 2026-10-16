"""What changed between two scans of the same targets.

Works on the documents the CLI writes with ``-f json`` (``formats.build_document``).
A finding is identified by its domain, module, title and location, so a finding
that is still there is "unchanged" and one that is gone is "resolved".
"""
from typing import Dict, List, Optional

from utils.result_analysis import severity_rank


def fingerprint(domain: str, finding: dict) -> str:
    return "|".join((domain, finding.get("module", ""), finding.get("title", ""), finding.get("location", "")))


def _subdomains(results) -> set:
    value = (results or {}).get("Subdomain Discovery")
    if isinstance(value, dict):
        value = value.get("subdomains")
    return {str(s) for s in value} if isinstance(value, list) else set()


def _ports(results) -> set:
    scan = (results or {}).get("Nmap Zero Day Scan")
    ports = ((scan or {}).get("port_scan") or {}).get("open_ports") if isinstance(scan, dict) else None
    return {str(p) for p in ports} if isinstance(ports, list) else set()


def diff_documents(old: dict, new: dict) -> dict:
    """``{"targets": {domain: {new, resolved, unchanged, subdomains, ports}}, "summary": {...}}``."""
    old_by_domain = {t["domain"]: t for t in old.get("targets", [])}
    targets: Dict[str, dict] = {}
    for target in new.get("targets", []):
        domain = target["domain"]
        before = old_by_domain.get(domain)
        known = {fingerprint(domain, f) for f in (before or {}).get("findings", [])}
        current = {fingerprint(domain, f): f for f in target["findings"]}
        added = [f for key, f in current.items() if key not in known]
        gone = [f for f in (before or {}).get("findings", []) if fingerprint(domain, f) not in current]
        entry = {
            "baseline_found": before is not None,
            "new": sorted(added, key=lambda f: severity_rank(f["severity"])),
            "resolved": sorted(gone, key=lambda f: severity_rank(f["severity"])),
            "unchanged": len(current) - len(added),
        }
        if before is not None and "results" in before and "results" in target:
            for label, pick in (("subdomains", _subdomains), ("open_ports", _ports)):
                a, b = pick(before["results"]), pick(target["results"])
                entry[label] = {"added": sorted(b - a), "removed": sorted(a - b)}
        targets[domain] = entry
    return {
        "targets": targets,
        "summary": {
            "new": sum(len(t["new"]) for t in targets.values()),
            "resolved": sum(len(t["resolved"]) for t in targets.values()),
            "unchanged": sum(t["unchanged"] for t in targets.values()),
        },
    }


def new_findings(old: dict, new: dict) -> List[dict]:
    """Every finding in ``new`` that ``old`` did not have (for gating on regressions only)."""
    out = []
    for domain, entry in diff_documents(old, new)["targets"].items():
        out.extend({**f, "domain": domain} for f in entry["new"])
    return out


def exceeds_new(old: dict, new: dict, threshold: str) -> bool:
    """True when a *new* finding is at least as severe as ``threshold``."""
    if threshold == "none":
        return False
    return any(severity_rank(f["severity"]) <= severity_rank(threshold) for f in new_findings(old, new))


def to_markdown(result: dict, limit: int = 30) -> str:
    s = result["summary"]
    lines = ["# WebAnalyzer changes", "", f"**{s['new']} new**, **{s['resolved']} resolved**, {s['unchanged']} unchanged.", ""]
    for domain, t in result["targets"].items():
        lines.append(f"## {domain}")
        if not t["baseline_found"]:
            lines += ["", "_Not in the baseline: every finding counts as new._"]
        for title, items in (("New findings", t["new"]), ("Resolved", t["resolved"])):
            if items:
                lines += ["", f"### {title}", ""]
                lines += [f"- **{f['severity'].upper()}** {f['title']} ({f['module']})" for f in items[:limit]]
                if len(items) > limit:
                    lines.append(f"- ...and {len(items) - limit} more")
        for key, label in (("subdomains", "Subdomains"), ("open_ports", "Open ports")):
            change = t.get(key)
            if change and (change["added"] or change["removed"]):
                lines += ["", f"### {label}", ""]
                lines += [f"- added: `{x}`" for x in change["added"][:limit]] + [f"- removed: `{x}`" for x in change["removed"][:limit]]
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def to_text(result: dict) -> str:
    s = result["summary"]
    out = [f"{s['new']} new, {s['resolved']} resolved, {s['unchanged']} unchanged"]
    for domain, t in result["targets"].items():
        out.append(f"{domain}")
        out += [f"  + {f['severity'].upper():8} {f['title']}  ({f['module']})" for f in t["new"]]
        out += [f"  - {f['severity'].upper():8} {f['title']}  ({f['module']})" for f in t["resolved"]]
        for key in ("subdomains", "open_ports"):
            change = t.get(key) or {"added": [], "removed": []}
            out += [f"  + {key}: {x}" for x in change["added"]] + [f"  - {key}: {x}" for x in change["removed"]]
    return "\n".join(out) + "\n"
