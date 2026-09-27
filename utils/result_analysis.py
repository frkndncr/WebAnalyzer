"""Pure helpers that turn raw scan-result dicts into dashboard summaries.

These functions are intentionally dependency-free (standard library only) and
side-effect-free, so they can be unit tested without a database, network
access, or any of the scanner modules. `api.py` imports them for the
`/api/recent-scans`, `/api/vulnerability-stats` and `/api/recent-alerts`
endpoints.
"""
from typing import Optional, Tuple

# Severity buckets tracked by the vulnerability aggregator.
SEVERITY_KEYS = ("critical", "high", "medium", "low", "info")

# Sub-lists inside the "Advanced Content Scan" module that hold findings.
ACS_FINDING_KEYS = ("secrets", "js_vulnerabilities", "active_vulnerabilities", "ssrf_vulnerabilities")

# Ordering used when ranking alerts (most severe first).
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def summarize_security_result(res) -> Tuple[Optional[int], Optional[str], int]:
    """Return ``(score, grade, vuln_count)`` for a domain's results dict.

    The Security Analysis module stores its score either as a plain number or
    as an object ``{overall_score, grade, ...}``; this normalises it to a
    number so the frontend can render it directly.
    """
    sec = res.get("Security Analysis", {}) if isinstance(res, dict) else {}
    if not isinstance(sec, dict):
        return None, None, 0

    raw = sec.get("security_score")
    grade = sec.get("security_grade")
    score = None
    if isinstance(raw, dict):
        score = raw.get("overall_score")
        grade = raw.get("grade", grade)
    elif isinstance(raw, (int, float)) and not isinstance(raw, bool):
        score = int(raw)

    vuln_count = sec.get("vulnerabilities_found", 0)
    return score, grade, vuln_count


def iter_findings(res):
    """Yield ``(finding_dict, module_name, acs_key)`` for every finding in res.

    ``acs_key`` is the sub-list name for Advanced Content Scan findings, or
    ``None`` for Security Analysis vulnerabilities.
    """
    if not isinstance(res, dict):
        return

    sec = res.get("Security Analysis", {})
    if isinstance(sec, dict):
        for v in sec.get("vulnerabilities", []) or []:
            if isinstance(v, dict):
                yield v, "Security Analysis", None

    acs = res.get("Advanced Content Scan", {})
    if isinstance(acs, dict):
        for key in ACS_FINDING_KEYS:
            for f in acs.get(key, []) or []:
                if isinstance(f, dict):
                    yield f, "Advanced Content Scan", key


def new_vuln_stats() -> dict:
    """Return a fresh, zeroed severity-count accumulator."""
    return {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}


def accumulate_vuln_stats(res, stats: dict) -> dict:
    """Add severity counts from ``res`` into ``stats`` in place, returning it."""
    for finding, _module, _key in iter_findings(res):
        sev = (finding.get("severity", "medium") or "medium").lower()
        if sev in stats:
            stats[sev] += 1
        stats["total"] += 1
    return stats


def extract_alerts(domain: str, res) -> list:
    """Return a list of normalised alert dicts for a domain's results."""
    alerts = []
    for finding, module, key in iter_findings(res):
        if module == "Security Analysis":
            title = finding.get("type", finding.get("title", "Vulnerability"))
            desc = finding.get("description", finding.get("detail", ""))
        else:
            default_title = key.replace("_", " ").title() if key else "Finding"
            title = finding.get("type", finding.get("vuln_type", default_title))
            desc = finding.get("description", finding.get("value", ""))
        alerts.append({
            "domain": domain,
            "title": title,
            "severity": (finding.get("severity", "Medium") or "Medium").upper(),
            "description": (desc or "")[:120],
            "module": module,
        })
    return alerts


def sort_and_dedupe_alerts(alerts: list, limit: int = 15) -> list:
    """De-duplicate alerts by ``(domain, title)`` and rank most-severe first."""
    seen = set()
    unique = []
    for a in alerts:
        key = (a.get("domain"), a.get("title"))
        if key not in seen:
            seen.add(key)
            unique.append(a)
    unique.sort(key=lambda x: SEVERITY_ORDER.get(x.get("severity"), 5))
    return unique[:limit]
