"""Pure helpers that turn raw scan-result dicts into dashboard summaries.

These functions are intentionally dependency-free (standard library only) and
side-effect-free, so they can be unit tested without a database, network
access, or any of the scanner modules. `api.py` imports them for the
`/api/recent-scans`, `/api/vulnerability-stats` and `/api/recent-alerts`
endpoints.
"""
from typing import Optional, Tuple

from utils.safety import normalize_target

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

    # Count real findings across modules; fall back to the legacy counter that
    # some older results carried.
    vuln_count = count_findings(res) or sec.get("vulnerabilities_found", 0)
    return score, grade, vuln_count


def severity_bucket(sev) -> str:
    """Map any severity label to one of SEVERITY_KEYS (mirrors the dashboard)."""
    s = str(sev or "").lower()
    if s.startswith("crit"):
        return "critical"
    if s.startswith("high"):
        return "high"
    if s.startswith("med"):
        return "medium"
    if s.startswith("low"):
        return "low"
    return "info"


def _synth(title, severity, description="", **extra):
    """A normalised finding built from a non-vulnerability signal."""
    return {"type": title, "title": title, "severity": severity, "description": description, **extra}


_HEADER_LEVEL = {"critical": "critical", "high": "high", "medium": "medium"}

# Advanced Content Scan lists and the severity assumed when an entry has none.
_ACS_DEFAULT_SEVERITY = {
    "secrets": "high",
    "js_vulnerabilities": "medium",
    "active_vulnerabilities": "high",
    "ssrf_vulnerabilities": "high",
}


def _as_list(value):
    return value if isinstance(value, list) else []


def _security_findings(sec):
    module = "Security Analysis"
    scan = sec.get("vulnerability_scan")
    scan_vulns = scan.get("vulnerabilities") if isinstance(scan, dict) else None
    for source in (scan_vulns, sec.get("vulnerabilities")):
        for v in _as_list(source):
            if isinstance(v, dict):
                yield (v if v.get("severity") else {**v, "severity": "medium"}), module, None

    headers = sec.get("security_headers")
    headers = headers.get("headers") if isinstance(headers, dict) else None
    if isinstance(headers, dict):
        for name, h in headers.items():
            if isinstance(h, dict) and h.get("present") is False:
                level = str(h.get("importance") or h.get("security_level") or "").lower()
                yield _synth(
                    f"Missing security header: {name}", _HEADER_LEVEL.get(level, "low"),
                    f"The {name} response header is not set.",
                ), module, None

    server = sec.get("server_information")
    for note in _as_list(server.get("information_disclosure") if isinstance(server, dict) else None):
        yield _synth("Information disclosure", "low", str(note)), module, None

    methods = sec.get("http_methods")
    for m in _as_list(methods.get("dangerous_methods") if isinstance(methods, dict) else None):
        yield _synth(f"Dangerous HTTP method enabled: {m}", "high"), module, None

    cors = sec.get("cors_policy")
    for issue in _as_list(cors.get("issues") if isinstance(cors, dict) else None):
        text = (issue.get("issue") or issue.get("description") or str(issue)) if isinstance(issue, dict) else str(issue)
        yield _synth("CORS misconfiguration", "medium", text), module, None

    ssl = sec.get("ssl_analysis")
    if isinstance(ssl, dict) and ssl.get("ssl_available") is False:
        yield _synth("TLS is not available", "high", "The target does not serve a valid HTTPS/TLS endpoint."), module, None


def iter_findings(res):
    """Yield ``(finding_dict, module_name, key)`` for every finding in res.

    This is the single backend definition of a "finding"; the dashboard's
    ``lib/findings.js`` applies the same rules so counts match everywhere.
    ``key`` is the Advanced Content Scan sub-list name, otherwise ``None``.
    """
    if not isinstance(res, dict):
        return

    sec = res.get("Security Analysis")
    if isinstance(sec, dict):
        yield from _security_findings(sec)

    acs = res.get("Advanced Content Scan")
    if isinstance(acs, dict):
        for key in ACS_FINDING_KEYS:
            for f in _as_list(acs.get(key)):
                if isinstance(f, dict):
                    yield (f if f.get("severity") else {**f, "severity": _ACS_DEFAULT_SEVERITY[key]}), "Advanced Content Scan", key
        for e in _as_list(acs.get("exposed_endpoints")):
            if isinstance(e, dict):
                yield _synth(
                    f"{e.get('endpoint_type') or 'Endpoint'} exposed", e.get("severity") or "medium",
                    f"Responds with HTTP {e['status_code']}." if e.get("status_code") else "",
                ), "Advanced Content Scan", "exposed_endpoints"

    takeover = res.get("Subdomain Takeover")
    if isinstance(takeover, dict):
        for t in _as_list(takeover.get("vulnerable_subdomains")) + _as_list(takeover.get("vulnerabilities")):
            name = (t.get("subdomain") or t.get("domain") or t.get("host")) if isinstance(t, dict) else t
            sev = (t.get("severity") if isinstance(t, dict) else None) or "high"
            yield _synth(f"Subdomain takeover: {name}", sev), "Subdomain Takeover", None

    phishing = res.get("Phishing Domain Protection")
    if isinstance(phishing, dict):
        for d in _as_list(phishing.get("phishing_domains")):
            if isinstance(d, dict):
                yield _synth(f"Look-alike domain: {d.get('domain')}", d.get("severity") or "medium"), "Phishing Domain Protection", None

    archive = res.get("Web Archive Spy")
    if isinstance(archive, dict):
        for item in _as_list(archive.get("secrets")):
            kind = (item.get("type") or item.get("secret_type") or "secret") if isinstance(item, dict) else "secret"
            sev = (item.get("severity") if isinstance(item, dict) else None) or "high"
            yield _synth(f"Historical secret: {kind}", sev), "Web Archive Spy", None

    cf = res.get("CloudFlare Bypass")
    if isinstance(cf, dict) and cf.get("cloudflare_protected"):
        exposed = [r for r in _as_list(cf.get("real_ips")) if isinstance(r, dict) and r.get("source") and r.get("source") != "direct_dns"]
        if exposed:
            yield _synth("Origin IP exposed behind CloudFlare", "high"), "CloudFlare Bypass", None


def new_vuln_stats() -> dict:
    """Return a fresh, zeroed severity-count accumulator."""
    return {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": 0}


def accumulate_vuln_stats(res, stats: dict) -> dict:
    """Add severity counts from ``res`` into ``stats`` in place, returning it."""
    for finding, _module, _key in iter_findings(res):
        stats[severity_bucket(finding.get("severity"))] += 1
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
            "severity": severity_bucket(finding.get("severity")).upper(),
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


def count_findings(res) -> int:
    """Total number of findings (all severities) in a domain's results."""
    return sum(1 for _ in iter_findings(res))


def normalize_domain(name) -> str:
    """Canonical host for a stored/typed target (``https://X.com/`` -> ``x.com``)."""
    return normalize_target(name)


def domain_variants(name) -> list:
    """Spellings a target may have been stored under, most likely first.

    Older scans were saved verbatim (``https://example.com/``), so lookups by
    the bare host must also match those rows.
    """
    host = normalize_domain(name)
    if not host:
        return []
    variants = [host, f"https://{host}", f"https://{host}/", f"http://{host}", f"http://{host}/"]
    raw = str(name).strip() if name else ""
    if raw and raw not in variants:
        variants.append(raw)
    return variants


def latest_per_domain(records) -> list:
    """Collapse scan rows to one per canonical host, keeping the first (newest).

    ``records`` must be sorted newest-first. Each returned row is a copy with
    ``name`` set to the canonical host; rows with no usable host are dropped.
    """
    seen = set()
    out = []
    for rec in records:
        host = normalize_domain(rec.get("domain"))
        if not host or host in seen:
            continue
        seen.add(host)
        row = dict(rec)
        row["name"] = host
        out.append(row)
    return out


def average_score(scores):
    """Mean of the numeric scores, rounded to an int; ``None`` when empty."""
    nums = [s for s in scores if isinstance(s, (int, float)) and not isinstance(s, bool)]
    if not nums:
        return None
    return round(sum(nums) / len(nums))
