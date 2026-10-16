"""A client-ready security assessment report (print-to-PDF HTML) from scan results.

Built from the same document as every other format (``formats.build_document``),
so the numbers in a report always match the dashboard, the CLI and SARIF.
Everything interpolated into the page is escaped.
"""
import html
from datetime import datetime, timezone
from typing import Dict, List, Optional

from utils import formats
from utils.taxonomy import classify

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
_COLORS = {"critical": "#b91c1c", "high": "#c2410c", "medium": "#a16207", "low": "#1d4ed8", "info": "#475569"}
_SCOPE_NOTE = (
    "This report was produced by an automated scan. It shows what could be observed from the "
    "outside at the time of the scan; it is not a substitute for a manual penetration test, and "
    "an absence of findings is not proof that no vulnerability exists. Findings should be "
    "validated before they are acted on."
)


def _e(value) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _clean(value: Optional[str], limit: int = 120) -> str:
    return "".join(ch for ch in (value or "") if ch.isprintable()).strip()[:limit]


def _risk_statement(summary: Dict[str, int], grade: Optional[str]) -> str:
    if summary["critical"]:
        return "Critical issues were found that could be exploited remotely. They should be fixed first."
    if summary["high"]:
        return "High-severity issues were found. They should be scheduled for remediation promptly."
    if summary["medium"]:
        return "No critical or high issues were found, but several medium-severity weaknesses need attention."
    if summary["low"] or summary["info"]:
        return "Only low-severity and informational items were found. The external posture looks sound."
    return "No findings were reported by the modules that ran."


def _findings_with_ids(target: dict) -> List[dict]:
    out = []
    for number, finding in enumerate(target["findings"], start=1):
        meta = classify(finding["title"], finding["description"]) or {}
        out.append({**finding, "id": f"WA-{number:03d}", **meta})
    return out


def _remediation(finding: dict) -> Dict[str, str]:
    """The finding's own recommendation, else the generic guidance for its type."""
    from modules.report_generator import _get_remediation       # the shared remediation library
    fallback = _get_remediation(finding["title"], finding["description"])
    return {
        "text": finding["recommendation"] or fallback["remediation"],
        "code": "" if finding["recommendation"] else fallback.get("code", ""),
    }


def to_html_report(doc: dict, client: str = "", author: str = "", title: str = "", classification: str = "Confidential") -> str:
    """One page set per target: cover, executive summary, findings, appendix."""
    client, author = _clean(client), _clean(author)
    title = _clean(title) or "Security Assessment Report"
    classification = _clean(classification, 40) or "Confidential"
    generated = doc["generated_at"][:10]
    pages = [_target_html(t, client, author, title, classification, generated, doc["tool"]["version"]) for t in doc["targets"]]
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_e(title)} - {_e(', '.join(t['domain'] for t in doc['targets']))}</title>
<style>{_CSS}</style></head>
<body>
<div class="bar"><b>WebAnalyzer</b><button onclick="window.print()">Save as PDF / Print</button></div>
{''.join(pages)}
</body></html>
"""


def _target_html(target: dict, client: str, author: str, title: str, classification: str, generated: str, version: str) -> str:
    s = target["summary"]
    findings = _findings_with_ids(target)
    score = target["score"]
    grade = target["grade"] or "-"
    domain = _e(target["domain"])
    top = [f for f in findings if f["severity"] in ("critical", "high")][:5] or findings[:5]

    counts = "".join(
        f'<div class="count" style="border-top-color:{_COLORS[sev]}"><b>{s[sev]}</b><span>{sev.title()}</span></div>'
        for sev in SEVERITY_ORDER)
    top_rows = "".join(
        f'<tr><td>{_e(f["id"])}</td><td><span class="sev" style="background:{_COLORS[f["severity"]]}">{f["severity"].upper()}</span></td>'
        f'<td>{_e(f["title"])}</td></tr>' for f in top) or '<tr><td colspan="3">No findings.</td></tr>'
    overview_rows = "".join(
        f'<tr><td>{_e(f["id"])}</td><td><span class="sev" style="background:{_COLORS[f["severity"]]}">{f["severity"].upper()}</span></td>'
        f'<td>{_e(f["title"])}</td><td>{_e(f.get("cwe", "-"))}</td><td>{_e(f["module"])}</td></tr>' for f in findings)
    detail = "".join(_finding_html(f) for f in findings) or "<p>No findings were reported.</p>"
    module_rows = "".join(
        f'<tr><td>{_e(name)}</td><td class="st-{status}">{ {"ok": "Completed", "empty": "No data", "error": "Failed"}[status] }</td></tr>'
        for name, status in target["modules"].items())
    ran = len(target["modules"])
    failed = sum(1 for v in target["modules"].values() if v == "error")
    prepared = " &middot; ".join(x for x in (f"Prepared for {_e(client)}" if client else "", f"by {_e(author)}" if author else "") if x)

    return f"""
<section class="cover page">
  <div class="classif">{_e(classification)}</div>
  <h1>{_e(title)}</h1>
  <h2>{domain}</h2>
  <p class="meta">{prepared or "Automated external assessment"}<br>Date: {_e(generated)} &middot; Report ID: WA-{_e(generated.replace('-', ''))}-{_e(target['domain'])}</p>
  <div class="grade"><b>{_e(grade)}</b><span>{_e(score if score is not None else 'n/a')}/100</span></div>
  <p class="foot">Generated by WebAnalyzer {_e(version)}</p>
</section>

<section class="page">
  <h2>1. Executive summary</h2>
  <p>{_risk_statement(s, target['grade'])}</p>
  <div class="counts">{counts}</div>
  <p><b>{s['total']}</b> finding(s) across <b>{ran}</b> module(s); {failed} module(s) failed.</p>
  <h3>Priorities</h3>
  <table><tr><th>ID</th><th>Severity</th><th>Finding</th></tr>{top_rows}</table>
  <h3>Scope and limitations</h3>
  <p>{_e(_SCOPE_NOTE)}</p>
</section>

<section class="page">
  <h2>2. Findings overview</h2>
  <table><tr><th>ID</th><th>Severity</th><th>Finding</th><th>CWE</th><th>Module</th></tr>{overview_rows or '<tr><td colspan="5">No findings.</td></tr>'}</table>
</section>

<section class="page">
  <h2>3. Findings in detail</h2>
  {detail}
</section>

<section class="page">
  <h2>Appendix A. Modules</h2>
  <table><tr><th>Module</th><th>Status</th></tr>{module_rows}</table>
  <h2>Appendix B. Method</h2>
  <p>Severity is assigned by the module that reports a finding and normalised to critical, high, medium, low or info. The
  score starts at 100 and drops for each issue found by the Security Analysis module. CWE and OWASP Top 10 (2021) references
  are suggested from the finding text and are indicative, not a formal classification. No CVSS vector is calculated.</p>
</section>
"""


def _finding_html(f: dict) -> str:
    rem = _remediation(f)
    rows = [("Module", f["module"]), ("Location", f["location"]), ("CWE", f"{f['cwe']} - {f['cwe_name']}" if f.get("cwe") else ""),
            ("OWASP", f.get("owasp"))]
    meta = "".join(f"<tr><th>{k}</th><td>{_e(v)}</td></tr>" for k, v in rows if v)
    evidence = f'<h4>Evidence</h4><pre>{_e(f["evidence"])}</pre>' if f["evidence"] else ""
    code = f'<pre>{_e(rem["code"])}</pre>' if rem["code"] else ""
    return f"""
<article class="finding" style="border-left-color:{_COLORS[f['severity']]}">
  <h3><span class="id">{_e(f['id'])}</span> {_e(f['title'])} <span class="sev" style="background:{_COLORS[f['severity']]}">{f['severity'].upper()}</span></h3>
  <table class="meta">{meta}</table>
  {f"<p>{_e(f['description'])}</p>" if f['description'] else ""}
  {evidence}
  <h4>Recommendation</h4><p>{_e(rem['text'])}</p>{code}
</article>"""


_CSS = """
:root{--ink:#0f172a;--muted:#64748b;--line:#e2e8f0}
*{box-sizing:border-box}body{margin:0;font:14px/1.6 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:var(--ink);background:#f1f5f9}
.bar{position:sticky;top:0;background:#0b1220;color:#fff;padding:12px 24px;display:flex;justify-content:space-between;align-items:center}
.bar button{background:#2563eb;color:#fff;border:0;border-radius:6px;padding:8px 16px;font-weight:600;cursor:pointer}
.page{background:#fff;max-width:900px;margin:24px auto;padding:48px 56px;border:1px solid var(--line);border-radius:8px}
.cover{min-height:760px;display:flex;flex-direction:column;justify-content:center}
.cover h1{font-size:34px;margin:8px 0}.cover h2{font-size:22px;color:#2563eb;margin:0 0 24px;word-break:break-all}
.classif{align-self:flex-start;border:1.5px solid #b91c1c;color:#b91c1c;padding:3px 12px;border-radius:4px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;font-size:12px}
.meta{color:var(--muted)}.foot{margin-top:auto;color:var(--muted);font-size:12px}
.grade{display:inline-flex;align-items:baseline;gap:12px;margin-top:12px}.grade b{font-size:64px;line-height:1}.grade span{color:var(--muted);font-size:18px}
h2{font-size:22px;border-bottom:2px solid var(--ink);padding-bottom:6px;margin:0 0 16px}h3{font-size:16px;margin:22px 0 8px}h4{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:14px 0 4px}
table{width:100%;border-collapse:collapse;margin:8px 0}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}th{font-size:12px;text-transform:uppercase;color:var(--muted);width:1%;white-space:nowrap}
.counts{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin:16px 0}.count{border:1px solid var(--line);border-top:4px solid;border-radius:6px;padding:10px;text-align:center}
.count b{display:block;font-size:26px}.count span{font-size:12px;color:var(--muted)}
.sev{color:#fff;border-radius:4px;padding:2px 8px;font-size:11px;font-weight:700;letter-spacing:.04em;vertical-align:middle}
.finding{border:1px solid var(--line);border-left:5px solid;border-radius:6px;padding:14px 18px;margin:16px 0;break-inside:avoid}.finding h3{margin-top:0}.id{color:var(--muted);font-weight:500}
.finding table.meta th{width:90px}pre{background:#0f172a;color:#e2e8f0;padding:10px 12px;border-radius:6px;overflow:auto;white-space:pre-wrap;word-break:break-word;font-size:12px}
.st-error{color:#b91c1c;font-weight:600}.st-empty{color:var(--muted)}.st-ok{color:#15803d}
@media print{body{background:#fff}.bar{display:none}.page{border:0;border-radius:0;margin:0;max-width:none;padding:0;page-break-after:always}.cover{min-height:95vh}pre{border:1px solid #cbd5e1;background:#f8fafc;color:#0f172a}}
@page{size:A4;margin:16mm}
"""


def build_report(domain: str, results: dict, **options) -> str:
    """Convenience for one domain's results (what the API and the dashboard have)."""
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    doc = formats.build_document([{"domain": domain, "scanned_at": now, "duration_seconds": None, "results": results}], include_results=False)
    return to_html_report(doc, **options)
