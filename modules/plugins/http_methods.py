"""HTTP behaviour: plain-HTTP redirect, risky methods and TRACE. Passive: a handful of ordinary requests."""
from modules.registry import module
from utils import webprobe

RISKY = ("PUT", "DELETE", "TRACE", "CONNECT")


def _finding(title, severity, description, recommendation, location=""):
    out = {"title": title, "severity": severity, "description": description, "recommendation": recommendation}
    if location:
        out["location"] = location
    return out


def _https_redirect(domain, get):
    """``(status, redirects_to_https)`` for the plain-HTTP home page, or ``(None, None)`` when nothing listens."""
    try:
        response = (get or webprobe.default_get)(f"http://{domain}/", method="GET", headers=None)
    except Exception:  # noqa: BLE001
        return None, None
    location = response.headers.get("Location", "")
    return response.status_code, response.status_code in webprobe.REDIRECTS and location.lower().startswith("https://")


@module("HTTP Methods & Redirects", description="HTTP to HTTPS redirect, risky methods, TRACE", group="security", weight="light", order=179)
def http_methods(domain, get=None):
    domain = webprobe.clean_host(domain)
    if not domain:
        return {"error": "not a valid domain name"}
    findings = []

    status, redirects = _https_redirect(domain, get)
    if status == 200:
        findings.append(_finding("Site is served over plain HTTP without redirecting", "medium",
                                 "http:// returns the site instead of redirecting to https://, so visitors can be downgraded or intercepted.",
                                 "Redirect all HTTP traffic to HTTPS (301) and enable HSTS.", f"http://{domain}/"))
    elif status in webprobe.REDIRECTS and not redirects:
        findings.append(_finding("HTTP redirects somewhere other than HTTPS", "low", "http:// is redirected, but not to an https:// address.",
                                 "Redirect HTTP to the HTTPS version of the same site.", f"http://{domain}/"))

    allowed = []
    options, url = webprobe.fetch(domain, "/", get=get, method="OPTIONS")
    if options is not None:
        allowed = [m.strip().upper() for m in options.headers.get("Allow", "").split(",") if m.strip()]
    risky = [m for m in allowed if m in RISKY]
    if risky:
        findings.append(_finding("Risky HTTP methods advertised: " + ", ".join(risky), "low",
                                 "The server lists methods that are rarely needed on a public site.",
                                 "Disable methods you do not use (PUT, DELETE, TRACE, CONNECT).", url))

    trace_enabled = False
    trace, url = webprobe.fetch(domain, "/", get=get, method="TRACE", headers={"X-WebAnalyzer-Trace": "probe"})
    if trace is not None and trace.status_code == 200 and "x-webanalyzer-trace" in webprobe.text(trace, 4096).lower():
        trace_enabled = True
        findings.append(_finding("HTTP TRACE is enabled", "medium", "The server echoes TRACE requests, which can expose headers to cross-site tracing attacks.",
                                 "Disable the TRACE method.", url))
    return {"http_status": status, "http_redirects_to_https": redirects, "allowed_methods": allowed, "trace_enabled": trace_enabled, "findings": findings}
