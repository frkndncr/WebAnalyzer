"""Cookie flags and CORS policy. Passive: three ordinary requests to the home page."""
import re

from modules.registry import module
from utils import webprobe

PROBE_ORIGIN = "https://webanalyzer-cors-probe.invalid"
_SESSIONISH = re.compile(r"sess|sid\b|auth|token|jwt|login|csrf|xsrf", re.I)


def _finding(title, severity, description, recommendation, location=""):
    out = {"title": title, "severity": severity, "description": description, "recommendation": recommendation}
    if location:
        out["location"] = location
    return out


def parse_cookie(header):
    parts = [p.strip() for p in header.split(";")]
    name, _, _ = parts[0].partition("=")
    attrs = {}
    for part in parts[1:]:
        key, _, value = part.partition("=")
        attrs[key.strip().lower()] = value.strip()
    return {"name": name.strip(), "secure": "secure" in attrs, "httponly": "httponly" in attrs,
            "samesite": attrs.get("samesite", "").lower() or None}


def cookie_findings(cookies, url):
    findings = []
    for cookie in cookies:
        sensitive = bool(_SESSIONISH.search(cookie["name"]))
        missing = []
        if not cookie["secure"]:
            missing.append("Secure")
        if not cookie["httponly"]:
            missing.append("HttpOnly")
        severity = "medium" if sensitive else "low"
        if missing:
            findings.append(_finding(
                f"Cookie '{cookie['name']}' lacks {' and '.join(missing)}", severity,
                "Without Secure the cookie can travel over plain HTTP; without HttpOnly scripts can read it (including injected ones).",
                "Set the missing attributes on the Set-Cookie header.", url))
        if cookie["samesite"] == "none" and not cookie["secure"]:
            findings.append(_finding(f"Cookie '{cookie['name']}' uses SameSite=None without Secure", "medium",
                                     "Browsers reject this combination and it exposes the cookie to cross-site requests.",
                                     "Add Secure or use SameSite=Lax/Strict.", url))
        elif cookie["samesite"] is None and sensitive:
            findings.append(_finding(f"Cookie '{cookie['name']}' has no SameSite attribute", "low",
                                     "Browsers default to Lax, but relying on the default is fragile.",
                                     "Set SameSite=Lax (or Strict) explicitly.", url))
    return findings


def cors_findings(allow_origin, allow_credentials, origin_sent, url):
    if not allow_origin:
        return []
    credentials = (allow_credentials or "").lower() == "true"
    if allow_origin == origin_sent and origin_sent != "null":
        return [_finding("CORS reflects arbitrary origins" + (" with credentials" if credentials else ""),
                         "high" if credentials else "medium",
                         "The server echoes any Origin it is sent back in Access-Control-Allow-Origin"
                         + (" and allows credentials, so any website can read authenticated responses." if credentials else "."),
                         "Allow only an explicit list of trusted origins.", url)]
    if allow_origin == "null":
        return [_finding("CORS trusts the 'null' origin", "medium" if not credentials else "high",
                         "Sandboxed iframes and local files send Origin: null, so allowing it lets them read responses.",
                         "Never allow the 'null' origin.", url)]
    if allow_origin == "*" and credentials:
        return [_finding("CORS wildcard combined with credentials", "low",
                         "Browsers ignore this combination, but it signals a misconfigured policy.",
                         "Use an explicit origin if credentials are needed.", url)]
    return []


@module("Cookies & CORS", description="Cookie flags and cross-origin policy", group="security", weight="light", order=176)
def cookies_cors(domain, get=None):
    domain = webprobe.clean_host(domain)
    if not domain:
        return {"error": "not a valid domain name"}
    response, url = webprobe.fetch(domain, "/", get=get)
    if response is None:
        return {"reachable": False, "cookies": [], "findings": []}
    cookies = [parse_cookie(h) for h in webprobe.set_cookie_headers(response)]
    findings = cookie_findings(cookies, url)

    cors = {}
    for origin in (PROBE_ORIGIN, "null"):
        probe, _ = webprobe.fetch(domain, "/", get=get, headers={"Origin": origin})
        if probe is None:
            continue
        allow, creds = probe.headers.get("Access-Control-Allow-Origin"), probe.headers.get("Access-Control-Allow-Credentials")
        cors[origin] = {"allow_origin": allow, "allow_credentials": creds}
        findings += cors_findings(allow, creds, origin, url)
    return {"reachable": True, "cookies": cookies, "cors": cors, "findings": findings}
