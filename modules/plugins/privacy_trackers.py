"""Third-party trackers and consent signals on the home page (KVKK / GDPR hygiene).

Passive: one GET of the home page. It reads the static HTML only, so trackers or
consent banners injected later by JavaScript are not seen; findings say so.
"""
import re
from urllib.parse import urlparse

from modules.registry import module
from utils import webprobe

TRACKERS = {
    "google-analytics.com": ("Google Analytics", "analytics"), "googletagmanager.com": ("Google Tag Manager", "tag manager"),
    "doubleclick.net": ("Google Ads / DoubleClick", "advertising"), "googleadservices.com": ("Google Ads", "advertising"),
    "connect.facebook.net": ("Meta Pixel", "advertising"), "facebook.net": ("Meta Pixel", "advertising"),
    "hotjar.com": ("Hotjar", "session recording"), "clarity.ms": ("Microsoft Clarity", "session recording"),
    "mouseflow.com": ("Mouseflow", "session recording"), "fullstory.com": ("FullStory", "session recording"),
    "static.ads-twitter.com": ("X (Twitter) Pixel", "advertising"), "analytics.tiktok.com": ("TikTok Pixel", "advertising"),
    "snap.licdn.com": ("LinkedIn Insight Tag", "advertising"), "yandex.ru/metrika": ("Yandex Metrica", "analytics"),
    "mc.yandex.ru": ("Yandex Metrica", "analytics"), "cdn.segment.com": ("Segment", "analytics"),
    "js.hs-scripts.com": ("HubSpot", "marketing"), "static.criteo.net": ("Criteo", "advertising"),
}
CONSENT_MARKERS = ("cookiebot", "onetrust", "cookieconsent", "osano", "termly", "iubenda", "usercentrics", "klaro",
                   "cookiehub", "complianz", "borlabs", "quantcast", "trustarc", "cookie-law", "cookie-notice", "didomi", "axeptio")
CONSENT_WORDS = re.compile(r"çerez|cerez|cookie|kvkk|consent|rıza", re.I)
POLICY_LINK = re.compile(r"privacy|gizlilik|kvkk|ayd[ıi]nlatma|datenschutz|confidentialit|privacidad|personal data|ki[sş]isel veri", re.I)
_URL_ATTR = re.compile(r"""(?:src|href|data-src)\s*=\s*["']([^"']+)["']""", re.I)
_ANCHOR = re.compile(r"<a\b[^>]*href\s*=\s*[\"']([^\"']+)[\"'][^>]*>(.*?)</a>", re.I | re.S)


def _finding(title, severity, description, recommendation, location=""):
    out = {"title": title, "severity": severity, "description": description, "recommendation": recommendation}
    if location:
        out["location"] = location
    return out


def analyse(html, domain):
    """Pure: trackers, third-party hosts and consent signals found in ``html``."""
    lowered = html.lower()
    hosts = set()
    trackers = {}
    for raw in _URL_ATTR.findall(html):
        if raw.startswith("//"):
            raw = "https:" + raw
        parsed = urlparse(raw)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            continue
        host = parsed.hostname.lower()
        if host == domain or host.endswith("." + domain):
            continue
        hosts.add(host)
        target = host + parsed.path
        for key, (name, category) in TRACKERS.items():
            if key in target:
                trackers[name] = category
    consent = sorted({m for m in CONSENT_MARKERS if m in lowered})
    has_banner_text = bool(CONSENT_WORDS.search(re.sub(r"<script.*?</script>|<style.*?</style>", " ", html, flags=re.I | re.S)))
    policy = next((href for href, label in _ANCHOR.findall(html) if POLICY_LINK.search(href) or POLICY_LINK.search(re.sub("<[^>]+>", " ", label))), None)
    return {"trackers": [{"name": n, "category": c} for n, c in sorted(trackers.items())],
            "third_party_hosts": sorted(hosts), "consent_managers": consent,
            "consent_text_found": has_banner_text, "privacy_policy_link": policy}


@module("Privacy & Trackers", description="Third-party trackers, consent and privacy-policy signals", group="security", weight="light", order=177)
def privacy_trackers(domain, get=None):
    domain = webprobe.clean_host(domain)
    if not domain:
        return {"error": "not a valid domain name"}
    response, url = webprobe.fetch(domain, "/", get=get)
    if response is None or response.status_code != 200:
        return {"reachable": False, "findings": []}
    data = analyse(webprobe.text(response), domain)
    findings = []
    if data["trackers"] and not data["consent_managers"]:
        names = ", ".join(t["name"] for t in data["trackers"])
        findings.append(_finding(
            "Trackers load with no detectable consent manager", "medium",
            f"The page references {names} but no known consent management platform. Consent may be handled by custom or "
            "JavaScript-injected code that a static scan cannot see.",
            "Load trackers only after consent (KVKK / GDPR / ePrivacy) and use a consent manager.", url))
    if not data["privacy_policy_link"]:
        findings.append(_finding("No privacy policy link found on the home page", "low",
                                 "No link that looks like a privacy policy / aydınlatma metni was found in the page.",
                                 "Link the privacy notice from every page (for example the footer).", url))
    if any(t["category"] == "session recording" for t in data["trackers"]):
        findings.append(_finding("Session-recording tool in use", "info",
                                 "Session recording captures what visitors do and can capture personal data.",
                                 "Mask form fields, disclose it in the privacy notice and require consent.", url))
    return {"reachable": True, **data, "findings": findings}
