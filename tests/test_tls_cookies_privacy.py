from datetime import datetime, timedelta, timezone

import pytest

from modules.plugins import cookies_cors as cc
from modules.plugins import privacy_trackers as pt
from modules.plugins import tls_health as tls

NOW = datetime(2026, 10, 18, tzinfo=timezone.utc)


def titles(out):
    return {f["title"]: f["severity"] for f in out["findings"]}


# ───────────────────────────── TLS ─────────────────────────────

def good_info(**over):
    return {"verified": True, "version": "TLSv1.3", "not_after": (NOW + timedelta(days=200)).isoformat(),
            "key_type": "RSA", "key_bits": 2048, "signature_hash": "sha256", "self_signed": False, **over}


def run_tls(info, legacy=False):
    return tls.tls_health("example.org", inspect=lambda d: info, legacy=lambda d: legacy, now=NOW)


def test_a_healthy_certificate_has_no_findings():
    out = run_tls(good_info())
    assert out["findings"] == [] and out["days_left"] == 200 and out["reachable"]


@pytest.mark.parametrize("days,title,severity", [
    (-3, "Certificate has expired", "high"),
    (5, "Certificate expires within a week", "high"),
    (20, "Certificate expires soon", "medium"),
])
def test_expiry_windows(days, title, severity):
    out = run_tls(good_info(not_after=(NOW + timedelta(days=days, hours=1)).isoformat()))
    assert titles(out) == {title: severity}


def test_untrusted_weak_and_legacy_findings():
    out = run_tls(good_info(verified=False, verify_error="self-signed certificate", self_signed=True, key_bits=1024, signature_hash="sha1"), legacy=True)
    assert titles(out) == {"Certificate is not trusted": "high", "Self-signed certificate": "medium", "Weak RSA key": "high",
                           "Certificate signed with a weak hash": "medium", "TLS 1.0/1.1 still enabled": "medium"}


def test_an_old_best_protocol_is_reported_once():
    out = run_tls(good_info(version="TLSv1"), legacy=True)
    assert titles(out) == {"Server negotiates an obsolete TLS version": "medium"}


def test_untestable_legacy_protocols_are_not_a_finding():
    assert run_tls(good_info(), legacy=None)["findings"] == []


def test_an_unreachable_server_is_not_an_error_finding():
    out = tls.tls_health("example.org", inspect=lambda d: {"error": "no TLS connection: TimeoutError"})
    assert out["reachable"] is False and out["findings"] == []


def test_certificate_parsing_with_a_real_certificate():
    pytest.importorskip("cryptography")
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.org")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(NOW - timedelta(days=1)).not_valid_after(NOW + timedelta(days=10))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("example.org")]), critical=False)
            .sign(key, hashes.SHA256()))
    parsed = tls.parse_certificate(cert.public_bytes(serialization.Encoding.DER))
    assert parsed["self_signed"] is True and parsed["key_bits"] == 2048 and parsed["san"] == ["example.org"]
    assert parsed["signature_hash"] == "sha256" and parsed["not_after"].startswith("2026-10-28")


def test_garbage_certificates_do_not_crash():
    assert tls.parse_certificate(b"not a certificate") == {}


# ───────────────────────── cookies & CORS ─────────────────────────

class Resp:
    def __init__(self, headers=None, cookies=(), status=200, body=""):
        self.status_code, self.headers, self.set_cookie_headers, self.content = status, headers or {}, list(cookies), body.encode()


def serve(cookies=(), cors=None):
    def get(url, method="GET", headers=None):
        origin = (headers or {}).get("Origin")
        return Resp(cors(origin) if (cors and origin) else {}, cookies)
    return get


def test_cookie_flags():
    out = cc.cookies_cors("example.org", get=serve(["sessionid=abc; Path=/", "theme=dark; Secure; HttpOnly; SameSite=Lax"]))
    found = titles(out)
    assert found["Cookie 'sessionid' lacks Secure and HttpOnly"] == "medium"
    assert found["Cookie 'sessionid' has no SameSite attribute"] == "low"
    assert not any("theme" in t for t in found)


def test_non_session_cookies_are_low():
    out = cc.cookies_cors("example.org", get=serve(["lang=tr"]))
    assert titles(out) == {"Cookie 'lang' lacks Secure and HttpOnly": "low"}


def test_samesite_none_without_secure():
    out = cc.cookies_cors("example.org", get=serve(["a=1; HttpOnly; SameSite=None"]))
    assert "Cookie 'a' lacks Secure" in titles(out) and "Cookie 'a' uses SameSite=None without Secure" in titles(out)


def test_cors_reflection_with_credentials_is_high():
    reflect = lambda origin: {"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true"}  # noqa: E731
    out = cc.cookies_cors("example.org", get=serve(cors=reflect))
    assert titles(out)["CORS reflects arbitrary origins with credentials"] == "high"
    assert titles(out)["CORS trusts the 'null' origin"] == "high"


def test_cors_wildcard_alone_is_fine_and_a_fixed_origin_is_fine():
    assert cc.cookies_cors("example.org", get=serve(cors=lambda o: {"Access-Control-Allow-Origin": "*"}))["findings"] == []
    assert cc.cookies_cors("example.org", get=serve(cors=lambda o: {"Access-Control-Allow-Origin": "https://app.example.org"}))["findings"] == []


def test_unreachable_site():
    def down(url, method="GET", headers=None):
        raise OSError("refused")
    assert cc.cookies_cors("example.org", get=down)["reachable"] is False


# ───────────────────────── privacy & trackers ─────────────────────────

PAGE = """<html><head>
<script src="https://www.googletagmanager.com/gtm.js?id=GTM-1"></script>
<script src="//static.hotjar.com/c/hotjar-1.js"></script>
<script src="/local.js"></script></head>
<body><a href="/legal/privacy">Privacy</a></body></html>"""


def page(html):
    return lambda url, method="GET", headers=None: Resp(body=html)


def test_trackers_without_consent_are_flagged_with_honest_wording():
    out = pt.privacy_trackers("example.org", get=page(PAGE))
    assert [t["name"] for t in out["trackers"]] == ["Google Tag Manager", "Hotjar"]
    assert titles(out)["Trackers load with no detectable consent manager"] == "medium"
    assert "Session-recording tool in use" in titles(out)
    assert "JavaScript-injected" in next(f for f in out["findings"] if f["title"].startswith("Trackers"))["description"]
    assert "No privacy policy link found on the home page" not in titles(out)


def test_a_consent_manager_silences_the_tracker_finding():
    html = PAGE.replace("<body>", '<body><script src="https://cdn.cookiebot.com/uc.js"></script>')
    assert "Trackers load with no detectable consent manager" not in titles(pt.privacy_trackers("example.org", get=page(html)))


def test_first_party_hosts_are_not_trackers():
    out = pt.analyse('<script src="https://static.example.org/a.js"></script>', "example.org")
    assert out["trackers"] == [] and out["third_party_hosts"] == []


def test_missing_privacy_policy_and_turkish_links():
    assert "No privacy policy link found on the home page" in titles(pt.privacy_trackers("example.org", get=page("<html></html>")))
    assert pt.analyse('<a href="/kvkk-aydinlatma">KVKK Aydınlatma Metni</a>', "example.org")["privacy_policy_link"] == "/kvkk-aydinlatma"


def test_a_non_200_home_page_yields_nothing():
    assert pt.privacy_trackers("example.org", get=lambda u, method="GET", headers=None: Resp(status=503))["findings"] == []
