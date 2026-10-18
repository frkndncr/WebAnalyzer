"""TLS and certificate health: expiry, trust, key strength and legacy protocols.

Passive: it makes ordinary TLS handshakes with the target on port 443.
"""
import socket
import ssl
from datetime import datetime, timezone

from modules.registry import module
from utils import webprobe

TIMEOUT = 8
EXPIRY_HIGH_DAYS = 7
EXPIRY_MEDIUM_DAYS = 30
WEAK_HASHES = ("md5", "sha1")


def _finding(title, severity, description, recommendation):
    return {"title": title, "severity": severity, "description": description, "recommendation": recommendation}


def inspect_server(domain, port=443):
    """What the server presents. Returns a dict, or ``{"error": ...}`` when no TLS connection could be made."""
    info = {"verified": False, "verify_error": None}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain):
                info["verified"] = True
    except ssl.SSLCertVerificationError as exc:
        info["verify_error"] = exc.verify_message or str(exc)
    except (OSError, ssl.SSLError) as exc:
        return {"error": f"no TLS connection: {type(exc).__name__}"}

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((domain, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as tls:
                info["version"] = tls.version()
                info["cipher"] = (tls.cipher() or [None])[0]
                der = tls.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError) as exc:
        return {"error": f"no TLS connection: {type(exc).__name__}"}
    info.update(parse_certificate(der))
    return info


def parse_certificate(der):
    """Expiry, issuer, key and signature details from a DER certificate (needs the ``cryptography`` package)."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import ec, rsa

        cert = x509.load_der_x509_certificate(der)
    except Exception:  # noqa: BLE001 - missing package or unparsable certificate: report what we have
        return {}
    key = cert.public_key()
    key_bits = key.key_size if isinstance(key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)) else None
    key_type = "RSA" if isinstance(key, rsa.RSAPublicKey) else "EC" if isinstance(key, ec.EllipticCurvePublicKey) else type(key).__name__
    try:
        names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    except Exception:  # noqa: BLE001
        names = []
    not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(tzinfo=timezone.utc)
    return {
        "not_after": not_after.isoformat(),
        "issuer": cert.issuer.rfc4514_string(),
        "self_signed": cert.issuer == cert.subject,
        "san": list(names),
        "key_type": key_type,
        "key_bits": key_bits,
        "signature_hash": cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None,
    }


def legacy_protocols_accepted(domain, port=443):
    """True/False when the server does/does not complete a TLS 1.0 or 1.1 handshake; None when it cannot be tested here."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.maximum_version = ssl.TLSVersion.TLSv1_1
    except (ValueError, ssl.SSLError):
        return None                                   # this OpenSSL build cannot speak the old protocols
    try:
        with socket.create_connection((domain, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain):
                return True
    except ssl.SSLError as exc:
        return False if "protocol" in str(exc).lower() or "version" in str(exc).lower() or "handshake" in str(exc).lower() else None
    except OSError:
        return None


def evaluate(domain, info, legacy, now=None):
    now = now or datetime.now(timezone.utc)
    findings = []
    if not info.get("verified"):
        findings.append(_finding(
            "Certificate is not trusted", "high",
            f"A client validating the certificate for {domain} fails with: {info.get('verify_error') or 'unknown reason'}.",
            "Install a certificate from a public CA that covers this host name and includes the full chain."))
    if info.get("not_after"):
        days = (datetime.fromisoformat(info["not_after"]) - now).days
        info["days_left"] = days
        if days < 0:
            findings.append(_finding("Certificate has expired", "high", f"The certificate expired {-days} day(s) ago.", "Renew the certificate."))
        elif days <= EXPIRY_HIGH_DAYS:
            findings.append(_finding("Certificate expires within a week", "high", f"{days} day(s) left.", "Renew now and automate renewal."))
        elif days <= EXPIRY_MEDIUM_DAYS:
            findings.append(_finding("Certificate expires soon", "medium", f"{days} day(s) left.", "Renew it and automate renewal (for example ACME)."))
    if info.get("self_signed") and info.get("verified") is False:
        findings.append(_finding("Self-signed certificate", "medium", "The certificate is signed by itself, not by a public CA.", "Use a certificate from a public CA."))
    if info.get("key_type") == "RSA" and info.get("key_bits") and info["key_bits"] < 2048:
        findings.append(_finding("Weak RSA key", "high", f"The certificate uses a {info['key_bits']}-bit RSA key.", "Reissue with at least a 2048-bit key."))
    if info.get("signature_hash") in WEAK_HASHES:
        findings.append(_finding("Certificate signed with a weak hash", "medium", f"The signature uses {info['signature_hash'].upper()}.", "Reissue with SHA-256 or better."))
    if info.get("version") in ("TLSv1", "TLSv1.1", "SSLv3"):
        findings.append(_finding("Server negotiates an obsolete TLS version", "medium", f"The best protocol offered was {info['version']}.", "Enable TLS 1.2 and 1.3 and disable older versions."))
    elif legacy is True:
        findings.append(_finding("TLS 1.0/1.1 still enabled", "medium", "The server completes handshakes using TLS 1.0 or 1.1, which are deprecated (RFC 8996).", "Disable TLS 1.0 and 1.1."))
    return findings


@module("TLS Health", description="Certificate expiry and trust, key strength, legacy protocols", group="security", weight="light", order=175)
def tls_health(domain, inspect=None, legacy=None, now=None):
    domain = webprobe.clean_host(domain)
    if not domain:
        return {"error": "not a valid domain name"}
    info = (inspect or inspect_server)(domain)
    if info.get("error"):
        return {"reachable": False, "error_detail": info["error"], "findings": []}
    legacy_result = (legacy or legacy_protocols_accepted)(domain)
    findings = evaluate(domain, info, legacy_result, now)
    return {"reachable": True, **info, "legacy_protocols": legacy_result, "findings": findings}
