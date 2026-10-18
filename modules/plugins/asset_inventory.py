"""What the domain points at: addresses, owning network (ASN) and certificate-transparency host names.

Passive for the target: DNS lookups (including Team Cymru's IP-to-ASN DNS service) and one
query to crt.sh, a public certificate-transparency search. The target is never contacted.
"""
import ipaddress
import re

from modules.registry import module
from utils import webprobe

CRTSH = "https://crt.sh/?q=%25.{domain}&output=json"
MAX_NAMES = 500
INTERESTING = re.compile(r"(^|[.-])(dev|test|staging|stage|uat|qa|internal|intranet|admin|vpn|jenkins|gitlab|git|jira|sandbox|old|backup|beta)([.-]|\d|$)", re.I)


def _finding(title, severity, description, recommendation):
    return {"title": title, "severity": severity, "description": description, "recommendation": recommendation}


def asn_for(ip, resolve):
    """Origin AS information for an IPv4 address via Team Cymru's DNS service, or None."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if address.version != 4:
        return None
    reversed_ip = ".".join(reversed(str(address).split(".")))
    answer = (resolve(f"{reversed_ip}.origin.asn.cymru.com", "TXT") or [""])[0]
    parts = [p.strip() for p in answer.strip('"').split("|")]
    if len(parts) < 3 or not parts[0]:
        return None
    asn = parts[0].split()[0]
    name_answer = (resolve(f"AS{asn}.asn.cymru.com", "TXT") or [""])[0]
    name_parts = [p.strip() for p in name_answer.strip('"').split("|")]
    return {"ip": str(address), "asn": f"AS{asn}", "prefix": parts[1], "country": parts[2], "name": name_parts[-1] if len(name_parts) >= 5 else None}


def ct_subdomains(domain, fetch_json=None):
    """Host names under ``domain`` that appear in certificate-transparency logs."""
    if fetch_json is None:
        import requests

        def fetch_json(url):
            response = requests.get(url, timeout=20, headers={"User-Agent": webprobe.USER_AGENT})
            response.raise_for_status()
            return response.json()

    rows = fetch_json(CRTSH.format(domain=domain))
    names = set()
    for row in rows if isinstance(rows, list) else []:
        for name in str(row.get("name_value", "")).splitlines():
            name = name.strip().lower().lstrip("*.")
            if name == domain or name.endswith("." + domain):
                names.add(name)
        if len(names) >= MAX_NAMES:
            break
    return sorted(names)


@module("Asset Inventory", description="Addresses, owning networks and certificate-transparency host names", group="recon", weight="medium", order=45)
def asset_inventory(domain, resolve=None, fetch_json=None):
    domain = webprobe.clean_host(domain)
    if not domain:
        return {"error": "not a valid domain name"}
    resolve = resolve or webprobe.resolve
    addresses = [a for a in (resolve(domain, "A") or [])] + [a for a in (resolve(domain, "AAAA") or [])]
    networks = [info for info in (asn_for(a, resolve) for a in addresses) if info]
    ct_error = None
    try:
        names = ct_subdomains(domain, fetch_json)
    except Exception as exc:  # noqa: BLE001 - crt.sh is slow and often down: not a scan failure
        names, ct_error = [], type(exc).__name__
    interesting = [n for n in names if INTERESTING.search(n[: -len(domain)])]
    findings = []
    if interesting:
        findings.append(_finding(
            f"{len(interesting)} certificate-transparency host name(s) suggest internal or non-production systems", "low",
            "Public certificate logs list: " + ", ".join(interesting[:8]) + (" ..." if len(interesting) > 8 else "")
            + ". Anyone can read these logs, so the names tell attackers where to look.",
            "Check that these hosts are meant to be public and not forgotten; use a wildcard or private CA for internal systems."))
    return {"addresses": addresses, "networks": networks, "ct_subdomains": names, "ct_error": ct_error, "findings": findings}
