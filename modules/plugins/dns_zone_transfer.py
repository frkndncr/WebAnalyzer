"""Does an authoritative nameserver hand out the whole zone (AXFR) to anyone?

ACTIVE: it connects to the domain's own nameservers and asks for a zone transfer, which
is why it needs a verified domain on the public demo.
"""
from modules.registry import module
from utils import webprobe

MAX_NAMESERVERS = 6


def try_axfr(nameserver_ip, domain, timeout=6):
    """Number of names in the zone if the server allows the transfer, else 0."""
    import dns.query
    import dns.zone

    try:
        zone = dns.zone.from_xfr(dns.query.xfr(nameserver_ip, domain, lifetime=timeout))
        return len(zone.nodes)
    except Exception:  # noqa: BLE001 - refused, timed out, malformed: all mean "not allowed"
        return 0


@module("DNS Zone Transfer", description="Open AXFR zone transfers on the nameservers", group="offensive", weight="light", active=True, order=182)
def dns_zone_transfer(domain, resolve=None, axfr=None):
    domain = webprobe.clean_host(domain)
    if not domain:
        return {"error": "not a valid domain name"}
    resolve = resolve or webprobe.resolve
    axfr = axfr or try_axfr
    nameservers = sorted({n.lower().rstrip(".") for n in (resolve(domain, "NS") or [])})[:MAX_NAMESERVERS]
    findings, results = [], []
    for ns in nameservers:
        ips = resolve(ns, "A") or []
        names = axfr(ips[0], domain) if ips else 0
        results.append({"nameserver": ns, "transfer_allowed": names > 0, "names": names})
        if names > 0:
            findings.append({
                "title": f"Zone transfer allowed by {ns}", "severity": "high",
                "description": f"The nameserver returned the whole zone ({names} names) to an anonymous client, exposing every host name in it.",
                "recommendation": "Restrict AXFR to your secondary nameservers (allow-transfer / TSIG).",
            })
    return {"nameservers": nameservers, "results": results, "findings": findings}
