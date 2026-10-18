"""DNS hygiene: nameserver redundancy, dangling nameservers, CAA and DNSSEC. Passive (DNS lookups only)."""
from modules.registry import module
from utils import webprobe


def _finding(title, severity, description, recommendation):
    return {"title": title, "severity": severity, "description": description, "recommendation": recommendation}


@module("DNS Health", description="Nameserver redundancy, dangling NS, CAA and DNSSEC", group="security", weight="light", order=171)
def dns_health(domain, resolve=None):
    domain = webprobe.clean_host(domain)
    if not domain:
        return {"error": "not a valid domain name"}
    resolve = resolve or webprobe.resolve
    nameservers = sorted({n.lower().rstrip(".") for n in (resolve(domain, "NS") or [])})
    findings = []
    if not nameservers:
        return {"nameservers": [], "findings": []}

    if len(nameservers) < 2:
        findings.append(_finding("Only one nameserver", "medium", f"{domain} is served by a single nameserver ({nameservers[0]}): if it fails, the domain is unreachable.",
                                 "Add at least two nameservers on independent networks (RFC 2182)."))
    dangling = []
    for ns in nameservers:
        if resolve(ns, "A") is None and resolve(ns, "AAAA") is None:           # None means NXDOMAIN
            dangling.append(ns)
            findings.append(_finding(f"Nameserver {ns} does not exist", "high",
                                     "The delegation points at a host name that does not resolve. Whoever registers that name can serve answers for this domain.",
                                     "Remove the delegation or fix the nameserver name."))
    caa = resolve(domain, "CAA") or []
    if not caa:
        findings.append(_finding("No CAA record", "low", "Any certificate authority may issue certificates for this domain.",
                                 'Publish a CAA record such as \'0 issue "letsencrypt.org"\' for the CAs you use.'))
    dnssec = bool(resolve(domain, "DS"))
    if not dnssec:
        findings.append(_finding("DNSSEC is not enabled", "info", "Answers for this domain are not cryptographically signed.",
                                 "Enable DNSSEC at your registrar and DNS host if they support it."))
    return {"nameservers": nameservers, "dangling": dangling, "caa": caa, "dnssec": dnssec, "findings": findings}
