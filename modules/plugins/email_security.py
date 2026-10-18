"""Email authentication: SPF, DMARC, DKIM and MTA-STS. Passive (DNS lookups and one GET)."""
import re

from modules.registry import module
from utils import webprobe

DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "k1", "k2", "mail", "dkim", "s1", "s2", "mandrill", "smtp")
SPF_LOOKUP_LIMIT = 10
_LOOKUP_TERMS = re.compile(r"^(include:|a(?::|/|$)|mx(?::|/|$)|ptr(?::|$)|exists:|redirect=)", re.I)


def _finding(title, severity, description, recommendation, location=""):
    out = {"title": title, "severity": severity, "description": description, "recommendation": recommendation}
    if location:
        out["location"] = location
    return out


def _records(txts, prefix):
    return [t for t in txts or [] if t.strip().lower().startswith(prefix)]


def count_spf_lookups(domain, txt, record=None, seen=None, budget=SPF_LOOKUP_LIMIT + 2):
    """DNS lookups an SPF record causes, following include: and redirect= (stops once the limit is clearly exceeded)."""
    seen = seen if seen is not None else set()
    if record is None:
        found = _records(txt(domain), "v=spf1")
        record = found[0] if found else ""
    total = 0
    for term in record.split()[1:]:
        term = term.lstrip("+-~?")                       # qualifiers do not change what costs a lookup
        if not _LOOKUP_TERMS.match(term):
            continue
        total += 1
        if total >= budget:
            return total
        lowered = term.lower()
        if lowered.startswith(("include:", "redirect=")):
            target = term.split(":", 1)[-1] if lowered.startswith("include:") else term.split("=", 1)[1]
            if target.lower() not in seen:
                seen.add(target.lower())
                inner = _records(txt(target), "v=spf1")
                if inner:
                    total += count_spf_lookups(target, txt, inner[0], seen, budget - total)
                    if total >= budget:
                        return total
    return total


def check_spf(domain, txt, has_mail):
    records = _records(txt(domain), "v=spf1")
    findings, info = [], {"present": bool(records)}
    if not records:
        findings.append(_finding(
            "No SPF record", "medium" if has_mail else "low",
            f"{domain} publishes no SPF record, so anyone can send mail that appears to come from it."
            if has_mail else f"{domain} sends no mail but has no SPF record that says so.",
            "Publish an SPF TXT record, e.g. 'v=spf1 include:<your provider> -all'"
            if has_mail else "Publish 'v=spf1 -all' to state that this domain sends no mail."))
        return findings, info
    if len(records) > 1:
        findings.append(_finding("Multiple SPF records", "medium",
                                 "More than one SPF record is published; receivers treat this as a permanent error and ignore SPF.",
                                 "Merge them into a single SPF record."))
    record = records[0]
    info["record"] = record
    terms = record.lower().split()
    qualifier = next((t[0] if t[0] in "+-~?" else "+" for t in terms if t.lstrip("+-~?") == "all"), None)
    has_redirect = any(t.startswith("redirect=") for t in terms)
    info["all"] = qualifier
    if qualifier == "+":
        findings.append(_finding("SPF allows every sender (+all)", "high", "'+all' authorises any server to send as this domain.",
                                 "Replace '+all' with '-all' (or '~all' while testing)."))
    elif qualifier == "?":
        findings.append(_finding("SPF is neutral (?all)", "medium", "'?all' gives receivers no guidance on unauthorised senders.",
                                 "End the record with '-all'."))
    elif qualifier == "~":
        findings.append(_finding("SPF uses soft fail (~all)", "low", "'~all' marks unauthorised mail as suspicious but does not reject it.",
                                 "Move to '-all' once all legitimate senders are listed."))
    elif qualifier is None and not has_redirect:
        findings.append(_finding("SPF has no 'all' mechanism", "medium", "The record never says what to do with other senders.",
                                 "End the record with '-all'."))
    lookups = count_spf_lookups(domain, txt, record)
    info["lookups"] = lookups
    if lookups > SPF_LOOKUP_LIMIT:
        findings.append(_finding("SPF exceeds 10 DNS lookups", "medium",
                                 f"The record needs at least {lookups} DNS lookups; the limit is {SPF_LOOKUP_LIMIT}, beyond which SPF fails.",
                                 "Remove unused include: entries or flatten the record."))
    return findings, info


def parse_tags(record):
    tags = {}
    for part in record.split(";"):
        key, _, value = part.strip().partition("=")
        if key:
            tags[key.strip().lower()] = value.strip()
    return tags


def check_dmarc(domain, txt, has_mail):
    records = _records(txt(f"_dmarc.{domain}"), "v=dmarc1")
    if not records:
        return [_finding("No DMARC record", "medium" if has_mail else "low",
                         f"No DMARC policy is published at _dmarc.{domain}, so spoofed mail is not blocked or reported.",
                         "Publish 'v=DMARC1; p=quarantine; rua=mailto:<address>' and move to p=reject.")], {"present": False}
    tags = parse_tags(records[0])
    policy = tags.get("p", "").lower()
    findings, info = [], {"present": True, "record": records[0], "policy": policy or None}
    if policy == "none" or not policy:
        findings.append(_finding("DMARC policy is 'none'", "medium",
                                 "p=none only monitors; spoofed mail is still delivered.",
                                 "Move to p=quarantine, then p=reject, once reports look clean."))
    elif tags.get("pct") and tags["pct"].isdigit() and int(tags["pct"]) < 100:
        findings.append(_finding("DMARC applies to only part of the mail", "low",
                                 f"pct={tags['pct']} means the policy is enforced on that share of messages.",
                                 "Raise pct to 100 when ready."))
    if "rua" not in tags:
        findings.append(_finding("DMARC has no aggregate report address", "low",
                                 "Without rua= you receive no reports about who sends mail as your domain.",
                                 "Add rua=mailto:<address> to the DMARC record."))
    return findings, info


def check_dkim(domain, txt):
    found = [s for s in DKIM_SELECTORS if any("p=" in t.lower() or "v=dkim1" in t.lower() for t in txt(f"{s}._domainkey.{domain}") or [])]
    findings = []
    if not found:
        findings.append(_finding("No DKIM key found at common selectors", "info",
                                 "None of the usual selectors has a DKIM key. A custom selector may be in use, so this is only a hint.",
                                 "Make sure outgoing mail is DKIM-signed."))
    return findings, {"selectors": found}


def check_mta_sts(domain, txt, get, has_mail):
    if not has_mail:
        return [], {"present": False}
    if not _records(txt(f"_mta-sts.{domain}"), "v=stsv1"):
        return [_finding("No MTA-STS policy", "info", "Without MTA-STS, mail servers may deliver to you over unencrypted SMTP.",
                         "Publish an _mta-sts TXT record and a policy at https://mta-sts." + domain + "/.well-known/mta-sts.txt.")], {"present": False}
    response, _ = webprobe.fetch(f"mta-sts.{domain}", "/.well-known/mta-sts.txt", get=get)
    mode = None
    if response is not None and response.status_code == 200:
        match = re.search(r"^mode:\s*(\w+)", webprobe.text(response, 8192), re.M | re.I)
        mode = match.group(1).lower() if match else None
    findings = []
    if mode in ("none", "testing"):
        findings.append(_finding("MTA-STS is not enforcing", "low", f"The policy mode is '{mode}'.", "Set 'mode: enforce' once delivery is verified."))
    elif mode is None:
        findings.append(_finding("MTA-STS policy unreachable", "low", "The _mta-sts record exists but the policy file could not be read.",
                                 f"Serve the policy at https://mta-sts.{domain}/.well-known/mta-sts.txt."))
    return findings, {"present": True, "mode": mode}


@module("Email Security", description="SPF, DKIM, DMARC and MTA-STS", group="security", weight="light", order=170)
def email_security(domain, txt=None, mx=None, get=None):
    domain = webprobe.clean_host(domain)
    if not domain:
        return {"error": "not a valid domain name"}
    txt = txt or (lambda name: webprobe.resolve(name, "TXT") or [])
    mx = mx or (lambda name: webprobe.resolve(name, "MX") or [])
    mx_records = [m for m in mx(domain) if m.strip() not in ("0 .", "")]
    has_mail = bool(mx_records)

    findings = []
    spf_findings, spf = check_spf(domain, txt, has_mail)
    dmarc_findings, dmarc = check_dmarc(domain, txt, has_mail)
    dkim_findings, dkim = check_dkim(domain, txt) if has_mail else ([], {"selectors": []})
    sts_findings, sts = check_mta_sts(domain, txt, get, has_mail)
    findings += spf_findings + dmarc_findings + dkim_findings + sts_findings
    return {"has_mail": has_mail, "mx": mx_records, "spf": spf, "dmarc": dmarc, "dkim": dkim, "mta_sts": sts, "findings": findings}
