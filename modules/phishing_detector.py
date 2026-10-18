import asyncio
import dns.resolver
import ipaddress
import logging
import os
import json

logger = logging.getLogger("modules.phishing_detector")

KEYWORDS = ("login", "secure", "verify", "portal", "support", "update", "signin")


def severity_for(kind, resolves_to_target, has_mx):
    """How worrying a look-alike domain that resolves is.

    * same addresses as the target: almost certainly the owner's own defensive registration -> info
    * can receive or send mail (MX): usable for impersonation by e-mail -> high
    * credential-lure wording (login-, secure-, ...): built to deceive -> high
    * otherwise it is simply registered and live -> medium
    """
    if resolves_to_target:
        return "Info"
    if has_mx or kind == "keyword":
        return "High"
    return "Medium"


class PhishingDetector:
    def __init__(self, domain, timeout=2, lookup=None, write_output=True):
        self.domain = domain
        self.timeout = timeout
        self.write_output = write_output
        self._lookup = lookup or self._dns_lookup          # lookup(name, rtype) -> list of text answers
        # Separate domain and tld
        parts = domain.split(".")
        if len(parts) >= 2:
            self.tld = parts[-1]
            self.name = ".".join(parts[:-1])
        else:
            self.name = domain
            self.tld = "com"

        self.output_dir = os.path.join("logs", self.domain)
        self.output_file = os.path.join(self.output_dir, "phishing_domains.json")
        self.detected_domains = []
        self.target_ips = set()

    @staticmethod
    def is_ip(value):
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def _candidates(self):
        """Typosquatted / homoglyph / keyword domains as ``{name: kind}``."""
        found = {}
        name, tld = self.name, self.tld

        # Character omission
        for i in range(len(name)):
            omitted = name[:i] + name[i + 1:]
            if omitted:
                found.setdefault(f"{omitted}.{tld}", "omission")

        # Character substitution (adjacent keys on QWERTY)
        qwerty_neighbors = {
            'a': 'qwsz', 'b': 'vghn', 'c': 'xdfv', 'd': 'ersfxc', 'e': 'wsdr',
            'f': 'rtgvcd', 'g': 'tyhbvf', 'h': 'yujnbg', 'i': 'ujko', 'j': 'uikmnh',
            'k': 'ijlm', 'l': 'okp', 'm': 'njk', 'n': 'bhjm', 'o': 'iklp',
            'p': 'ol', 'q': 'wa', 'r': 'edtf', 's': 'wadezx', 't': 'rfgy',
            'u': 'yhji', 'v': 'cfgb', 'w': 'qase', 'x': 'zsdc', 'y': 'tghu',
            'z': 'asx'
        }
        for i, char in enumerate(name):
            for replacement in qwerty_neighbors.get(char, ""):
                found.setdefault(f"{name[:i]}{replacement}{name[i + 1:]}.{tld}", "substitution")

        # Homoglyphs (look-alike characters)
        homoglyphs = {
            'a': ['а', 'á'],  # cyrillic a, accented
            'c': ['с'],            # cyrillic c
            'e': ['е'],            # cyrillic e
            'i': ['ı', 'i̇'],  # dotless i, dotted i
            'o': ['о', '0', 'ö'],   # cyrillic o, zero, o-umlaut
            's': ['ѕ'],            # cyrillic s
            'p': ['р'],            # cyrillic p
            'y': ['у', 'ý'],       # cyrillic y, y-acute
        }
        for i, char in enumerate(name):
            for replacement in homoglyphs.get(char, []):
                found.setdefault(f"{name[:i]}{replacement}{name[i + 1:]}.{tld}", "homoglyph")

        # Common additions (credential-lure wording)
        for add in KEYWORDS:
            found.setdefault(f"{name}-{add}.{tld}", "keyword")
            found.setdefault(f"{add}-{name}.{tld}", "keyword")

        found.pop(self.domain, None)
        return found

    @staticmethod
    def _select(candidates, limit):
        """At most ``limit`` candidates, taking each kind in turn so a long name cannot crowd out homoglyphs and keywords."""
        by_kind = {}
        for name, kind in candidates.items():
            by_kind.setdefault(kind, []).append((name, kind))
        chosen = []
        while len(chosen) < limit and any(by_kind.values()):
            for kind in list(by_kind):
                if by_kind[kind] and len(chosen) < limit:
                    chosen.append(by_kind[kind].pop(0))
        return chosen

    def _generate_typosquat_domains(self):
        """Kept for callers that only want the names."""
        return list(self._candidates())

    @staticmethod
    def _ascii(domain):
        """The wire form of a domain: IDN look-alikes (Cyrillic letters ...) are looked up as punycode."""
        try:
            return domain.encode("idna").decode("ascii")
        except UnicodeError:
            return None

    async def _resolve_domain(self, domain, kind="omission"):
        """Resolve a candidate and record it, with a severity based on what it can be used for."""
        loop = asyncio.get_event_loop()
        wire = self._ascii(domain)
        if not wire:
            return
        try:
            answers = await loop.run_in_executor(None, lambda: self._lookup(wire, "A"))
            if not answers:
                return
            mx = await loop.run_in_executor(None, lambda: self._lookup(wire, "MX"))
        except Exception:
            return
        same = bool(self.target_ips) and set(answers) <= self.target_ips
        self.detected_domains.append({
            "domain": domain,
            "punycode": wire if wire != domain else None,
            "ips": answers,
            "kind": kind,
            "has_mx": bool(mx),
            "same_as_target": same,
            "status": "Active",
            "severity": severity_for(kind, same, bool(mx)),
        })

    def _dns_lookup(self, domain, rtype="A"):
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout
            result = resolver.resolve(domain, rtype)
            return [str(r).split()[-1] if rtype == "MX" else str(r) for r in result]
        except Exception:
            return []

    async def run(self):
        logger.info(f"Starting Typosquatting / Phishing Domain Protection for {self.domain}")
        if self.is_ip(self.domain):
            return {"domain": self.domain, "skipped": "look-alike checks apply to domain names, not IP addresses",
                    "total_candidates_scanned": 0, "total_active_phishing_domains": 0, "phishing_domains": []}

        self.target_ips = set(self._lookup(self.domain, "A") or [])
        candidates = self._select(self._candidates(), 100)       # limit the list size to prevent huge delays
        logger.info(f"Generated {len(candidates)} phishing candidates to probe.")

        # Asynchronously resolve candidates in batches
        batch_size = 10
        for i in range(0, len(candidates), batch_size):
            batch = candidates[i:i + batch_size]
            await asyncio.gather(*[self._resolve_domain(dom, kind) for dom, kind in batch])
            await asyncio.sleep(0.1)  # Cooldown

        results = {
            "domain": self.domain,
            "total_candidates_scanned": len(candidates),
            "total_active_phishing_domains": len(self.detected_domains),
            "phishing_domains": self.detected_domains
        }

        if not self.write_output:
            return results
        try:
            os.makedirs(self.output_dir, exist_ok=True)
            with open(self.output_file, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2)
        except OSError as exc:                                  # a read-only disk must not fail the module
            logger.warning(f"Could not write {self.output_file}: {exc}")

        return results
