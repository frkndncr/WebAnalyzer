import asyncio
import dns.resolver
import logging
import os
import json

logger = logging.getLogger("modules.phishing_detector")

class PhishingDetector:
    def __init__(self, domain, timeout=2):
        self.domain = domain
        self.timeout = timeout
        # Separate domain and tld
        parts = domain.split(".")
        if len(parts) >= 2:
            self.tld = parts[-1]
            self.name = ".".join(parts[:-1])
        else:
            self.name = domain
            self.tld = "com"
        
        self.output_dir = os.path.join("logs", self.domain)
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
        self.output_file = os.path.join(self.output_dir, "phishing_domains.json")
        self.detected_domains = []

    def _generate_typosquat_domains(self):
        """Generates typosquatted / homoglyph domains"""
        domains = set()
        name = self.name
        tld = self.tld

        # Character omission
        for i in range(len(name)):
            omitted = name[:i] + name[i+1:]
            if omitted:
                domains.add(f"{omitted}.{tld}")

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
            if char in qwerty_neighbors:
                for replacement in qwerty_neighbors[char]:
                    substituted = name[:i] + replacement + name[i+1:]
                    domains.add(f"{substituted}.{tld}")

        # Homoglyphs (look-alike characters)
        homoglyphs = {
            'a': ['а', 'a\u0301'],  # cyrillic a, accented
            'c': ['с'],            # cyrillic c
            'e': ['е'],            # cyrillic e
            'i': ['ı', 'i\u0307'],  # dotless i, dotted i
            'o': ['о', '0', 'ö'],   # cyrillic o, zero, o-umlaut
            's': ['ѕ'],            # cyrillic s
            'p': ['р'],            # cyrillic p
            'y': ['у', 'ý'],       # cyrillic y, y-acute
        }
        for i, char in enumerate(name):
            if char in homoglyphs:
                for replacement in homoglyphs[char]:
                    replaced = name[:i] + replacement + name[i+1:]
                    domains.add(f"{replaced}.{tld}")

        # Common additions
        additions = ["login", "secure", "verify", "portal", "support", "update", "signin"]
        for add in additions:
            domains.add(f"{name}-{add}.{tld}")
            domains.add(f"{add}-{name}.{tld}")

        # Remove the original domain itself
        domains.discard(self.domain)
        return list(domains)

    async def _resolve_domain(self, domain):
        """Asynchronously resolve domain for IP address"""
        loop = asyncio.get_event_loop()
        try:
            # Run blocking DNS resolution in thread pool
            answers = await loop.run_in_executor(None, lambda: self._dns_lookup(domain))
            if answers:
                self.detected_domains.append({
                    "domain": domain,
                    "ips": answers,
                    "status": "Active",
                    "severity": "High"
                })
        except Exception:
            pass

    def _dns_lookup(self, domain):
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout
            result = resolver.resolve(domain, 'A')
            return [str(ip) for ip in result]
        except Exception:
            return []

    async def run(self):
        logger.info(f"Starting Typosquatting / Phishing Domain Protection for {self.domain}")
        candidate_domains = self._generate_typosquat_domains()
        
        # Limit target list size to prevent huge delays (e.g., max 100)
        candidate_domains = list(candidate_domains)[:100]
        
        logger.info(f"Generated {len(candidate_domains)} phishing candidates to probe.")
        
        # Asynchronously resolve candidates in batches
        batch_size = 10
        for i in range(0, len(candidate_domains), batch_size):
            batch = candidate_domains[i:i+batch_size]
            tasks = [self._resolve_domain(dom) for dom in batch]
            await asyncio.gather(*tasks)
            await asyncio.sleep(0.1) # Cooldown

        results = {
            "domain": self.domain,
            "total_candidates_scanned": len(candidate_domains),
            "total_active_phishing_domains": len(self.detected_domains),
            "phishing_domains": self.detected_domains
        }

        with open(self.output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2)

        return results
