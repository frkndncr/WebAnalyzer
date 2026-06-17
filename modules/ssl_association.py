import asyncio
import aiohttp
import re
import socket
import ssl
import logging
import os
import json

logger = logging.getLogger("modules.ssl_association")

class SSLAssociation:
    def __init__(self, domain, timeout=10):
        self.domain = domain
        self.timeout = timeout
        self.output_dir = os.path.join("logs", self.domain)
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
        self.output_file = os.path.join(self.output_dir, "ssl_association.json")
        self.sans = set()

    async def run(self):
        logger.info(f"Starting SSL Certificate SAN Association for {self.domain}")
        
        # 1. Direct Socket Connection Query (Extract from live cert)
        await self._fetch_live_sans()

        # 2. crt.sh Scraping Query
        await self._fetch_crt_sh_sans()

        # Deduplicate and sort findings
        clean_sans = sorted(list(self.sans))
        
        # Remove wildcard indicators for cleaner reporting (but keep records)
        results = {
            "domain": self.domain,
            "total_san_domains": len(clean_sans),
            "associated_domains": clean_sans
        }

        with open(self.output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2)

        return results

    async def _fetch_live_sans(self):
        """Query direct SSL socket on port 443 to get SAN names"""
        loop = asyncio.get_event_loop()
        try:
            # Run socket operation in executor
            sans = await loop.run_in_executor(None, self._query_socket_cert)
            if sans:
                self.sans.update(sans)
        except Exception as e:
            logger.error(f"Error querying SSL socket for SANs: {e}")

    def _query_socket_cert(self):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.domain, 443), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    names = []
                    if cert and "subjectAltName" in cert:
                        for entry in cert["subjectAltName"]:
                            if entry[0] == "DNS":
                                names.append(entry[1])
                    return names
        except Exception:
            return []

    async def _fetch_crt_sh_sans(self):
        """Query crt.sh JSON API for historical SAN names"""
        url = f"https://crt.sh/?q={self.domain}&output=json"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=self.timeout) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for cert in data:
                            name_value = cert.get("name_value", "")
                            # name_value can have newline-separated domains
                            for name in name_value.split("\n"):
                                name = name.strip().lower()
                                if name and not name.startswith("*."):
                                    self.sans.add(name)
                                elif name.startswith("*."):
                                    # also record base domain if wildcard is used
                                    self.sans.add(name[2:])
                                    self.sans.add(name)
        except Exception as e:
            logger.error(f"Error querying crt.sh API: {e}")
