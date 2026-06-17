import asyncio
import aiohttp
import re
import os
import json
import logging
from utils.utils import serialize_results

logger = logging.getLogger("modules.archive_spy")

class ArchiveSpy:
    def __init__(self, domain, timeout=15):
        self.domain = domain
        self.timeout = timeout
        self.output_dir = os.path.join("logs", self.domain)
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
        self.output_file = os.path.join(self.output_dir, "archive_secrets.json")
        self.secrets = []

        # Use common patterns or fall back
        self.secret_patterns = {
            "AWS API Key": r"AKIA[0-9A-Z]{16}",
            "Google API Key": r"AIza[Sy][0-9A-Za-z-_]{35}",
            "Slack Token": r"xox[bapr]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}",
            "Generic Password/Secret": r"(?i)(password|passwd|secret|api_key|apikey|token|private_key)\s*[:=]\s*['\"][a-zA-Z0-9_\-\.\@\/]{8,40}['\"]",
            "JWT Token": r"eyJhbGciOi[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
            "Generic Private Key": r"-----BEGIN[ A-Z0-9_-]+PRIVATE KEY-----",
            "Database Connection URL": r"mongodb(\+srv)?://[a-zA-Z0-9_\-\.\%\:]+:[a-zA-Z0-9_\-\.\%\:]+@[a-zA-Z0-9_\-\.\:]+/[a-zA-Z0-9_\-\.]+"
        }

    async def run(self):
        """Scrapes web archive history for secrets"""
        logger.info(f"Starting Web Archive Time Machine Spy for {self.domain}")
        urls_to_check = await self._fetch_archive_urls()
        if not urls_to_check:
            logger.info("No archive history urls found.")
            return {"domain": self.domain, "secrets": [], "message": "No historical data found"}

        logger.info(f"Found {len(urls_to_check)} historical assets in Wayback Machine. Scanning files...")
        await self._scan_assets(urls_to_check)

        # Save output
        results = {
            "domain": self.domain,
            "total_secrets_found": len(self.secrets),
            "secrets": self.secrets
        }
        with open(self.output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2)

        return results

    async def _fetch_archive_urls(self):
        """Fetches list of JS/config/env files from CDX API"""
        cdx_url = "http://web.archive.org/cdx/search/cdx"
        params = {
            "url": f"*.{self.domain}/*",
            "output": "json",
            "fl": "original,mimetype",
            "collapse": "urlkey",
            "limit": 500
        }
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(cdx_url, params=params, timeout=self.timeout) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if len(data) <= 1:
                            return []
                        
                        # Filter for interesting file extensions or MIME types
                        valid_urls = []
                        for row in data[1:]:  # skip header row
                            original_url = row[0]
                            mimetype = row[1] or ""
                            
                            # Filter JS, JSON, XML, TXT, ENV files
                            if (any(original_url.endswith(ext) for ext in [".js", ".json", ".xml", ".env", ".config", ".yml", ".yaml"]) or 
                                "javascript" in mimetype or "json" in mimetype):
                                # Skip common library wrappers to optimize
                                if not any(lib in original_url.lower() for lib in ["jquery", "bootstrap", "angular", "react-dom", "vue"]):
                                    valid_urls.append(original_url)
                        return list(set(valid_urls))[:30]  # Limit to 30 assets to prevent rate limits
        except Exception as e:
            logger.error(f"Error fetching archive CDX urls: {e}")
        return []

    async def _scan_assets(self, urls):
        """Scrapes and scans each URL for secrets"""
        async with aiohttp.ClientSession() as session:
            tasks = []
            for url in urls:
                # Wayback Machine rewrite url
                wayback_url = f"http://web.archive.org/web/0/{url}"
                tasks.append(self._download_and_scan(session, wayback_url, url))
            await asyncio.gather(*tasks)

    async def _download_and_scan(self, session, wayback_url, original_url):
        try:
            async with session.get(wayback_url, timeout=10) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    
                    # Scan for secrets using regex
                    for name, pattern in self.secret_patterns.items():
                        matches = re.finditer(pattern, text)
                        for match in matches:
                            matched_val = match.group(0)
                            
                            # Mask the secret for display safety
                            masked_val = matched_val[:6] + "..." + matched_val[-4:] if len(matched_val) > 10 else "..."
                            
                            # Extract context
                            start = max(0, match.start() - 30)
                            end = min(len(text), match.end() + 30)
                            context = text[start:end].replace('\n', ' ').strip()
                            
                            self.secrets.append({
                                "file_url": original_url,
                                "wayback_url": wayback_url,
                                "type": name,
                                "value": masked_val,
                                "context": context,
                                "severity": "High" if "Password" not in name else "Medium"
                            })
        except Exception:
            pass  # Fail silently on network errors
