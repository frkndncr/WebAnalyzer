# modules/advanced_content_scanner.py
import re
import os
import json
import time
import logging
from logging.handlers import RotatingFileHandler
import hashlib
import urllib.parse
import math
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse
from collections import deque
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from bs4 import BeautifulSoup
import validators

class AdvancedContentScanner:
    def __init__(self, domain, output_dir=None, max_depth=2, max_pages=100, 
                 timeout=10, max_workers=10, verify_ssl=True, log_level="WARNING",
                 log_file=None, auth=None, user_agent=None, respect_robots=True,
                 rate_limit=1, custom_patterns=None):
        """
        Initialize the Advanced Content Scanner which combines JS Security Analysis,
        API Key & Secret Leakage Detection, and SSRF vulnerability detection.
        
        Args:
            domain (str): Target domain
            output_dir (str, optional): Output directory
            max_depth (int, optional): Maximum crawling depth
            max_pages (int, optional): Maximum pages to crawl
            timeout (int, optional): Request timeout
            max_workers (int, optional): Maximum concurrent workers
            verify_ssl (bool, optional): Whether to verify SSL certificates
            log_level (str, optional): Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            log_file (str, optional): Log file path
            auth (tuple, optional): Authentication (username, password) for Basic Auth
            user_agent (str, optional): Custom User-Agent string
            respect_robots (bool, optional): Whether to respect robots.txt
            rate_limit (float, optional): Minimum seconds between requests
            custom_patterns (dict, optional): Custom detection patterns
        """
        # Input validation
        if not isinstance(domain, str) or not domain:
            raise ValueError("Domain must be a non-empty string")
        if max_depth < 0 or not isinstance(max_depth, int):
            raise ValueError("max_depth must be a non-negative integer")
        if max_pages < 1 or not isinstance(max_pages, int):
            raise ValueError("max_pages must be a positive integer")
        if max_workers < 1 or not isinstance(max_workers, int):
            raise ValueError("max_workers must be a positive integer")
        
        # Normalize domain and create base URL
        self.domain = domain.lower().strip()
        self.base_url = f"https://{domain}" if not domain.startswith(('http://', 'https://')) else domain
        
        # Parse domain for future URL matching
        parsed_url = urlparse(self.base_url)
        self.domain_netloc = parsed_url.netloc
        
        # Configuration parameters
        self.output_dir = output_dir or os.path.join(os.getcwd(), "results", self.domain_netloc)
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout
        self.max_workers = max_workers
        self.verify_ssl = verify_ssl
        self.auth = auth
        self.respect_robots = respect_robots
        self.rate_limit = rate_limit
        
        # Create output directory
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Configure logging
        log_levels = {
            "DEBUG": logging.DEBUG,
            "INFO": logging.INFO,
            "WARNING": logging.WARNING,
            "ERROR": logging.ERROR,
            "CRITICAL": logging.CRITICAL
        }
        
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(log_levels.get(log_level.upper(), logging.WARNING))
        
        # Clear existing handlers
        if self.logger.handlers:
            for handler in self.logger.handlers:
                self.logger.removeHandler(handler)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_formatter = logging.Formatter('%(levelname)s:%(name)s: %(message)s')
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)
        
        # File handler if requested
        if log_file:
            file_handler = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5)
            file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(name)s - %(message)s')
            file_handler.setFormatter(file_formatter)
            self.logger.addHandler(file_handler)
        
        # State variables
        self.visited_urls = set()
        self.crawled_pages = 0
        self.js_files = {}
        self.api_endpoints = set()
        self.last_request_time = 0
        self.robots_disallowed = set()
        
        # Storage for findings
        self.findings = {
            "secrets": [],
            "js_vulnerabilities": [],
            "ssrf_vulnerabilities": [],
            "summary": {
                "secrets_count": 0,
                "js_vulnerabilities_count": 0,
                "ssrf_vulnerabilities_count": 0,
                "total_urls_crawled": 0,
                "total_js_files": 0,
                "total_api_endpoints": 0
            }
        }
        
        # HTTP session configuration
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=0.3,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "HEAD", "OPTIONS"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Default User-Agent
        default_user_agent = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"
        )
        
        # Headers for HTTP requests
        self.headers = {
            "User-Agent": user_agent or default_user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }
        
        # Load patterns
        self._load_patterns(custom_patterns)
        
        # Process robots.txt if needed
        if self.respect_robots:
            self._process_robots_txt()

    def _load_patterns(self, custom_patterns):
        """
        Load detection patterns with optional custom patterns
        
        Args:
            custom_patterns (dict, optional): Custom detection patterns
        """
        # Patterns for secrets detection - improved for accuracy
        self.secret_patterns = {
            'AWS Access Key': r'(?<![A-Za-z0-9])AKIA[0-9A-Z]{16}(?![A-Za-z0-9])',
            'AWS Secret Key': r'(?<![A-Za-z0-9])[0-9a-zA-Z/+]{40}(?![A-Za-z0-9/+])',  
            'Google API Key': r'AIza[0-9A-Za-z\-_]{35}(?![A-Za-z0-9\-_])',
            'Google OAuth': r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
            'Stripe API Key': r'(?:sk|pk)_(live|test)_[0-9a-zA-Z]{24,34}',
            'Stripe Publishable Key': r'pk_(live|test)_[0-9a-zA-Z]{24,34}',
            'GitHub Token': r'(?:github|gh)(?:_pat)?_[0-9a-zA-Z]{36,40}',
            'GitHub OAuth': r'gho_[0-9a-zA-Z]{36,40}',
            'Twitter API Key': r'(?<![A-Za-z0-9])[0-9a-zA-Z]{18,25}(?=\W)',
            'Twitter Secret': r'(?<![A-Za-z0-9])[0-9a-zA-Z]{35,44}(?=\W)',
            'Facebook Access Token': r'EAACEdEose0cBA[0-9A-Za-z]+',
            'JWT Token': r'eyJ[a-zA-Z0-9_\-]*\.[a-zA-Z0-9_\-]*\.[a-zA-Z0-9_\-]*',
            'SSH Private Key': r'-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY(?:\s+BLOCK)?-----',
            'Password in URL': r'[a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}',
            'Firebase URL': r'https://[a-z0-9-]+\.firebaseio\.com',
            'MongoDB Connection String': r'mongodb(\+srv)?://[^/\s]+:[^/\s]+@[^/\s]+',
            'Slack Token': r'xox[baprs]-[0-9a-zA-Z-]{10,48}',
            'Slack Webhook': r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+',
            'API Key': r'(?i)\b(api[_\-]?key|apikey)\b\s*[=:]\s*["\'`]([a-zA-Z0-9_\-\.]{16,64})["\'`]',
            'Secret Key': r'(?i)\b(secret[_\-]?key|secretkey)\b\s*[=:]\s*["\'`]([a-zA-Z0-9_\-\.]{16,64})["\'`]',
            'Auth Token': r'(?i)\b(auth[_\-]?token|authtoken)\b\s*[=:]\s*["\'`]([a-zA-Z0-9_\-\.]{16,64})["\'`]',
            'Access Token': r'(?i)\b(access[_\-]?token|accesstoken)\b\s*[=:]\s*["\'`]([a-zA-Z0-9_\-\.]{16,64})["\'`]',
            'Password': r'(?i)(?:password|passwd|pwd)[\s=:]+["\'`](?=.*[A-Za-z])(?=.*\d).{8,64}["\'`]',
            'Encryption Key': r'(?i)(?:encryption|aes|des|blowfish)[\s_-]?key[\s=:]+["\'`][A-Za-z0-9+/]{16,}={0,2}["\'`]',
            'Database Credentials': r'(?i)(?:host|server|db_host|database)[\s=:]+["\'`][^"\'`]+["\'`][\s,]+(?:user|username|uid)[\s=:]+["\'`][^"\'`\s]+["\'`][\s,]+(?:password|pwd|passwd)[\s=:]+["\'`][^"\'`\s]+["\'`]',
        }
        
        # Patterns for JavaScript security issues - improved analysis
        self.js_security_patterns = {
            'DOM XSS': [
                r'document\.write\s*\(\s*(?:.*?(?:location|URL|documentURI|referrer|href|search|hash|pathname)|.*?user.*?input)',
                r'\.innerHTML\s*=\s*(?:.*?(?:location|URL|documentURI|referrer|href|search|hash|pathname)|.*?user.*?input)',
                r'\.outerHTML\s*=\s*(?:.*?(?:location|URL|documentURI|referrer|href|search|hash|pathname)|.*?user.*?input)',
                r'eval\s*\(\s*(?:.*?(?:location|URL|documentURI|referrer|href|search|hash|pathname)|.*?user.*?input)',
                r'setTimeout\s*\(\s*(?:.*?(?:location|URL|documentURI|referrer|href|search|hash|pathname)|.*?user.*?input)',
                r'setInterval\s*\(\s*(?:.*?(?:location|URL|documentURI|referrer|href|search|hash|pathname)|.*?user.*?input)',
                r'(?:document|window)\.location\s*=\s*(?:.*?(?:user|input|param|arg|argv|variable|var))'
            ],
            'Open Redirect': [
                r'(?:window\.)?location(?:\.href)?\s*=\s*(?:.*?(?:user|input|param|arg|variable|var))',
                r'(?:window\.)?location\.replace\s*\(\s*(?:.*?(?:user|input|param|arg|variable|var))',
                r'(?:window\.)?location\.assign\s*\(\s*(?:.*?(?:user|input|param|arg|variable|var))'
            ],
            'CORS Misconfiguration': [
                r'Access-Control-Allow-Origin\s*:\s*\*',
                r'Access-Control-Allow-Origin\s*:\s*null',
                r'Access-Control-Allow-Credentials\s*:\s*true'
            ],
            'Insecure Cookie': [
                r'document\.cookie\s*=\s*[^;]*(?!;\s*secure)',
                r'document\.cookie\s*=\s*[^;]*(?!;\s*HttpOnly)'
            ],
            'Insecure Data Transmission': [
                r'\.postMessage\([^,]+,\s*["\']\*["\']\)',
                r'\.postMessage\(.+?,\s*["\'][^"\']+["\']\s*\)'
            ],
            'Potential Prototype Pollution': [
                r'Object\.assign\([^,]+?,\s*(?:user|input|param|arg|variable|var)',
                r'Object\.setPrototypeOf\([^,]+?,\s*(?:user|input|param|arg|variable|var)',
                r'\_\_proto\_\_\s*[=\[]',
                r'prototype\[\s*(?:user|input|param|arg|variable|var)'
            ],
            'Potential Command Injection': [
                r'exec\s*\(\s*(?:.*?(?:user|input|param|arg|variable|var))',
                r'spawn\s*\(\s*(?:.*?(?:user|input|param|arg|variable|var))',
                r'eval\s*\(\s*(?:.*?(?:user|input|param|arg|variable|var))'
            ],
            'Insecure Data Storage': [
                r'localStorage\.setItem\(\s*[^,]+,\s*(?:.*?(?:password|token|key|secret|credentials))',
                r'sessionStorage\.setItem\(\s*[^,]+,\s*(?:.*?(?:password|token|key|secret|credentials))'
            ],
            'Event Handler XSS': [
                r'\.setAttribute\(["\']on\w+["\']\s*,\s*(?:.*?(?:user|input|param|arg|variable|var))',
                r'addEventListener\(["\'](?:click|load|mouseover|keyup|change)["\']\s*,\s*(?:.*?(?:user|input|param|arg|variable|var))'
            ],
            'CSP Bypass': [
                r'\.appendChild\((?:.*?(?:user|input|param|arg|variable|var))',
                r'\.insertBefore\((?:.*?(?:user|input|param|arg|variable|var))',
                r'document\.createElement\(["\']script["\']\)'
            ],
            'Clickjacking': [
                r'X-Frame-Options\s*:\s*deny',
                r'X-Frame-Options\s*:\s*sameorigin'
            ],
            'WebSocket Insecurity': [
                r'new\s+WebSocket\(\s*["\'](ws|wss)://',
                r'WebSocket\s*\(\s*(?:.*?(?:user|input|param|arg|variable|var))'
            ],
            'Insecure Crypto': [
                r'(?:createHash|crypto\.subtle)(?:.*?)["\'](md5|sha1)["\']',
                r'Math\.random\(\)'
            ],
            'Path Traversal': [
                r'\.\.\/|\.\.\\',
                r'path\.join\(\s*(?:.*?(?:user|input|param|arg|variable|var))'
            ]
        }
        
        # SSRF Vulnerable parameters - expanded
        self.ssrf_params = [
            'url', 'uri', 'link', 'src', 'href', 'target', 'destination',
            'redirect', 'redirect_to', 'redirecturl', 'redirect_uri',
            'return', 'return_to', 'returnurl', 'return_path', 'path',
            'load', 'file', 'filename', 'path', 'folder', 'folder_url',
            'image', 'img', 'image_url', 'image_path', 'avatar',
            'document', 'doc', 'document_url', 'document_path', 'asset',
            'fetch', 'get', 'view', 'content', 'domain', 'callback',
            'reference', 'site', 'html', 'page', 'data', 'data_url',
            'resource', 'template', 'api_endpoint', 'endpoint', 'proxy',
            'feed', 'host', 'webhook', 'address', 'media', 'video', 'audio',
            'download', 'upload', 'preview', 'source', 'location', 'goto',
            'callback_url', 'forward', 'next', 'origin', 'continue'
        ]
        
        # SSRF probe URLs - more comprehensive
        self.ssrf_probe_urls = [
            'http://169.254.169.254/latest/meta-data/',  # AWS
            'http://metadata.google.internal/computeMetadata/v1/',  # GCP
            'http://169.254.169.254/metadata/v1/',  # DigitalOcean
            'http://127.0.0.1:1',  # Local connections
            'http://localhost:1',
            'http://[::]:1',
            'http://[0:0:0:0:0:ffff:127.0.0.1]:1',
            'http://example.com@127.0.0.1',
            'http://127.0.0.1#.example.com',
            'http://127.0.0.1:22',  # SSH
            'http://127.0.0.1:3306',  # MySQL
            'http://127.0.0.1:6379',  # Redis
            'http://127.0.0.1:8080',  # Common web port
            'http://127.0.0.1:27017',  # MongoDB
            'http://10.0.0.1:1',  # Private IP
            'http://192.168.1.1:1'  # Private IP
        ]
        
        # Common API Endpoint Patterns - expanded
        self.api_endpoint_patterns = [
            r'/api/v\d+/',
            r'/api/',
            r'/graphql',
            r'/graph',
            r'/v\d+/\w+',
            r'/service/',
            r'/rest/',
            r'/json/',
            r'/rpc/',
            r'/gateway/',
            r'/gw/',
            r'/web-service/',
            r'/ajax/',
            r'/data/',
            r'/query/',
            r'/feeds/',
            r'/svc/',
            r'/soap/',
            r'/api/v\d+/[A-Za-z0-9_-]+/\d+',
            r'/api/[A-Za-z0-9_-]+/v\d+/',
            r'/rest/v\d+/',
            r'/\w+Service',
            r'/\w+Controller',
            r'/\w+Adapter'
        ]
        
        # False positive patterns
        self.exclusion_patterns = [
            r'example\.com',
            r'sample',
            r'placeholder',
            r'test',
            r'your_',
            r'my_',
            r'[A-Za-z0-9]{100,}',  # Too long strings
            r'\\[ux][0-9a-fA-F]{2,4}',  # Unicode escape sequences
            r'\\n',  # Newline escape sequence
            r'[0-9a-f]{32,}',  # MD5, SHA-1 hashes
            r'data:image',
            r'demo',
            r'dummy',
            r'template',
            r'format',
            r'example[A-Za-z0-9]+',
            r'undefined',
            r'never-used',
            r'default',
            r'null',
            r'localhost',
            r'127\.0\.0\.1',
            r'^$'  # Empty strings
        ]
        
        # JS file exclusions - known libraries
        self.js_file_exclusions = [
            r'\.min\.js$',          # Minimized JS files
            r'jquery',              # jQuery library
            r'bootstrap',           # Bootstrap library
            r'modernizr',           # Modernizr library
            r'polyfill',            # Polyfills
            r'vendor',              # Vendor scripts
            r'bundle',              # Bundles
            r'analytics',           # Analytics scripts
            r'tracking',            # Tracking scripts
            r'ga\.js',              # Google Analytics
            r'fbevents',            # Facebook Events
            r'gtm\.js',             # Google Tag Manager
            r'chartjs',             # Chart.js
            r'react',               # React
            r'angular',             # Angular
            r'vue',                 # Vue.js
            r'lodash',              # Lodash
            r'moment',              # Moment.js
            r'popper',              # Popper.js
            r'slick',               # Slick carousel
            r'owl',                 # Owl carousel
            r'swiper',              # Swiper
            r'fontawesome',         # Font Awesome
            r'mathjax',             # MathJax
            r'twemoji',             # Twitter Emoji
            r'player',              # Video players
            r'lightbox',            # Lightboxes
            r'codemirror',          # CodeMirror
            r'highlight',           # Syntax highlighters
            r'tinymce',             # TinyMCE
            r'ckeditor',            # CKEditor
            r'carousel',            # Carousels
            r'(?<!/)[a-f0-9]{8,}\.js$',  # Hashed filenames
            r'cdn',                 # CDN resources
            r'static',              # Static resources
            r'assets',              # Assets
            r'lib',                 # Libraries
            r'plugins',             # Plugins
            r'dist',                # Distribution files
            r'umd',                 # UMD modules
            r'chunk',               # Chunks
            r'runtime',             # Runtime
            r'common',              # Common 
            r'framework',           # Framework
            r'utils?',              # Utilities
            r'helpers?'             # Helpers
        ]
        
        # Apply any custom patterns
        if custom_patterns:
            if 'secret_patterns' in custom_patterns:
                self.secret_patterns.update(custom_patterns['secret_patterns'])
            if 'js_security_patterns' in custom_patterns:
                for category, patterns in custom_patterns['js_security_patterns'].items():
                    if category in self.js_security_patterns:
                        self.js_security_patterns[category].extend(patterns)
                    else:
                        self.js_security_patterns[category] = patterns
            if 'ssrf_params' in custom_patterns:
                self.ssrf_params.extend(custom_patterns['ssrf_params'])
            if 'exclusion_patterns' in custom_patterns:
                self.exclusion_patterns.extend(custom_patterns['exclusion_patterns'])
            if 'js_file_exclusions' in custom_patterns:
                self.js_file_exclusions.extend(custom_patterns['js_file_exclusions'])

    def _process_robots_txt(self):
        """
        Process robots.txt file to respect crawling rules
        """
        try:
            robots_url = urljoin(self.base_url, "/robots.txt")
            response = self._make_request("GET", robots_url)
            
            if response and response.status_code == 200:
                lines = response.text.splitlines()
                
                user_agent_match = False
                for line in lines:
                    line = line.strip().lower()
                    
                    # Check if the line targets our user agent or all agents
                    if line.startswith('user-agent:'):
                        agent = line[11:].strip()
                        user_agent_match = agent == '*' or agent in self.headers['User-Agent'].lower()
                    
                    # Process disallow rules for matching user agent
                    if user_agent_match and line.startswith('disallow:'):
                        path = line[9:].strip()
                        if path:
                            # Convert robots.txt wildcard pattern to regex pattern
                            path = path.replace('*', '.*').replace('?', '.?')
                            path_pattern = f"^{path}"
                            self.robots_disallowed.add(path_pattern)
                
                self.logger.info(f"Processed robots.txt with {len(self.robots_disallowed)} disallowed patterns")
        except Exception as e:
            self.logger.warning(f"Error processing robots.txt: {str(e)}")

    def _is_url_allowed(self, url):
        """
        Check if URL is allowed to be crawled according to robots.txt rules
        
        Args:
            url (str): URL to check
            
        Returns:
            bool: True if allowed, False otherwise
        """
        if not self.respect_robots or not self.robots_disallowed:
            return True
            
        parsed_url = urlparse(url)
        path = parsed_url.path
        
        for pattern in self.robots_disallowed:
            if re.search(pattern, path):
                return False
                
        return True

    def _make_request(self, method, url, **kwargs):
        """
        Make an HTTP request with rate limiting and error handling
        
        Args:
            method (str): HTTP method (GET, POST, etc.)
            url (str): URL to request
            **kwargs: Additional arguments for requests
            
        Returns:
            Response: Response object or None if failed
        """
        # Respect rate limit
        current_time = time.time()
        if current_time - self.last_request_time < self.rate_limit:
            sleep_time = self.rate_limit - (current_time - self.last_request_time)
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()
        
        # Set default parameters
        kwargs.setdefault('timeout', self.timeout)
        kwargs.setdefault('verify', self.verify_ssl)
        kwargs.setdefault('headers', self.headers)
        
        if self.auth:
            kwargs.setdefault('auth', self.auth)
        
        try:
            response = self.session.request(method, url, **kwargs)
            return response
        except requests.exceptions.RequestException as e:
            self.logger.debug(f"Request error for {url}: {str(e)}")
            return None

    def _is_same_domain(self, url):
        """
        Check if URL is on the same domain
        
        Args:
            url (str): URL to check
            
        Returns:
            bool: True if same domain, False otherwise
        """
        parsed_url = urlparse(url)
        return parsed_url.netloc == self.domain_netloc or not parsed_url.netloc

    def _is_valid_url(self, url):
        """
        Check if URL is valid and should be crawled
        
        Args:
            url (str): URL to check
            
        Returns:
            bool: True if valid, False otherwise
        """
        # Skip empty URLs
        if not url:
            return False
            
        # Skip non-http(s) URLs
        if not url.startswith(('http://', 'https://')):
            return False
            
        # Skip URLs with common file extensions to avoid
        skip_extensions = ['.pdf', '.jpg', '.jpeg', '.png', '.gif', '.css', '.zip', 
                          '.rar', '.tar', '.gz', '.doc', '.docx', '.ppt', '.pptx',
                          '.xls', '.xlsx', '.xml', '.svg', '.webp', '.mp4', '.mp3',
                          '.avi', '.mov', '.wmv', '.flv', '.csv', '.ico']
                          
        for ext in skip_extensions:
            if url.lower().endswith(ext):
                return False
        
        # Skip URLs that are not allowed by robots.txt
        if not self._is_url_allowed(url):
            return False
            
        return True

    def crawl_website(self):
        """
        Crawl the website to find JS files, API endpoints, and potential vulnerabilities
        
        Returns:
            dict: Scan findings
        """
        self.logger.warning(f"Starting content scan for {self.domain}")
        start_time = time.time()
        
        # Initialize progress tracking
        total_estimated_pages = min(500, self.max_pages * 3)  # Rough estimation
        progress_interval = max(1, min(10, total_estimated_pages // 10))
        
        # Start with the base URL - use a priority queue for better crawling
        urls_to_crawl = deque([(self.base_url, 0)])  # (url, depth)
        
        # Look for sitemap.xml first to improve crawling efficiency
        self._process_sitemap()
        
        # Main crawling loop
        while urls_to_crawl and self.crawled_pages < self.max_pages:
            current_url, depth = urls_to_crawl.popleft()
            
            # Skip if already visited or max depth reached
            if current_url in self.visited_urls or depth > self.max_depth:
                continue
            
            # Skip if invalid URL
            if not self._is_valid_url(current_url):
                continue
            
            self.visited_urls.add(current_url)
            self.crawled_pages += 1
            
            # Log progress at intervals
            if self.crawled_pages % progress_interval == 0:
                progress_pct = min(100, int((self.crawled_pages / total_estimated_pages) * 100))
                self.logger.warning(f"Progress: {self.crawled_pages}/{total_estimated_pages} pages ({progress_pct}%)")
                # Calculate and log ETA
                elapsed = time.time() - start_time
                pages_per_second = self.crawled_pages / elapsed if elapsed > 0 else 0
                if pages_per_second > 0:
                    remaining_pages = self.max_pages - self.crawled_pages
                    eta_seconds = remaining_pages / pages_per_second
                    eta_minutes = eta_seconds / 60
                    self.logger.warning(f"ETA: approximately {eta_minutes:.1f} minutes")
            
            try:
                self.logger.debug(f"Crawling {current_url} (depth {depth})")
                response = self._make_request("GET", current_url)
                
                if not response or response.status_code != 200:
                    continue
                
                # Check content type
                content_type = response.headers.get('Content-Type', '')
                
                # Process HTML pages
                if 'text/html' in content_type:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Process meta elements for additional data
                    self._process_meta_elements(soup, current_url)
                    
                    # Check for SSRF in forms
                    self._check_forms_for_ssrf(soup, current_url)
                    
                    # Extract JS code from script tags
                    self._process_script_tags(soup, current_url)
                    
                    # Extract API endpoints
                    self._extract_api_endpoints(response.text, current_url)
                    
                    # Find new URLs to crawl
                    if depth < self.max_depth:
                        for link in soup.find_all('a', href=True):
                            href = link.get('href', '').strip()
                            
                            # Skip empty or JavaScript links
                            if not href or href.startswith(('javascript:', '#', 'mailto:', 'tel:')):
                                continue
                                
                            # Convert relative URLs to absolute
                            full_url = urljoin(current_url, href)
                            
                            # Only follow links on the same domain
                            if not self._is_same_domain(full_url):
                                continue
                                
                            if full_url not in self.visited_urls:
                                urls_to_crawl.append((full_url, depth + 1))
                
                # Process JavaScript files directly
                elif ('javascript' in content_type or current_url.endswith('.js')) and not self.is_known_library_file(current_url):
                    self.js_files[current_url] = response.text
                    self._analyze_js_security(response.text, current_url)
                    self._scan_for_secrets(response.text, current_url)
                    self._extract_api_endpoints(response.text, current_url)
                
                # Check URL parameters for SSRF
                self._check_url_params_for_ssrf(current_url)
                
            except Exception as e:
                self.logger.error(f"Error crawling {current_url}: {str(e)}")
        
        # Analyze API endpoints for SSRF
        self.logger.warning(f"Found {len(self.api_endpoints)} potential API endpoints. Testing for SSRF...")
        api_endpoints_list = list(self.api_endpoints)
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            executor.map(self._check_api_endpoint_for_ssrf, api_endpoints_list)
        
        # Update summary statistics
        duration = time.time() - start_time
        self.findings["summary"]["total_urls_crawled"] = len(self.visited_urls)
        self.findings["summary"]["total_js_files"] = len(self.js_files)
        self.findings["summary"]["total_api_endpoints"] = len(self.api_endpoints)
        self.findings["summary"]["secrets_count"] = len(self.findings["secrets"])
        self.findings["summary"]["js_vulnerabilities_count"] = len(self.findings["js_vulnerabilities"])
        self.findings["summary"]["ssrf_vulnerabilities_count"] = len(self.findings["ssrf_vulnerabilities"])
        self.findings["summary"]["scan_duration_seconds"] = round(duration, 2)
        self.findings["summary"]["scan_speed_pages_per_second"] = round(self.crawled_pages / duration, 2) if duration > 0 else 0
        
        # Save findings to different formats
        self._save_findings()
        
        self.logger.warning(f"Completed content scan for {self.domain}")
        self.logger.warning(f"Found {self.findings['summary']['secrets_count']} potential secrets")
        self.logger.warning(f"Found {self.findings['summary']['js_vulnerabilities_count']} potential JS vulnerabilities")
        self.logger.warning(f"Found {self.findings['summary']['ssrf_vulnerabilities_count']} potential SSRF vulnerabilities")
        
        return self.findings

    def _process_sitemap(self):
        """
        Process sitemap.xml to find URLs to crawl
        """
        sitemap_url = urljoin(self.base_url, "/sitemap.xml")
        try:
            response = self._make_request("GET", sitemap_url)
            
            if response and response.status_code == 200 and 'xml' in response.headers.get('Content-Type', ''):
                self.logger.info("Processing sitemap.xml")
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Find all URLs in the sitemap
                locs = soup.find_all('loc')
                for loc in locs:
                    url = loc.text.strip()
                    if url and url not in self.visited_urls and self._is_valid_url(url):
                        self.visited_urls.add(url)  # Mark as visited to avoid duplication
                        
                        # Process the found URL
                        try:
                            page_response = self._make_request("GET", url)
                            if page_response and page_response.status_code == 200:
                                self.crawled_pages += 1
                                content_type = page_response.headers.get('Content-Type', '')
                                
                                # Process HTML pages
                                if 'text/html' in content_type:
                                    soup = BeautifulSoup(page_response.text, 'html.parser')
                                    self._process_script_tags(soup, url)
                                    self._check_forms_for_ssrf(soup, url)
                                    self._extract_api_endpoints(page_response.text, url)
                                
                                # Process JavaScript directly
                                elif ('javascript' in content_type or url.endswith('.js')) and not self.is_known_library_file(url):
                                    self.js_files[url] = page_response.text
                                    self._analyze_js_security(page_response.text, url)
                                    self._scan_for_secrets(page_response.text, url)
                        except Exception as e:
                            self.logger.debug(f"Error processing sitemap URL {url}: {str(e)}")
                
                self.logger.info(f"Processed {len(locs)} URLs from sitemap.xml")
        except Exception as e:
            self.logger.debug(f"Error processing sitemap.xml: {str(e)}")

    def _process_meta_elements(self, soup, page_url):
        """
        Process meta elements for additional information
        
        Args:
            soup (BeautifulSoup): Parsed HTML
            page_url (str): URL of the page
        """
        # Check for CSP
        meta_csp = soup.find('meta', {'http-equiv': 'Content-Security-Policy'})
        if meta_csp:
            content = meta_csp.get('content', '')
            if content and ('unsafe-inline' in content or 'unsafe-eval' in content):
                vulnerability = {
                    "type": "Weak Content Security Policy",
                    "source_url": page_url,
                    "details": "CSP allows unsafe-inline or unsafe-eval",
                    "csp_content": content,
                    "severity": "Medium"
                }
                
                # Check if this vulnerability was already found
                if not any(v['source_url'] == page_url and v['type'] == "Weak Content Security Policy" 
                          for v in self.findings["js_vulnerabilities"]):
                    self.findings["js_vulnerabilities"].append(vulnerability)
                    self.logger.info(f"Weak CSP found in {page_url}")
        
        # Check for CSRF token
        forms = soup.find_all('form')
        has_csrf_token = False
        for form in forms:
            csrf_inputs = form.find_all('input', {'name': re.compile(r'csrf|xsrf|token', re.IGNORECASE)})
            if csrf_inputs:
                has_csrf_token = True
                break
        
        if forms and not has_csrf_token:
            vulnerability = {
                "type": "Missing CSRF Protection",
                "source_url": page_url,
                "details": "Forms found without CSRF tokens",
                "severity": "Medium"
            }
            
            # Check if this vulnerability was already found
            if not any(v['source_url'] == page_url and v['type'] == "Missing CSRF Protection" 
                      for v in self.findings["js_vulnerabilities"]):
                self.findings["js_vulnerabilities"].append(vulnerability)
                self.logger.info(f"Missing CSRF protection in {page_url}")

    def _process_script_tags(self, soup, page_url):
        """
        Process script tags in HTML
        
        Args:
            soup (BeautifulSoup): Parsed HTML
            page_url (str): URL of the page
        """
        for script in soup.find_all('script'):
            # Inline JavaScript
            if script.string:
                js_content = script.string
                # Skip empty scripts
                if not js_content or len(js_content.strip()) < 10:
                    continue
                    
                js_key = f"{page_url}#inline-script-{self._generate_hash(js_content)}"
                self.js_files[js_key] = js_content
                self._analyze_js_security(js_content, js_key)
                self._scan_for_secrets(js_content, js_key)
            
            # External JavaScript files
            if script.has_attr('src'):
                js_url = script['src']
                
                # Normalize URL
                if js_url.startswith('//'):
                    js_url = f"https:{js_url}"
                elif not js_url.startswith(('http://', 'https://')):
                    js_url = urljoin(page_url, js_url)
                
                # Only fetch JS files from the same domain or if they're relative URLs
                if self._is_same_domain(js_url) and js_url not in self.js_files:
                    self._fetch_and_analyze_js(js_url)

    def _generate_hash(self, content):
        """
        Generate a hash for content
        
        Args:
            content (str): Content to hash
            
        Returns:
            str: Hash value
        """
        return hashlib.md5(content.encode()).hexdigest()

    def is_known_library_file(self, url):
        """
        Check if URL points to a known JavaScript library
        
        Args:
            url (str): URL to check
            
        Returns:
            bool: True if known library, False otherwise
        """
        return any(re.search(pattern, url.lower()) for pattern in self.js_file_exclusions)

    def _fetch_and_analyze_js(self, js_url):
        """
        Fetch and analyze a JavaScript file
        
        Args:
            js_url (str): URL of the JavaScript file
        """
        if js_url in self.js_files or self.is_known_library_file(js_url):
            return
            
        try:
            response = self._make_request("GET", js_url)
            
            if response and response.status_code == 200:
                js_content = response.text
                
                # Skip empty files
                if not js_content or len(js_content.strip()) < 10:
                    return
                    
                self.js_files[js_url] = js_content
                self._analyze_js_security(js_content, js_url)
                self._scan_for_secrets(js_content, js_url)
                self._extract_api_endpoints(js_content, js_url)
        except Exception as e:
            self.logger.debug(f"Error fetching JS file {js_url}: {str(e)}")

    def _analyze_js_security(self, js_content, source_url):
        """
        Analyze JavaScript code for security vulnerabilities with improved context awareness
        
        Args:
            js_content (str): JavaScript code
            source_url (str): Source URL of the JavaScript code
        """
        # Skip analysis for known libraries or minified files
        is_library = self.is_known_library_file(source_url)
        is_minified = len(js_content) > 5000 and js_content.count('\n') < 50
        
        # For libraries or minified files, only check for high-severity issues
        if is_library or is_minified:
            patterns_to_check = {
                'Potential Command Injection': self.js_security_patterns.get('Potential Command Injection', []),
                'DOM XSS': self.js_security_patterns.get('DOM XSS', [])
            }
        else:
            patterns_to_check = self.js_security_patterns
        
        # Track unique vulnerabilities to avoid duplication
        found_vulnerabilities = set()

        for vuln_type, patterns in patterns_to_check.items():
            for pattern in patterns:
                matches = re.finditer(pattern, js_content)
                for match in matches:
                    # Get line number and context
                    line_number = js_content[:match.start()].count('\n') + 1
                    
                    # Get more context for better analysis
                    start_pos = max(0, match.start() - 200)
                    end_pos = min(len(js_content), match.end() + 200)
                    full_context = js_content[start_pos:end_pos]
                    
                    # Clean up context for display
                    display_context = full_context.replace('\n', ' ').strip()
                    if len(display_context) > 300:
                        display_context = "..." + display_context[len(display_context)-300:]
                    
                    # Additional validation for DOM XSS
                    if vuln_type == "DOM XSS":
                        # Only report if there's likely user input involved
                        if not any(term in full_context.lower() for term in 
                                ['user', 'input', 'param', 'value', 'get', 'post', 
                                 'request', 'location', 'search', 'hash', 'href', 
                                 'pathname', 'query', 'data', 'json']):
                            continue
                    
                    # Additional validation for Open Redirect
                    if vuln_type == "Open Redirect":
                        # Only report if it's likely redirecting to unvalidated input
                        if not any(term in full_context.lower() for term in 
                                ['user', 'input', 'param', 'value', 'get', 'redirect',
                                 'return', 'url', 'href', 'location']):
                            continue
                    
                    # Create unique vulnerability identifier to avoid duplicates
                    context_hash = self._generate_hash(match.group(0) + str(line_number))
                    vuln_id = f"{vuln_type}:{source_url}:{context_hash}"
                    
                    if vuln_id in found_vulnerabilities:
                        continue
                        
                    found_vulnerabilities.add(vuln_id)
                    
                    # Determine severity
                    severity = self._determine_js_vulnerability_severity(vuln_type)
                    
                    # Better code snippet with highlighting
                    matched_code = match.group(0)
                    code_context = js_content[max(0, match.start() - 50):min(len(js_content), match.end() + 50)]
                    code_context = code_context.replace('\n', ' ').strip()
                    
                    vulnerability = {
                        "type": vuln_type,
                        "source_url": source_url,
                        "line": line_number,
                        "matched_code": matched_code,
                        "code_context": code_context,
                        "surrounding_context": display_context,
                        "severity": severity,
                        "description": self._get_vulnerability_description(vuln_type),
                        "recommendation": self._get_vulnerability_recommendation(vuln_type)
                    }
                    
                    self.findings["js_vulnerabilities"].append(vulnerability)
                    
                    # Log high severity findings
                    if severity == "High" and not is_library:
                        self.logger.warning(f"High severity {vuln_type} found in {source_url} at line {line_number}")

    def _determine_js_vulnerability_severity(self, vuln_type):
        """
        Determine the severity of a JavaScript vulnerability with clear categorization
        
        Args:
            vuln_type (str): Type of vulnerability
            
        Returns:
            str: Severity level (High, Medium, Low)
        """
        high_severity = [
            "DOM XSS", 
            "Potential Command Injection", 
            "Open Redirect",
            "WebSocket Insecurity",
            "Insecure Crypto"
        ]
        
        medium_severity = [
            "CORS Misconfiguration", 
            "Insecure Data Transmission", 
            "Potential Prototype Pollution", 
            "Event Handler XSS",
            "CSP Bypass",
            "Path Traversal"
        ]
                      
        if vuln_type in high_severity:
            return "High"
        elif vuln_type in medium_severity:
            return "Medium"
        else:
            return "Low"

    def _get_vulnerability_description(self, vuln_type):
        """
        Get a description for a vulnerability type
        
        Args:
            vuln_type (str): Type of vulnerability
            
        Returns:
            str: Description
        """
        descriptions = {
            "DOM XSS": "DOM-based XSS vulnerabilities occur when client-side JavaScript takes user-controllable data and passes it to a sink that supports dynamic code execution.",
            "Open Redirect": "Open redirect vulnerabilities occur when user input is used to determine the destination of a redirect, allowing attackers to redirect users to malicious sites.",
            "CORS Misconfiguration": "CORS misconfiguration can allow unauthorized websites to access resources that should be restricted.",
            "Insecure Cookie": "Cookies without secure and/or HttpOnly flags can be vulnerable to theft and modification.",
            "Insecure Data Transmission": "Data is being transmitted insecurely, potentially exposing sensitive information.",
            "Potential Prototype Pollution": "Prototype pollution vulnerabilities occur when JavaScript object prototypes can be manipulated, leading to property injection.",
            "Potential Command Injection": "Command injection vulnerabilities allow attackers to execute arbitrary commands on the host system.",
            "Insecure Data Storage": "Sensitive data is being stored insecurely in client-side storage mechanisms.",
            "Event Handler XSS": "Event handlers are being assigned dynamically, potentially leading to XSS vulnerabilities.",
            "CSP Bypass": "The code may contain techniques that bypass Content Security Policy protections.",
            "Clickjacking": "The application may be vulnerable to clickjacking attacks if frame protection headers are missing or improperly configured.",
            "WebSocket Insecurity": "Insecure WebSocket connections can lead to data interception or manipulation.",
            "Insecure Crypto": "Weak cryptographic methods are being used, which can lead to data exposure.",
            "Path Traversal": "Path traversal attacks allow access to files and directories outside the intended path."
        }
        
        return descriptions.get(vuln_type, f"Potential security issue related to {vuln_type}")

    def _get_vulnerability_recommendation(self, vuln_type):
        """
        Get a recommendation for fixing a vulnerability
        
        Args:
            vuln_type (str): Type of vulnerability
            
        Returns:
            str: Recommendation
        """
        recommendations = {
            "DOM XSS": "Sanitize and validate all user inputs before using them in DOM operations. Consider using libraries like DOMPurify or implementing a Content Security Policy.",
            "Open Redirect": "Implement a whitelist of allowed URLs or use indirect reference maps instead of directly using user input for redirects.",
            "CORS Misconfiguration": "Be specific with CORS policies. Avoid using '*' for Access-Control-Allow-Origin and set specific domains instead.",
            "Insecure Cookie": "Set the 'Secure' and 'HttpOnly' flags on cookies containing sensitive information.",
            "Insecure Data Transmission": "Use specific origin URLs with postMessage() and validate message senders.",
            "Potential Prototype Pollution": "Avoid using user-controlled data with Object.assign() or Object.prototype methods. Consider using Object.create(null) for objects without prototypes.",
            "Potential Command Injection": "Avoid executing commands with user input. If necessary, implement strict validation and sanitization.",
            "Insecure Data Storage": "Don't store sensitive information in localStorage or sessionStorage. Use secure cookies or server-side storage.",
            "Event Handler XSS": "Validate and sanitize data before assigning to event handlers. Avoid using innerHTML with user-controlled data.",
            "CSP Bypass": "Implement a strict Content Security Policy and avoid dynamic script creation with user input.",
            "Clickjacking": "Implement X-Frame-Options or frame-ancestors CSP directive to prevent your content from being embedded in other sites.",
            "WebSocket Insecurity": "Use secure WebSocket connections (wss://) and validate input/output data.",
            "Insecure Crypto": "Use modern cryptographic algorithms and avoid MD5/SHA1. Use secure random number generators.",
            "Path Traversal": "Validate and sanitize file paths. Use allowlists instead of denylists for file extensions and paths."
        }
        
        return recommendations.get(vuln_type, "Review the code and implement proper security controls.")

    def _scan_for_secrets(self, content, source_url):
        """
        Scan content for API keys and other secrets with improved detection and validation
        
        Args:
            content (str): Content to scan
            source_url (str): Source URL of the content
        """
        # Skip known libraries
        if self.is_known_library_file(source_url):
            return
            
        # Track unique secrets to avoid duplication
        found_secrets = set()
        
        for secret_type, pattern in self.secret_patterns.items():
            matches = re.finditer(pattern, content)
            for match in matches:
                line_number = content[:match.start()].count('\n') + 1
                secret_value = match.group(0)
                
                # Skip if matches exclusion patterns
                if any(re.search(excl_pattern, secret_value) for excl_pattern in self.exclusion_patterns):
                    continue
                
                # Get context for better validation
                start_pos = max(0, match.start() - 100)
                end_pos = min(len(content), match.end() + 100)
                context = content[start_pos:end_pos].replace('\n', ' ').strip()
                
                # Skip common false positives based on context
                if any(term in context.lower() for term in 
                      ['example', 'sample', 'placeholder', 'dummy', 'test', 'demo']):
                    continue
                
                # Validate entropy for certain secret types to reduce false positives
                if secret_type in ['AWS Secret Key', 'Google API Key', 'API Key', 'Secret Key']:
                    # Calculate entropy of the secret
                    entropy = self._calculate_shannon_entropy(secret_value)
                    # Skip low entropy strings (likely not real secrets)
                    if entropy < 3.5:  # Threshold can be adjusted
                        continue
                
                # Create unique secret identifier
                secret_hash = f"{secret_type}:{source_url}:{self._generate_hash(secret_value)}"
                
                if secret_hash in found_secrets:
                    continue
                    
                found_secrets.add(secret_hash)
                
                # Mask secret value for security in report
                masked_value = self._mask_secret(secret_value)
                
                # Determine severity
                severity = self._determine_secret_severity(secret_type)
                
                secret = {
                    "type": secret_type,
                    "source_url": source_url,
                    "line": line_number,
                    "masked_value": masked_value,
                    "context": context,
                    "severity": severity,
                    "entropy": round(self._calculate_shannon_entropy(secret_value), 2),
                    "recommendation": self._get_secret_recommendation(secret_type)
                }
                
                self.findings["secrets"].append(secret)
                
                # Log high severity findings
                if severity == "High":
                    self.logger.warning(f"High severity {secret_type} found in {source_url} at line {line_number}")

    def _calculate_shannon_entropy(self, data):
        """
        Calculate Shannon entropy of a string to help validate potential secrets
        
        Args:
            data (str): String to calculate entropy for
            
        Returns:
            float: Entropy value
        """
        if not data:
            return 0
            
        entropy = 0
        for x in range(256):
            p_x = float(data.count(chr(x))) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
                
        return entropy

    def _mask_secret(self, secret):
        """
        Mask a secret value for security in reports
        
        Args:
            secret (str): Secret to mask
            
        Returns:
            str: Masked secret
        """
        if len(secret) <= 8:
            return "****" + secret[-2:] if len(secret) > 2 else "****"
        else:
            return secret[:4] + "****" + secret[-4:]

    def _determine_secret_severity(self, secret_type):
        """
        Determine the severity of a secret finding
        
        Args:
            secret_type (str): Type of secret
            
        Returns:
            str: Severity level (High, Medium, Low)
        """
        high_severity = [
            "AWS Secret Key", 
            "Stripe API Key", 
            "GitHub Token", 
            "SSH Private Key", 
            "Password in URL", 
            "MongoDB Connection String",
            "Database Credentials",
            "Encryption Key"
        ]
        
        medium_severity = [
            "AWS Access Key", 
            "Google API Key", 
            "JWT Token", 
            "Facebook Access Token", 
            "Slack Token", 
            "Slack Webhook",
            "API Key",
            "Secret Key",
            "Auth Token"
        ]
                          
        if secret_type in high_severity:
            return "High"
        elif secret_type in medium_severity:
            return "Medium"
        else:
            return "Low"

    def _get_secret_recommendation(self, secret_type):
        """
        Get a recommendation for handling a leaked secret
        
        Args:
            secret_type (str): Type of secret
            
        Returns:
            str: Recommendation
        """
        recommendations = {
            "AWS Access Key": "Rotate the key immediately. Use AWS IAM roles instead of hard-coded keys when possible.",
            "AWS Secret Key": "Rotate the key immediately. Store secrets in a secure vault like AWS Secrets Manager.",
            "Google API Key": "Rotate the key and implement API key restrictions such as HTTP referrer and IP address.",
            "Google OAuth": "Review and potentially regenerate the OAuth credentials. Use environment variables for storage.",
            "Stripe API Key": "Rotate the key immediately. Only use server-side code to access the Stripe API.",
            "GitHub Token": "Revoke and regenerate the token. Use GitHub Actions secrets for CI/CD workflows.",
            "SSH Private Key": "Generate a new key pair and update authorized_keys on all servers. Never store private keys in code.",
            "Password in URL": "Remove the password from the URL and use a secure authentication method.",
            "JWT Token": "If this is a valid token, rotate it. Store JWTs securely and implement proper expiration.",
            "Firebase URL": "Review Firebase security rules and regenerate any associated secrets.",
            "MongoDB Connection String": "Rotate the password in the connection string and use environment variables instead of hardcoding.",
            "Slack Token": "Revoke and regenerate the token. Use a secrets management solution instead of hardcoding.",
            "Slack Webhook": "Regenerate the webhook URL and store it securely.",
            "API Key": "Rotate the key and implement proper restrictions. Store it in environment variables or a secrets manager.",
            "Secret Key": "Rotate the key and ensure it's stored in a secure vault or environment variable.",
            "Auth Token": "Revoke the token and issue a new one. Implement proper token management.",
            "Access Token": "Revoke and regenerate the token. Store tokens securely and implement proper expiration.",
            "Password": "Change the password immediately and use a password manager or secrets vault instead of hardcoding.",
            "Encryption Key": "Rotate the key and store it securely using a key management system.",
            "Database Credentials": "Change the credentials immediately and use environment variables or a secrets manager instead."
        }
        
        return recommendations.get(secret_type, "Remove this secret from code and store it securely using environment variables or a secrets management solution.")

    def _extract_api_endpoints(self, content, source_url):
        """
        Extract potential API endpoints from content
        
        Args:
            content (str): Content to analyze
            source_url (str): Source URL of the content
        """
        for pattern in self.api_endpoint_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                endpoint = match.group(0)
                full_url = urljoin(source_url, endpoint)
                
                # Validate URL format
                if not validators.url(full_url):
                    continue
                    
                self.api_endpoints.add(full_url)
                self.logger.debug(f"Found API endpoint: {full_url}")
    
    def _check_forms_for_ssrf(self, soup, page_url):
        """
        Check HTML forms for potential SSRF vulnerabilities with improved detection
        
        Args:
            soup (BeautifulSoup): Parsed HTML
            page_url (str): URL of the page
        """
        forms = soup.find_all('form')
        for form in forms:
            form_action = form.get('action', '')
            form_method = form.get('method', 'get').lower()
            
            # Track if the form has SSRF-vulnerable fields
            has_ssrf_field = False
            vulnerable_fields = []
            
            # Check form fields
            fields = form.find_all(['input', 'textarea'])
            for field in fields:
                field_name = field.get('name', '').lower()
                field_type = field.get('type', '').lower()
                
                if not field_name:
                    continue
                
                # Check if field name contains SSRF-related terms
                if any(param in field_name for param in self.ssrf_params) or field_type in ['url', 'text']:
                    has_ssrf_field = True
                    vulnerable_fields.append(field_name)
            
            # If form has SSRF-vulnerable fields, report it
            if has_ssrf_field:
                # Generate a unique ID for this vulnerability
                vuln_id = f"ssrf_form:{page_url}:{form_action}:{'-'.join(vulnerable_fields)}"
                vuln_hash = self._generate_hash(vuln_id)
                
                # Check if this vulnerability was already found
                if any(v.get('hash') == vuln_hash for v in self.findings["ssrf_vulnerabilities"]):
                    continue
                
                vulnerability = {
                    "type": "Potential SSRF in Form",
                    "source_url": page_url,
                    "form_action": urljoin(page_url, form_action),
                    "form_method": form_method,
                    "vulnerable_parameters": vulnerable_fields,
                    "hash": vuln_hash,
                    "severity": "Medium",
                    "description": "The form contains fields that could be used for Server-Side Request Forgery attacks.",
                    "recommendation": "Validate and sanitize all user inputs, especially URL parameters. Implement allowlists for accepted domains and protocols."
                }
                
                self.findings["ssrf_vulnerabilities"].append(vulnerability)
                self.logger.warning(f"Potential SSRF in form found: {page_url} - parameters: {', '.join(vulnerable_fields)}")
    
    def _check_url_params_for_ssrf(self, url):
        """
        Check URL parameters for potential SSRF vulnerabilities with improved validation
        
        Args:
            url (str): URL to check
        """
        parsed_url = urlparse(url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        
        # Skip if no query parameters
        if not query_params:
            return
            
        # Track vulnerable parameters
        vulnerable_params = []
        
        for param in query_params:
            if any(ssrf_param in param.lower() for ssrf_param in self.ssrf_params):
                vulnerable_params.append(param)
        
        # If vulnerable parameters found, report it
        if vulnerable_params:
            # Generate a unique ID for this vulnerability
            vuln_id = f"ssrf_url:{url}:{'-'.join(vulnerable_params)}"
            vuln_hash = self._generate_hash(vuln_id)
            
            # Check if this vulnerability was already found
            if any(v.get('hash') == vuln_hash for v in self.findings["ssrf_vulnerabilities"]):
                return
            
            vulnerability = {
                "type": "Potential SSRF in URL Parameter",
                "source_url": url,
                "vulnerable_parameters": vulnerable_params,
                "parameter_values": {p: query_params[p][0] for p in vulnerable_params},
                "hash": vuln_hash,
                "severity": "Medium",
                "description": "The URL contains parameters that could be used for Server-Side Request Forgery attacks.",
                "recommendation": "Validate and sanitize all user inputs, especially URL parameters. Implement allowlists for accepted domains and protocols."
            }
            
            self.findings["ssrf_vulnerabilities"].append(vulnerability)
            self.logger.warning(f"Potential SSRF in URL parameters found: {url} - parameters: {', '.join(vulnerable_params)}")
    
    def _check_api_endpoint_for_ssrf(self, endpoint):
        """
        Test API endpoint for SSRF vulnerabilities with safer testing approach
        
        Args:
            endpoint (str): API endpoint to test
        """
        try:
            # Parse the endpoint URL
            parsed_url = urlparse(endpoint)
            
            # Skip non-HTTP(S) URLs
            if parsed_url.scheme not in ['http', 'https']:
                return
                
            # Skip URLs on different domains
            if not self._is_same_domain(endpoint):
                return
            
            # Extract existing query parameters
            existing_params = urllib.parse.parse_qs(parsed_url.query)
            
            # Skip endpoints that already have too many parameters to avoid overloading
            if len(existing_params) > 10:
                return
            
            # Build test parameters using a safe, unique value that can be tracked
            # Use a unique identifier to avoid false positives
            test_value = f"https://ssrf-test-{self._generate_hash(endpoint)[:8]}.example.com"
            
            test_params = {}
            for param in self.ssrf_params[:5]:  # Limit to 5 parameters to avoid query string limits
                test_params[param] = test_value
            
            # Combine with existing parameters
            for param, values in existing_params.items():
                if param not in test_params:
                    test_params[param] = values[0]
            
            # Make a request with test parameters
            response = self._make_request(
                "GET",
                endpoint,
                params=test_params,
                allow_redirects=False  # Don't follow redirects to avoid triggering the SSRF
            )
            
            if not response:
                return
            
            # Check for potential SSRF indicators in redirects
            if response.status_code in [301, 302, 303, 307, 308]:
                location = response.headers.get('Location', '')
                
                if test_value in location:
                    # Generate a unique ID for this vulnerability
                    vuln_id = f"ssrf_api:{endpoint}"
                    vuln_hash = self._generate_hash(vuln_id)
                    
                    # Check if this vulnerability was already found
                    if any(v.get('hash') == vuln_hash for v in self.findings["ssrf_vulnerabilities"]):
                        return
                    
                    vulnerability = {
                        "type": "Confirmed SSRF in API Endpoint",
                        "source_url": endpoint,
                        "redirect_url": location,
                        "hash": vuln_hash,
                        "severity": "High",
                        "description": "The API endpoint redirects to a URL specified in the request parameters, which could lead to Server-Side Request Forgery.",
                        "recommendation": "Validate all URL inputs and implement strict allowlists for accepted domains and protocols. Avoid using user input for server-side requests."
                    }
                    
                    self.findings["ssrf_vulnerabilities"].append(vulnerability)
                    self.logger.warning(f"Confirmed SSRF in API endpoint: {endpoint} -> {location}")
        
        except Exception as e:
            self.logger.debug(f"Error checking API endpoint {endpoint} for SSRF: {str(e)}")
    
    def _save_findings(self):
        """
        Save findings to JSON format, excluding unnecessary information and only include high severity issues
        """
        # Create base filename
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        filename = f"content_scan_{self.domain_netloc}_{timestamp}.json"
        
        # Save as JSON - only include high severity findings to reduce log size
        json_file = os.path.join(self.output_dir, filename)
        
        # Filter only high severity findings
        high_secrets = [s for s in self.findings["secrets"] if s["severity"] == "High"]
        high_js_vulns = [v for v in self.findings["js_vulnerabilities"] if v["severity"] == "High"]
        high_ssrf_vulns = [v for v in self.findings["ssrf_vulnerabilities"] if v["severity"] == "High"]
        
        # Create minimal findings object with only high severity issues
        minimal_findings = {
            "high_severity_secrets": high_secrets,
            "high_severity_js_vulnerabilities": high_js_vulns,
            "high_severity_ssrf_vulnerabilities": high_ssrf_vulns,
            "scan_info": {
                "domain": self.domain,
                "scan_date": time.strftime('%Y-%m-%d %H:%M:%S'),
                "scan_duration_seconds": self.findings["summary"]["scan_duration_seconds"] if "summary" in self.findings else 0
            }
        }
        
        try:
            with open(json_file, 'w') as f:
                json.dump(minimal_findings, f, indent=2)  # Reduce indentation from 4 to 2
            
            self.logger.warning(f"High severity findings saved to JSON: {json_file}")
            return json_file
        except Exception as e:
            self.logger.error(f"Error saving findings to JSON: {str(e)}")
            return None
    
    def run(self):
        """
        Run the scanner
        
        Returns:
            dict: Scan findings
        """
        try:
            self.logger.warning(f"Starting Advanced Content Scanner for {self.domain}")
            start_time = time.time()
            
            findings = self.crawl_website()
            
            duration = time.time() - start_time
            self.logger.warning(f"Scan completed in {duration:.2f} seconds")
            
            return findings
        
        except Exception as e:
            self.logger.error(f"Error running content scanner: {str(e)}")
            import traceback
            self.logger.error(traceback.format_exc())
            
            return {
                "error": str(e),
                "domain": self.domain,
                "traceback": traceback.format_exc()
            }