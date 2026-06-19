# utils/session_manager.py
import requests
import random
import time
import itertools
import socket
import logging
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

# Try importing curl_cffi for advanced JA3 fingerprint impersonation
try:
    from curl_cffi import requests as curl_requests
    HAS_CURL_CFFI = True
except ImportError:
    HAS_CURL_CFFI = False

# Try importing httpx for HTTP/2 support fallback
try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

logger = logging.getLogger(__name__)


class SessionResponseWrapper:
    """Unified wrapper around requests, curl_cffi and httpx responses"""
    def __init__(self, raw_response, backend):
        self.raw_response = raw_response
        self.backend = backend

    @property
    def status_code(self):
        if self.backend == 'httpx':
            return self.raw_response.status_code
        return self.raw_response.status_code

    @property
    def headers(self):
        return self.raw_response.headers

    @property
    def text(self):
        return self.raw_response.text

    @property
    def content(self):
        if self.backend == 'httpx':
            return self.raw_response.content
        return self.raw_response.content

    @property
    def cookies(self):
        if self.backend == 'httpx':
            return self.raw_response.cookies
        return self.raw_response.cookies

    def json(self, **kwargs):
        return self.raw_response.json(**kwargs)


class AdvancedSessionManager:
    def __init__(self, delay_range=(2, 5), max_retries=3):
        self.delay_range = delay_range
        self.max_retries = max_retries
        self.current_session = None
        self.session_backend = None
        self.request_count = 0
        self.last_latency = 0.0
        self.cookies_jar = {}
        
        # Max requests per session burst (rotate after 5 to 12 requests)
        self.max_requests_per_session = random.randint(5, 12)
        
        # Auto-detect local Tor services
        self.tor_socks_port = self._detect_tor_socks_port()
        self.tor_control_port = self._detect_tor_control_port()
        
        # Dynamic proxy list
        self.proxies_list = [None]  # Include direct connection as a option
        
        if self.tor_socks_port:
            tor_proxy = {
                'http': f'socks5://127.0.0.1:{self.tor_socks_port}',
                'https': f'socks5://127.0.0.1:{self.tor_socks_port}'
            }
            self.proxies_list.append(tor_proxy)
            logger.info(f"Tor SOCKS proxy automatically added to rotation: port {self.tor_socks_port}")
            
        self.proxy_cycle = itertools.cycle(self.proxies_list)
        
        # Realistic User Agent list
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1'
        ]
        
        self._create_new_session()

    def _detect_tor_socks_port(self):
        """Check if Tor SOCKS5 proxy is listening on common ports"""
        for port in [9050, 9150]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                s.connect(('127.0.0.1', port))
                s.close()
                return port
            except (socket.timeout, ConnectionRefusedError):
                continue
        return None

    def _detect_tor_control_port(self):
        """Check if Tor control port is listening on common ports"""
        for port in [9051, 9151]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                s.connect(('127.0.0.1', port))
                s.close()
                return port
            except (socket.timeout, ConnectionRefusedError):
                continue
        return None

    def _rotate_tor_circuit(self):
        """Rotate Tor IP circuit by sending NEWNYM signal via raw socket control port connection"""
        if not self.tor_control_port:
            return
        logger.info(f"Triggering Tor circuit rotation on control port {self.tor_control_port}...")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect(('127.0.0.1', self.tor_control_port))
            s.send(b'AUTHENTICATE ""\r\n')
            res = s.recv(1024)
            if b'250' in res:
                s.send(b'SIGNAL NEWNYM\r\n')
                res2 = s.recv(1024)
                if b'250' in res2:
                    logger.info("Tor circuit rotated successfully (NEWNYM issued).")
                    # Give Tor a moment to establish new circuit connection
                    time.sleep(2)
            s.close()
        except Exception as e:
            logger.warning(f"Could not rotate Tor circuit: {e}")

    def _create_new_session(self):
        """Initialize a new session choosing the best available client engine"""
        if self.current_session:
            try:
                self.current_session.close()
            except Exception:
                pass
        
        # Get next proxy from rotation
        current_proxy = next(self.proxy_cycle)
        
        # If proxy is Tor, rotate the Tor circuit first
        if current_proxy and any(p in str(current_proxy) for p in ['9050', '9150']):
            self._rotate_tor_circuit()
            
        user_agent = random.choice(self.user_agents)
        headers = {
            'User-Agent': user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9,tr;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'DNT': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1'
        }

        # 1st Choice: curl_cffi for advanced JA3 TLS & HTTP/2 impersonation
        if HAS_CURL_CFFI:
            try:
                self.session_backend = 'curl_cffi'
                self.current_session = curl_requests.Session(impersonate="chrome")
                self.current_session.headers.update(headers)
                if current_proxy:
                    self.current_session.proxies = current_proxy
                
                # Apply saved cookies
                if self.cookies_jar:
                    self.current_session.cookies.update(self.cookies_jar)
                
                logger.info(f"Created curl_cffi Session (JA3 impersonate=chrome) with User-Agent: {user_agent}")
                self.request_count = 0
                self.max_requests_per_session = random.randint(5, 12)
                return
            except Exception as e:
                logger.warning(f"Failed to initialize curl_cffi session, falling back to HTTPX: {e}")

        # 2nd Choice: HTTPX for clean HTTP/2 support
        if HAS_HTTPX:
            try:
                self.session_backend = 'httpx'
                # Format proxies for HTTPX
                httpx_proxies = None
                if current_proxy:
                    httpx_proxies = {
                        "http://": current_proxy.get("http", ""),
                        "https://": current_proxy.get("https", "")
                    }
                
                self.current_session = httpx.Client(
                    http2=True, 
                    headers=headers, 
                    proxies=httpx_proxies,
                    follow_redirects=True,
                    timeout=30.0,
                    cookies=self.cookies_jar
                )
                logger.info(f"Created HTTPX Client (HTTP/2 enabled) with User-Agent: {user_agent}")
                self.request_count = 0
                self.max_requests_per_session = random.randint(5, 12)
                return
            except Exception as e:
                logger.warning(f"Failed to initialize HTTPX client, falling back to standard requests: {e}")

        # 3rd Choice: Standard Requests (HTTP/1.1 with rotated headers/proxies)
        self.session_backend = 'requests'
        self.current_session = requests.Session()
        retry_strategy = Retry(
            total=self.max_retries,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"],
            backoff_factor=1
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.current_session.mount("http://", adapter)
        self.current_session.mount("https://", adapter)
        self.current_session.headers.update(headers)
        
        if current_proxy:
            self.current_session.proxies.update(current_proxy)
            
        if self.cookies_jar:
            self.current_session.cookies.update(self.cookies_jar)
            
        logger.info(f"Created standard requests.Session with User-Agent: {user_agent}")
        self.request_count = 0
        self.max_requests_per_session = random.randint(5, 12)

    def _should_rotate_session(self):
        """Determine if current session burst limits are exceeded"""
        return self.request_count >= self.max_requests_per_session

    def _get_adaptive_delay(self):
        """Calculate adaptive delay dynamically incorporating target server latency & random jitter"""
        base_delay = random.uniform(*self.delay_range)
        
        # If server is experiencing slow response times (> 2s), adaptively slow down requests
        adaptive_adder = 0.0
        if self.last_latency > 2.0:
            adaptive_adder = self.last_latency * 0.5
            logger.info(f"Target latency is high ({self.last_latency:.2f}s). Throttling down (adding +{adaptive_adder:.2f}s).")
            
        total_delay = base_delay + adaptive_adder
        
        # Add random human-like +/- 15% fluctuation jitter
        jitter = total_delay * random.uniform(-0.15, 0.15)
        return max(0.5, total_delay + jitter)

    def _delay_request(self):
        """Apply the computed human-like delay before executing a request"""
        delay = self._get_adaptive_delay()
        logger.debug(f"Applying delay of {delay:.2f} seconds...")
        time.sleep(delay)

    def get(self, url, **kwargs):
        return self._make_request('GET', url, **kwargs)

    def post(self, url, **kwargs):
        return self._make_request('POST', url, **kwargs)

    def _make_request(self, method, url, **kwargs):
        """Send HTTP request handling session lifecycle, evasion, and automatic rate-limit recovery"""
        # Trigger session rotation if request burst limits exceeded
        if self._should_rotate_session():
            logger.info("Session request burst limit reached. Rotating session...")
            self._create_new_session()
            
        # Human Jitter Reading Cycles: after every 8 requests, simulate reading time
        if self.request_count > 0 and self.request_count % 8 == 0:
            reading_sleep = random.uniform(10.0, 25.0)
            logger.info(f"Simulating human reading time. Pausing for {reading_sleep:.2f} seconds...")
            time.sleep(reading_sleep)
            
        # Apply delay before request
        self._delay_request()
        
        start_time = time.time()
        try:
            # Enforce 30s timeout by default
            if 'timeout' not in kwargs:
                kwargs['timeout'] = 30
                
            if self.session_backend == 'httpx':
                raw_resp = self.current_session.request(method, url, **kwargs)
            else:
                raw_resp = self.current_session.request(method, url, **kwargs)
                
            response = SessionResponseWrapper(raw_resp, self.session_backend)
            self.last_latency = time.time() - start_time
            self.request_count += 1
            
            # Persist successful cookies to our local jar
            if response.status_code == 200:
                try:
                    for c_name, c_val in response.cookies.items():
                        self.cookies_jar[c_name] = c_val
                except Exception:
                    pass

            # Detect Cloudflare or standard rate limit block (HTTP 429 / 403 WAF page)
            is_cf_block = 'Server' in response.headers and 'cloudflare' in response.headers['Server'].lower() and response.status_code in [403, 503]
            is_rate_limited = response.status_code == 429
            
            if is_cf_block or is_rate_limited:
                wait_time = random.uniform(12.0, 24.0)
                logger.warning(f"Rate limiting or WAF block detected from {url} (Status: {response.status_code}). Sleeping for {wait_time:.1f}s and rotating session...")
                time.sleep(wait_time)
                
                # Rotate session immediately to swap IP/UA
                self._create_new_session()
                
                # Retry request with fresh identity
                if self.session_backend == 'httpx':
                    raw_resp = self.current_session.request(method, url, **kwargs)
                else:
                    raw_resp = self.current_session.request(method, url, **kwargs)
                response = SessionResponseWrapper(raw_resp, self.session_backend)
                
            return response
            
        except Exception as e:
            logger.error(f"HTTP request failed for {url}: {e}")
            self.last_latency = time.time() - start_time
            
            # Connection errors trigger session recreation to refresh socket pipelines
            self._create_new_session()
            raise

    def close(self):
        """Close current active session client"""
        if self.current_session:
            try:
                self.current_session.close()
            except Exception:
                pass


# Global singleton manager interface
_session_manager = None

def get_session_manager():
    global _session_manager
    if _session_manager is None:
        _session_manager = AdvancedSessionManager()
    return _session_manager

def close_session_manager():
    global _session_manager
    if _session_manager:
        _session_manager.close()
        _session_manager = None