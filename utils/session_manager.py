# utils/session_manager.py
import requests
import random
import time
import itertools
from fake_useragent import UserAgent
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import logging

logger = logging.getLogger(__name__)

class AdvancedSessionManager:
    def __init__(self, delay_range=(2, 5), max_retries=3):
        self.delay_range = delay_range
        self.max_retries = max_retries
        self.user_agent = UserAgent()
        self.current_session = None
        self.request_count = 0
        self.max_requests_per_session = random.randint(5, 15)  # Her session için max istek sayısı
        
        # Proxy listesi (örnek - kendi proxy'lerinizi ekleyin)
        self.proxies_list = [
            None,  # Proxy yok
            # {'http': 'http://proxy1:port', 'https': 'https://proxy1:port'},
            # {'http': 'http://proxy2:port', 'https': 'https://proxy2:port'},
        ]
        self.proxy_cycle = itertools.cycle(self.proxies_list)
        
        # Farklı User Agent kategorileri
        self.user_agents = [
            # Modern Chrome
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            
            # Firefox
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/121.0',
            
            # Safari
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
            
            # Edge
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
            
            # Mobile
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (Android 14; Mobile; rv:109.0) Gecko/109.0 Firefox/121.0',
        ]
        
        self._create_new_session()
    
    def _create_new_session(self):
        """Yeni session oluştur ve konfigüre et"""
        if self.current_session:
            self.current_session.close()
        
        self.current_session = requests.Session()
        
        # Retry stratejisi
        try:
            # Yeni urllib3 versiyonu için
            retry_strategy = Retry(
                total=self.max_retries,
                status_forcelist=[429, 500, 502, 503, 504],
                allowed_methods=["HEAD", "GET", "OPTIONS"],
                backoff_factor=1
            )
        except TypeError:
            # Eski urllib3 versiyonu için
            retry_strategy = Retry(
                total=self.max_retries,
                status_forcelist=[429, 500, 502, 503, 504],
                method_whitelist=["HEAD", "GET", "OPTIONS"],
                backoff_factor=1
            )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.current_session.mount("http://", adapter)
        self.current_session.mount("https://", adapter)
        
        # Random User Agent
        user_agent = random.choice(self.user_agents)
        
        # Gerçekçi headers
        headers = {
            'User-Agent': user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9,tr;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Charset': 'UTF-8,*;q=0.7',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': '1',
            'DNT': '1',
            'Connection': 'keep-alive',
        }
        
        self.current_session.headers.update(headers)
        
        # Proxy ayarla
        current_proxy = next(self.proxy_cycle)
        if current_proxy:
            self.current_session.proxies.update(current_proxy)
            logger.info(f"Using proxy: {current_proxy}")
        
        self.request_count = 0
        self.max_requests_per_session = random.randint(5, 15)
        
        logger.info(f"Created new session with User-Agent: {user_agent}")
    
    def _should_rotate_session(self):
        """Session'ın rotate edilmesi gerekip gerekmediğini kontrol et"""
        return self.request_count >= self.max_requests_per_session
    
    def _delay_request(self):
        """İstekler arası gecikme"""
        delay = random.uniform(*self.delay_range)
        logger.debug(f"Waiting {delay:.2f} seconds before next request")
        time.sleep(delay)
    
    def get(self, url, **kwargs):
        """GET isteği gönder"""
        return self._make_request('GET', url, **kwargs)
    
    def post(self, url, **kwargs):
        """POST isteği gönder"""
        return self._make_request('POST', url, **kwargs)
    
    def _make_request(self, method, url, **kwargs):
        """HTTP isteği gönder"""
        # Session rotation kontrolü
        if self._should_rotate_session():
            logger.info("Rotating session...")
            self._create_new_session()
        
        # İstek öncesi gecikme
        self._delay_request()
        
        try:
            # Timeout ekle (eğer yoksa)
            if 'timeout' not in kwargs:
                kwargs['timeout'] = 30
            
            response = self.current_session.request(method, url, **kwargs)
            self.request_count += 1
            
            # Rate limiting tespiti
            if response.status_code == 429:
                logger.warning(f"Rate limited by {url}. Waiting longer...")
                time.sleep(random.uniform(10, 20))
                # Yeni session oluştur
                self._create_new_session()
                # Tekrar dene
                response = self.current_session.request(method, url, **kwargs)
            
            return response
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed for {url}: {e}")
            # Connection error durumunda session yenile
            self._create_new_session()
            raise
    
    def close(self):
        """Session'ı kapat"""
        if self.current_session:
            self.current_session.close()


# Singleton pattern ile global session manager
_session_manager = None

def get_session_manager():
    """Global session manager'ı al"""
    global _session_manager
    if _session_manager is None:
        _session_manager = AdvancedSessionManager()
    return _session_manager

def close_session_manager():
    """Global session manager'ı kapat"""
    global _session_manager
    if _session_manager:
        _session_manager.close()
        _session_manager = None