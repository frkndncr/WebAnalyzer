# config.py - Configuration management for WebAnalyzer
import os
from dataclasses import dataclass
from typing import List, Tuple, Optional, Dict
import json

@dataclass
class SessionConfig:
    """Session management configuration"""
    min_delay: float = 2.0
    max_delay: float = 5.0
    max_retries: int = 3
    max_requests_per_session: int = 15
    timeout: int = 30
    rotate_after_error: bool = True
    
@dataclass  
class ModuleConfig:
    """Module execution configuration"""
    inter_module_delay: Dict[str, Tuple[float, float]] = None
    error_recovery_delay: Tuple[float, float] = (15.0, 30.0)
    max_concurrent_modules: int = 1  # Sıralı execution için 1
    
    def __post_init__(self):
        if self.inter_module_delay is None:
            self.inter_module_delay = {
                'light': (3.0, 7.0),
                'medium': (5.0, 10.0), 
                'heavy': (10.0, 20.0)
            }

@dataclass
class ProxyConfig:
    """Proxy configuration"""
    enabled: bool = False
    proxy_list: List[Dict[str, str]] = None
    rotation_enabled: bool = True
    
    def __post_init__(self):
        if self.proxy_list is None:
            self.proxy_list = []

@dataclass
class UserAgentConfig:
    """User Agent configuration"""
    rotation_enabled: bool = True
    custom_agents: List[str] = None
    use_fake_useragent: bool = True
    
    def __post_init__(self):
        if self.custom_agents is None:
            self.custom_agents = [
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

@dataclass
class AppConfig:
    """Main application configuration"""
    # API Keys
    whois_api_key: str = "at_14sqNbh0sbZ61CY1Bl0meKYgVKrL8"  # WhoisXML API key
    
    # Directories
    output_dir: str = "logs"
    log_file: str = "webanalyzer.log"
    
    # Module configurations
    session: SessionConfig = None
    modules: ModuleConfig = None
    proxy: ProxyConfig = None
    user_agent: UserAgentConfig = None
    
    # Module weights (for delay calculation)
    module_weights: Dict[str, str] = None
    
    # Rate limiting detection
    rate_limit_detection: Dict[str, any] = None
    
    def __post_init__(self):
        # Environment variables
        self.whois_api_key = os.getenv('WHOIS_API_KEY', self.whois_api_key)
        
        if self.session is None:
            self.session = SessionConfig()
        if self.modules is None:
            self.modules = ModuleConfig()
        if self.proxy is None:
            self.proxy = ProxyConfig()
        if self.user_agent is None:
            self.user_agent = UserAgentConfig()
            
        if self.module_weights is None:
            self.module_weights = {
                'Domain Information': 'light',
                'DNS Records': 'light',
                'SEO Analysis': 'medium', 
                'Web Technologies': 'medium',
                'Security Analysis': 'heavy',
                'Advanced Content Scan': 'heavy',
                'API Security Scanner': 'heavy',
                'Contact Spy': 'heavy',
                'Subdomain Discovery': 'heavy',
                'Subdomain Takeover': 'heavy',
                'CloudFlare Bypass': 'heavy',
                'Nmap Zero Day Scan': 'heavy',
            }
            
        if self.rate_limit_detection is None:
            self.rate_limit_detection = {
                'status_codes': [429, 503, 502],
                'keywords': ['rate limit', 'too many requests', 'blocked'],
                'retry_delay': (10.0, 30.0)
            }

class ConfigManager:
    """Configuration manager with file support"""
    
    def __init__(self, config_file: str = "webanalyzer_config.json"):
        self.config_file = config_file
        self.config = self.load_config()
    
    def load_config(self) -> AppConfig:
        """Load configuration from file or create default"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    config_dict = json.load(f)
                return self._dict_to_config(config_dict)
            except Exception as e:
                print(f"Error loading config: {e}. Using defaults.")
                return AppConfig()
        else:
            config = AppConfig()
            self.save_config(config)
            return config
    
    def save_config(self, config: AppConfig = None):
        """Save configuration to file"""
        if config is None:
            config = self.config
            
        config_dict = self._config_to_dict(config)
        
        try:
            with open(self.config_file, 'w') as f:
                json.dump(config_dict, f, indent=4)
            print(f"Configuration saved to {self.config_file}")
        except Exception as e:
            print(f"Error saving config: {e}")
    
    def _config_to_dict(self, config: AppConfig) -> dict:
        """Convert config object to dictionary"""
        return {
            'whois_api_key': config.whois_api_key,
            'output_dir': config.output_dir,
            'log_file': config.log_file,
            'session': {
                'min_delay': config.session.min_delay,
                'max_delay': config.session.max_delay,
                'max_retries': config.session.max_retries,
                'max_requests_per_session': config.session.max_requests_per_session,
                'timeout': config.session.timeout,
                'rotate_after_error': config.session.rotate_after_error,
            },
            'modules': {
                'inter_module_delay': config.modules.inter_module_delay,
                'error_recovery_delay': config.modules.error_recovery_delay,
                'max_concurrent_modules': config.modules.max_concurrent_modules,
            },
            'proxy': {
                'enabled': config.proxy.enabled,
                'proxy_list': config.proxy.proxy_list,
                'rotation_enabled': config.proxy.rotation_enabled,
            },
            'user_agent': {
                'rotation_enabled': config.user_agent.rotation_enabled,
                'custom_agents': config.user_agent.custom_agents,
                'use_fake_useragent': config.user_agent.use_fake_useragent,
            },
            'module_weights': config.module_weights,
            'rate_limit_detection': config.rate_limit_detection,
        }
    
    def _dict_to_config(self, config_dict: dict) -> AppConfig:
        """Convert dictionary to config object"""
        return AppConfig(
            whois_api_key=config_dict.get('whois_api_key', ''),
            output_dir=config_dict.get('output_dir', 'logs'),
            log_file=config_dict.get('log_file', 'webanalyzer.log'),
            session=SessionConfig(**config_dict.get('session', {})),
            modules=ModuleConfig(**config_dict.get('modules', {})),
            proxy=ProxyConfig(**config_dict.get('proxy', {})),
            user_agent=UserAgentConfig(**config_dict.get('user_agent', {})),
            module_weights=config_dict.get('module_weights', {}),
            rate_limit_detection=config_dict.get('rate_limit_detection', {}),
        )
    
    def get_config(self) -> AppConfig:
        """Get current configuration"""
        return self.config
    
    def update_proxy_list(self, proxy_list: List[Dict[str, str]]):
        """Update proxy list"""
        self.config.proxy.proxy_list = proxy_list
        self.config.proxy.enabled = len(proxy_list) > 0
        self.save_config()
    
    def update_delays(self, light: Tuple[float, float] = None, 
                     medium: Tuple[float, float] = None,
                     heavy: Tuple[float, float] = None):
        """Update module delay configurations"""
        if light:
            self.config.modules.inter_module_delay['light'] = light
        if medium:
            self.config.modules.inter_module_delay['medium'] = medium
        if heavy:
            self.config.modules.inter_module_delay['heavy'] = heavy
        self.save_config()

# Global configuration instance
config_manager = ConfigManager()

def get_config() -> AppConfig:
    """Get global configuration instance"""
    return config_manager.get_config()

# Example usage and CLI configuration
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='WebAnalyzer Configuration Manager')
    parser.add_argument('--create-config', action='store_true', help='Create default config file')
    parser.add_argument('--show-config', action='store_true', help='Show current configuration')
    parser.add_argument('--add-proxy', help='Add proxy (format: http://ip:port or https://ip:port)')
    parser.add_argument('--set-api-key', help='Set WHOIS API key')
    
    args = parser.parse_args()
    
    manager = ConfigManager()
    
    if args.create_config:
        manager.save_config()
        print("Default configuration created.")
    
    if args.show_config:
        config = manager.get_config()
        print(json.dumps(manager._config_to_dict(config), indent=2))
    
    if args.add_proxy:
        proxy_url = args.add_proxy
        proxy_dict = {'http': proxy_url, 'https': proxy_url}
        current_proxies = manager.config.proxy.proxy_list
        current_proxies.append(proxy_dict)
        manager.update_proxy_list(current_proxies)
        print(f"Proxy added: {proxy_url}")
    
    if args.set_api_key:
        manager.config.whois_api_key = args.set_api_key
        manager.save_config()
        print("API key updated.")