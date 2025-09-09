# utils/module_wrapper.py
import time
import random
import logging
from functools import wraps
from utils.session_manager import get_session_manager, close_session_manager

logger = logging.getLogger(__name__)

class ModuleExecutor:
    def __init__(self):
        self.executed_modules = []
        try:
            self.session_manager = get_session_manager()
        except Exception as e:
            logger.warning(f"Session manager initialization failed: {e}")
            self.session_manager = None
        
        # Modül arası bekleme süreleri (saniye)
        self.module_delays = {
            'light': (3, 7),      # Hafif taramalar için
            'medium': (5, 10),    # Orta seviye taramalar için  
            'heavy': (10, 20),    # Ağır taramalar için
        }
    
    def execute_module(self, module_func, module_name, domain, delay_type='medium', *args, **kwargs):
        """
        Modül çalıştırıcı - her modül öncesi IP/User Agent rotation yapar
        
        Args:
            module_func: Çalıştırılacak modül fonksiyonu
            module_name: Modül adı
            domain: Hedef domain
            delay_type: Gecikme tipi ('light', 'medium', 'heavy')
        """
        try:
            # Önceki modülden sonra bekleme
            if self.executed_modules:
                self._inter_module_delay(delay_type)
            
            logger.info(f"Starting module: {module_name} for domain: {domain}")
            
            # Session rotation (IP ve User Agent değişimi)
            self._rotate_session()
            
            # Modülü çalıştır
            start_time = time.time()
            result = module_func(domain, *args, **kwargs)
            execution_time = time.time() - start_time
            
            # Başarılı modül kaydı
            self.executed_modules.append({
                'name': module_name,
                'domain': domain,
                'execution_time': execution_time,
                'success': True,
                'timestamp': time.time()
            })
            
            logger.info(f"Module {module_name} completed successfully in {execution_time:.2f}s")
            
            # Modül sonrası kısa bekleme
            time.sleep(random.uniform(1, 3))
            
            return result
            
        except Exception as e:
            logger.error(f"Module {module_name} failed for {domain}: {e}")
            
            # Başarısız modül kaydı  
            self.executed_modules.append({
                'name': module_name,
                'domain': domain,
                'execution_time': 0,
                'success': False,
                'error': str(e),
                'timestamp': time.time()
            })
            
            # Hata durumunda daha uzun bekleme
            self._error_recovery_delay()
            
            return {'error': str(e), 'module': module_name}
    
    def _inter_module_delay(self, delay_type='medium'):
        """Modüller arası bekleme"""
        min_delay, max_delay = self.module_delays.get(delay_type, (5, 10))
        delay = random.uniform(min_delay, max_delay)
        
        logger.info(f"Inter-module delay: {delay:.1f} seconds")
        
        # Progress gösterici ile bekleme
        for i in range(int(delay)):
            print(f"\rWaiting... {i+1}/{int(delay)} seconds", end='', flush=True)
            time.sleep(1)
        
        # Kalan kısım için
        remaining = delay - int(delay)
        if remaining > 0:
            time.sleep(remaining)
        
        print()  # Yeni satır
    
    def _rotate_session(self):
        """Session rotation - yeni IP ve User Agent"""
        if self.session_manager:
            logger.info("Rotating session (IP + User Agent)")
            try:
                self.session_manager._create_new_session()
            except Exception as e:
                logger.warning(f"Session rotation failed: {e}")
        else:
            logger.warning("Session manager not available, skipping rotation")
    
    def _error_recovery_delay(self):
        """Hata sonrası recovery bekleme"""
        delay = random.uniform(15, 30)  # Hata durumunda daha uzun bekleme
        logger.info(f"Error recovery delay: {delay:.1f} seconds")
        time.sleep(delay)
    
    def get_execution_summary(self):
        """Çalıştırma özeti"""
        if not self.executed_modules:
            return {
                'total_modules': 0,
                'successful': 0,
                'failed': 0,
                'total_execution_time': 0.0,
                'modules': []
            }
        
        successful = len([m for m in self.executed_modules if m['success']])
        failed = len([m for m in self.executed_modules if not m['success']])
        total_time = sum(m['execution_time'] for m in self.executed_modules)
        
        return {
            'total_modules': len(self.executed_modules),
            'successful': successful,
            'failed': failed,
            'total_execution_time': total_time,
            'modules': self.executed_modules
        }
    
    def cleanup(self):
        """Temizlik işlemleri"""
        try:
            close_session_manager()
            logger.info("Module executor cleanup completed")
        except Exception as e:
            logger.warning(f"Cleanup failed: {e}")

# Decorator için wrapper
def safe_module_execution(delay_type='medium'):
    """
    Modül fonksiyonları için decorator
    
    Usage:
    @safe_module_execution(delay_type='heavy')
    def analyze_security(domain):
        # Modül kodu
    """
    def decorator(func):
        @wraps(func)
        def wrapper(domain, *args, **kwargs):
            # Basit gecikme sistemi (session manager olmasa bile çalışsın)
            delay_ranges = {
                'light': (2, 5),
                'medium': (3, 8), 
                'heavy': (5, 12)
            }
            
            min_delay, max_delay = delay_ranges.get(delay_type, (3, 8))
            delay = random.uniform(min_delay, max_delay)
            
            logger.info(f"Executing {func.__name__} with {delay:.1f}s delay")
            
            if delay > 1:  # Sadece uzun gecikmelerde göster
                print(f"⏳ Waiting {delay:.1f}s before {func.__name__}...")
                time.sleep(delay)
            
            try:
                return func(domain, *args, **kwargs)
            except Exception as e:
                logger.error(f"Module {func.__name__} failed: {e}")
                # Hata durumunda ekstra bekleme
                error_delay = random.uniform(5, 15)
                print(f"⚠️  Error occurred, waiting {error_delay:.1f}s before continuing...")
                time.sleep(error_delay)
                raise
        return wrapper
    return decorator


# Ana execution fonksiyonu
async def execute_modules_safely(domain, selected_modules, module_functions):
    """
    Tüm modülleri güvenli şekilde sırayla çalıştır
    
    Args:
        domain: Hedef domain
        selected_modules: Seçilen modül listesi
        module_functions: Modül fonksiyonları dict'i
    """
    executor = ModuleExecutor()
    results = {}
    
    # Modül tiplerini tanımla (ağırlık seviyesine göre)
    module_weights = {
        'Domain Information': 'light',
        'DNS Records': 'light', 
        'SEO Analysis': 'medium',
        'Web Technologies': 'medium',
        'Security Analysis': 'heavy',
        'Advanced Content Scan': 'heavy',
        'Contact Spy': 'heavy',
        'Subdomain Discovery': 'heavy',
        'Subdomain Takeover': 'heavy',
        'CloudFlare Bypass': 'heavy',
        'Nmap Zero Day Scan': 'heavy',
    }
    
    print(f"\n🚀 Starting analysis for: {domain}")
    print(f"📋 Modules to execute: {len(selected_modules)}")
    print("=" * 60)
    
    for i, module_name in enumerate(selected_modules, 1):
        if module_name in module_functions:
            print(f"\n[{i}/{len(selected_modules)}] 🔍 {module_name}")
            
            # Modül ağırlığına göre delay tipi belirle
            delay_type = module_weights.get(module_name, 'medium')
            
            # Modülü çalıştır
            result = executor.execute_module(
                module_functions[module_name],
                module_name,
                domain,
                delay_type
            )
            
            results[module_name] = result
            
            # Progress göster
            progress = (i / len(selected_modules)) * 100
            print(f"✅ Progress: {progress:.1f}% ({i}/{len(selected_modules)})")
        else:
            logger.warning(f"Module function not found for: {module_name}")
    
    # Özet bilgi
    summary = executor.get_execution_summary()
    print("\n" + "=" * 60)
    print("📊 EXECUTION SUMMARY")
    print("=" * 60)
    print(f"✅ Successful modules: {summary['successful']}")
    print(f"❌ Failed modules: {summary['failed']}")
    print(f"⏱️  Total execution time: {summary['total_execution_time']:.1f}s")
    
    # Cleanup
    executor.cleanup()
    
    return results