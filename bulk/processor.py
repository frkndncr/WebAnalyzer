import json
import time
import logging
import signal
import psutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from tqdm import tqdm
import sys
import os
import importlib
import warnings
import requests
import urllib3
import concurrent.futures
from collections import defaultdict, deque
from threading import Lock
import gc

# SSL uyarılarını ve diğer gereksiz uyarıları kapat
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
requests.packages.urllib3.disable_warnings()
warnings.filterwarnings('ignore')

# Parent directory'yi path'e ekle
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.db_manager import db_manager
from modules.universal_adapter import run_module_universal, is_subdomain, should_skip_domain

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('bulk_scan.log'),
        logging.StreamHandler()
    ]
)

# Modül bazlı timeout ayarları - OPTIMIZE EDİLDİ
TIMEOUT_SETTINGS = {
    'domain_info': 10,
    'domain_dns': 10,
    'seo_analysis': 45,
    'security_analysis': 30,
    'web_technologies': 45
}

# Domain tipi bazlı modül çalıştırma kuralları
MODULE_RULES = {
    'main_domain': ['domain_info', 'domain_dns', 'seo_analysis', 'security_analysis', 'web_technologies'],
    'subdomain': ['domain_dns', 'seo_analysis', 'security_analysis', 'web_technologies'],
    'service_domain': ['domain_dns']
}

# Servis domain pattern'leri
SERVICE_PATTERNS = [
    'stun.l.google.com',
    '.cloudapp.azure.com',
    'clients6.google.com',
    '.cdn.cloudflare.net',
    'rr1.sn-', 'rr2.sn-', 'rr3.sn-',
    '.t-msedge.net',
    'analytics-alv.google.com'
]

def get_domain_type(domain):
    """Domain tipini belirle"""
    for pattern in SERVICE_PATTERNS:
        if pattern in domain.lower():
            return 'service_domain'
    
    if is_subdomain(domain):
        return 'subdomain'
    
    return 'main_domain'

def safe_run_module(module, module_name, domain, max_retries=None):
    """
    Modülü güvenli şekilde çalıştır (timeout + retry desteği ile).
    """
    # Modül bazlı retry sayıları
    if max_retries is None:
        retry_config = {
            'security_analysis': 3,
            'web_technologies': 4,
            'seo_analysis': 4,
            'domain_info': 2,
            'domain_dns': 2
        }
        max_retries = retry_config.get(module_name, 2)
    
    domain_type = get_domain_type(domain)
    allowed_modules = MODULE_RULES.get(domain_type, [])
    
    if module_name not in allowed_modules:
        return {
            "domain": domain,
            "status": "skipped",
            "reason": f"Module not applicable for {domain_type}",
            "execution_time": 0
        }
    
    if should_skip_domain(domain, module_name):
        return {
            "domain": domain,
            "status": "skipped",
            "reason": "Domain in skip list",
            "execution_time": 0
        }
    
    backoff_times = [2.0, 5.0, 10.0]
    
    for attempt in range(max_retries):
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(run_module_universal, module, module_name, domain)
                result = future.result(timeout=TIMEOUT_SETTINGS.get(module_name, 5))
                
                if result and result.get('status') not in ['failed', 'error', 'timeout']:
                    return result
                    
        except concurrent.futures.TimeoutError:
            logging.debug(f"Timeout {module_name} for {domain} (attempt {attempt + 1})")
        except Exception as e:
            logging.debug(f"Module {module_name} error for {domain}: {str(e)[:100]}")
        
        # Retry with backoff
        if attempt < max_retries - 1:
            time.sleep(backoff_times[min(attempt, len(backoff_times) - 1)])
    
    return {
        "domain": domain,
        "status": "failed",
        "error": f"{module_name} failed after {max_retries} retries",
        "execution_time": TIMEOUT_SETTINGS.get(module_name, 5)
    }

class OptimizedBulkProcessor:
    def __init__(self, job_id, max_workers=10):
        self.job_id = job_id
        self.db = db_manager
        self.max_workers = min(max_workers, 20)  # Hard limit
        
        # Cache management
        self.domain_cache = {}
        self.max_cache_size = 10000
        self.cache_lock = Lock()
        
        # Batch updates için queue
        self.pending_updates = {}
        self.update_lock = Lock()
        
        # Shutdown handling
        self.shutdown_requested = False
        self._setup_signal_handlers()
        
        # Performance monitoring
        self.performance_data = {
            'peak_memory': 0,
            'avg_cpu': 0,
            'cpu_samples': deque(maxlen=100)
        }
        
        # Modüller
        self.safe_modules = {
            'domain_info': None,
            'domain_dns': None,
            'seo_analysis': None,
            'security_analysis': None,
            'web_technologies': None
        }
        
        # İstatistikler
        self.domain_type_stats = defaultdict(int)
        
        self._load_modules()
    
    def _setup_signal_handlers(self):
        """Graceful shutdown için signal handler'ları kur"""
        def signal_handler(signum, frame):
            logging.info(f"Shutdown signal received: {signum}")
            self.shutdown_requested = True
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    def _load_modules(self):
        """Modülleri dinamik olarak yükle"""
        for module_name in list(self.safe_modules.keys()):
            try:
                module = importlib.import_module(f'modules.{module_name}')
                self.safe_modules[module_name] = module
                logging.info(f"Module loaded: {module_name}")
            except ImportError as e:
                logging.warning(f"Module {module_name} could not be loaded: {e}")
                del self.safe_modules[module_name]
        
        logging.info(f"Total modules loaded: {len(self.safe_modules)}")
    
    def _cleanup_cache(self):
        """Cache boyutu kontrolü ve temizlik"""
        with self.cache_lock:
            if len(self.domain_cache) > self.max_cache_size:
                # LRU mantığı ile eski entry'leri temizle
                oldest_keys = list(self.domain_cache.keys())[:2000]
                for key in oldest_keys:
                    del self.domain_cache[key]
                logging.debug(f"Cache cleaned, new size: {len(self.domain_cache)}")
    
    def _monitor_resources(self):
        """System resource monitoring"""
        try:
            memory = psutil.virtual_memory()
            cpu = psutil.cpu_percent()
            
            self.performance_data['peak_memory'] = max(
                self.performance_data['peak_memory'], 
                memory.percent
            )
            
            self.performance_data['cpu_samples'].append(cpu)
            self.performance_data['avg_cpu'] = sum(self.performance_data['cpu_samples']) / len(self.performance_data['cpu_samples'])
            
            # Memory pressure kontrolü
            if memory.percent > 85:
                logging.warning(f"High memory usage: {memory.percent}%")
                # Garbage collection'ı tetikle
                gc.collect()
                return True
                
            return False
            
        except Exception as e:
            logging.debug(f"Resource monitoring error: {e}")
            return False
    
    def _calculate_batch_size(self, base_size=100):
        """Dynamic batch size calculation"""
        try:
            memory = psutil.virtual_memory()
            
            if memory.percent > 80:
                return max(20, base_size // 4)
            elif memory.percent > 60:
                return max(50, base_size // 2)
            else:
                return min(200, max(base_size, self.max_workers * 8))
                
        except Exception:
            return base_size
    
    def _batch_update_status(self, domain_id, status):
        """Batch update için status'ları queue'ya ekle"""
        with self.update_lock:
            self.pending_updates[domain_id] = status
            
            # Belirli sayıya ulaştığında batch update yap
            if len(self.pending_updates) >= 10:
                self._flush_batch_updates()
    
    def _flush_batch_updates(self):
        """Pending update'leri database'e gönder"""
        if not self.pending_updates:
            return
            
        try:
            updates = [(status, domain_id) for domain_id, status in self.pending_updates.items()]
            
            # Batch update SQL
            self.db.execute_query(
                "UPDATE domains SET status = %s, updated_at = NOW() WHERE id = %s",
                updates,
                batch=True
            )
            
            self.pending_updates.clear()
            logging.debug(f"Batch updated {len(updates)} domain statuses")
            
        except Exception as e:
            logging.error(f"Batch update failed: {e}")
    
    def _save_checkpoint(self, stats):
        """Progress checkpoint kaydet"""
        try:
            checkpoint = {
                'job_id': self.job_id,
                'processed_count': stats['total_processed'],
                'timestamp': time.time(),
                'domain_cache_size': len(self.domain_cache),
                'performance': self.performance_data
            }
            
            checkpoint_file = f'checkpoint_{self.job_id}.json'
            with open(checkpoint_file, 'w') as f:
                json.dump(checkpoint, f, indent=2)
                
        except Exception as e:
            logging.debug(f"Checkpoint save failed: {e}")
    
    def process_job(self, use_risky_modules=False):
        """Ana işlem fonksiyonu - optimized version"""
        logging.info(f"Starting job #{self.job_id} with {self.max_workers} workers")
        
        # Job status'unu güncelle
        self.db.execute_query(
            "UPDATE scan_jobs SET status = 'running', started_at = NOW() WHERE id = %s",
            (self.job_id,)
        )
        
        stats = {
            'total_processed': 0,
            'successful': 0,
            'failed': 0,
            'skipped': 0,
            'module_results': {},
            'domain_types': defaultdict(int),
            'start_time': time.time(),
            'last_checkpoint': time.time()
        }
        
        # Module stats initialize
        for module_name in self.safe_modules:
            stats['module_results'][module_name] = {
                'success': 0,
                'failed': 0,
                'skipped': 0,
                'total_time': 0
            }
        
        try:
            while not self.shutdown_requested:
                # Dynamic batch size calculation
                batch_size = self._calculate_batch_size()
                
                domains = self.db.get_pending_domains(self.job_id, limit=batch_size)
                if not domains:
                    logging.info("No more domains to process")
                    break
                
                # Resource monitoring
                high_memory = self._monitor_resources()
                if high_memory:
                    logging.warning("High memory detected, reducing batch size")
                    batch_size = max(10, batch_size // 2)
                    time.sleep(2)  # Brief pause for memory recovery
                
                # Cache cleanup if needed
                self._cleanup_cache()
                
                # Unique domain filtering
                unique_domains = self._filter_unique_domains(domains, stats)
                
                if not unique_domains:
                    continue
                
                # Process batch
                self._process_batch(unique_domains, stats)
                
                # Periodic updates
                if time.time() - stats['last_checkpoint'] > 60:  # Her dakika
                    self._update_job_stats(stats)
                    self._save_checkpoint(stats)
                    stats['last_checkpoint'] = time.time()
                
                # Memory pressure check
                if self._monitor_resources():
                    time.sleep(1)  # Brief pause
                
                # Shutdown check
                if self.shutdown_requested:
                    logging.info("Shutdown requested, stopping batch processing")
                    break
        
        except KeyboardInterrupt:
            logging.info("Process interrupted by user")
            self.shutdown_requested = True
        
        except Exception as e:
            logging.error(f"Critical error in process_job: {e}")
            
        finally:
            self._cleanup_and_exit(stats)
            
        return stats
    
    def _filter_unique_domains(self, domains, stats):
        """Unique domain'leri filtrele ve cache'i güncelle"""
        unique_domains = []
        
        with self.cache_lock:
            for domain in domains:
                domain_name = domain['domain']
                if domain_name not in self.domain_cache:
                    unique_domains.append(domain)
                    self.domain_cache[domain_name] = True
                else:
                    # Already processed, mark as skipped
                    self._batch_update_status(domain['id'], 'skipped')
                    stats['skipped'] += 1
        
        if len(domains) != len(unique_domains):
            logging.info(f"Processing {len(unique_domains)} unique domains (skipped {len(domains) - len(unique_domains)} duplicates)")
        
        return unique_domains
    
    def _process_batch(self, domains, stats):
        """Batch processing with optimizations"""
        # Domain type analysis
        domain_type_counts = defaultdict(int)
        for domain in domains:
            domain_type = get_domain_type(domain['domain'])
            domain_type_counts[domain_type] += 1
            stats['domain_types'][domain_type] += 1
        
        logging.info(f"Batch: {len(domains)} domains - {dict(domain_type_counts)}")
        
        with tqdm(total=len(domains), desc="Batch Progress") as pbar:
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                # Submit all tasks
                futures = {
                    executor.submit(self.scan_domain, domain['id'], domain['domain']): domain
                    for domain in domains
                }
                
                # Process results
                for future in as_completed(futures):
                    if self.shutdown_requested:
                        break
                        
                    domain = futures[future]
                    try:
                        result = future.result(timeout=60)
                        
                        # Update stats
                        if result.get('success'):
                            stats['successful'] += 1
                        elif result.get('skipped'):
                            stats['skipped'] += 1
                        else:
                            stats['failed'] += 1
                        
                        # Update module stats
                        for module_name, module_stats in result.get('module_stats', {}).items():
                            if module_name in stats['module_results']:
                                for key in ['success', 'failed', 'skipped']:
                                    stats['module_results'][module_name][key] += module_stats.get(key, 0)
                                stats['module_results'][module_name]['total_time'] += module_stats.get('time', 0)
                                        
                    except concurrent.futures.TimeoutError:
                        logging.error(f"Domain scan timeout for {domain['domain']}")
                        self._batch_update_status(domain['id'], 'timeout')
                        stats['failed'] += 1
                        
                    except Exception as e:
                        logging.error(f"Error processing {domain['domain']}: {str(e)[:100]}")
                        stats['failed'] += 1
                    
                    stats['total_processed'] += 1
                    pbar.update(1)
        
        # Flush any pending updates
        with self.update_lock:
            if self.pending_updates:
                self._flush_batch_updates()
    
    def scan_domain(self, domain_id, domain_name):
        """Tek bir domain'i tara - optimized version"""
        domain_type = get_domain_type(domain_name)
        allowed_modules = MODULE_RULES.get(domain_type, [])
        
        result = {
            'success': False,
            'skipped': False,
            'domain_type': domain_type,
            'module_stats': {}
        }
        
        try:
            self._batch_update_status(domain_id, 'scanning')
            
            successful_modules = 0
            failed_modules = 0
            skipped_modules = 0
            
            for module_name, module in self.safe_modules.items():
                if self.shutdown_requested:
                    break
                    
                if module is None or module_name not in allowed_modules:
                    skipped_modules += 1
                    result['module_stats'][module_name] = {
                        'success': 0, 'failed': 0, 'skipped': 1, 'time': 0
                    }
                    continue
                    
                module_start = time.time()
                
                try:
                    module_result = safe_run_module(module, module_name, domain_name)
                    execution_time = max(0, module_result.get('execution_time', time.time() - module_start))
                    
                    if module_result.get('status') == 'skipped':
                        skipped_modules += 1
                        result['module_stats'][module_name] = {
                            'success': 0, 'failed': 0, 'skipped': 1, 'time': execution_time
                        }
                    else:
                        risk_level, score = self._calculate_risk(module_result)
                        
                        self.db.save_scan_result(
                            domain_id, module_name, module_result, 
                            risk_level, score, execution_time
                        )

                        try:
                            self.db.save_vulnerabilities_from_result(
                                domain_id, module_name, module_result
                            )
                        except Exception as e:
                            logging.debug(f"Vulnerability extraction failed for {domain_name}: {e}")
                        
                        if module_name == 'web_technologies' and 'technologies' in module_result:
                            try:
                                technologies = []
                                tech_list = module_result.get('technologies', [])
                                for tech in tech_list:
                                    if isinstance(tech, str):
                                        technologies.append({
                                            'name': tech,
                                            'category': 'unknown',
                                            'version': None,
                                            'confidence': 90
                                        })
                                    elif isinstance(tech, dict):
                                        technologies.append(tech)
                                
                                if technologies:
                                    self.db.save_technologies_bulk(domain_id, technologies)
                            except Exception as e:
                                logging.debug(f"Technology extraction failed for {domain_name}: {e}")

                        successful_modules += 1
                        result['module_stats'][module_name] = {
                            'success': 1, 'failed': 0, 'skipped': 0, 'time': execution_time
                        }
                        
                except Exception as e:
                    logging.debug(f"Module {module_name} failed for {domain_name}: {str(e)[:100]}")
                    try:
                        self.db.log_scan_activity(
                            domain_id, 'error', 
                            f"Module {module_name} failed: {str(e)[:200]}", 
                            module_name
                        )
                    except Exception as log_error:
                        logging.debug(f"Error logging failed: {log_error}")
                    
                    failed_modules += 1
                    result['module_stats'][module_name] = {
                        'success': 0, 'failed': 1, 'skipped': 0, 'time': time.time() - module_start
                    }
                
                # Brief pause between modules
                time.sleep(2)
            
            # Determine final status
            if successful_modules > 0:
                self._batch_update_status(domain_id, 'completed')
                result['success'] = True
            elif skipped_modules > 0 and failed_modules == 0:
                self._batch_update_status(domain_id, 'partial')
                result['skipped'] = True
            else:
                self._batch_update_status(domain_id, 'failed')
                result['success'] = False
            
        except Exception as e:
            logging.error(f"Failed to scan {domain_name}: {str(e)[:200]}")
            self._batch_update_status(domain_id, 'failed')
            result['success'] = False
        
        return result
    
    def _calculate_risk(self, result):
        """Risk seviyesi hesapla"""
        if not isinstance(result, dict):
            return 'low', 75
            
        if result.get('status') in ['error', 'failed', 'skipped', 'timeout']:
            return 'low', 80
        
        # Security score varsa kullan
        if 'security_score' in result:
            score = result['security_score']
            if score >= 80:
                return 'low', score
            elif score >= 60:
                return 'medium', score
            elif score >= 40:
                return 'high', score
            else:
                return 'critical', score
        
        # Vulnerability count
        if 'vulnerabilities' in result and isinstance(result['vulnerabilities'], list):
            vuln_count = len(result['vulnerabilities'])
            if vuln_count == 0:
                return 'low', 85
            elif vuln_count < 3:
                return 'medium', 65
            elif vuln_count < 5:
                return 'high', 45
            else:
                return 'critical', 25
        
        return 'low', 75
    
    def _update_job_stats(self, stats):
        """İstatistikleri güncelle - optimized"""
        try:
            job_stats = self.db.get_job_statistics(self.job_id)
            
            self.db.execute_query("""
                UPDATE scan_jobs 
                SET completed_domains = %s, 
                    last_activity = NOW()
                WHERE id = %s
            """, (job_stats['completed'], self.job_id))
            
            try:
                self.db.update_job_statistics_auto(self.job_id)
            except Exception as e:
                logging.debug(f"Auto statistics update failed: {e}")

            # Performance report
            if stats['total_processed'] % 100 == 0 and stats['total_processed'] > 0:
                elapsed = time.time() - stats['start_time']
                domains_per_second = stats['total_processed'] / max(elapsed, 1)
                
                logging.info(f"\nProgress Report - Job #{self.job_id}")
                logging.info(f"Processed: {stats['total_processed']} | Success: {stats['successful']} | Failed: {stats['failed']} | Skipped: {stats['skipped']}")
                logging.info(f"Speed: {domains_per_second:.2f} domains/sec")
                logging.info(f"Memory: {self.performance_data['peak_memory']:.1f}% peak | CPU: {self.performance_data['avg_cpu']:.1f}% avg")
                
        except Exception as e:
            logging.error(f"Failed to update stats: {e}")
    
    def _cleanup_and_exit(self, stats):
        """Cleanup ve exit işlemleri"""
        logging.info("Starting cleanup process...")
        
        # Flush any remaining updates
        with self.update_lock:
            if self.pending_updates:
                self._flush_batch_updates()
        
        # Final stats update
        try:
            self._complete_job(stats)
        except Exception as e:
            logging.error(f"Error completing job: {e}")
        
        # Cleanup checkpoint file
        try:
            checkpoint_file = f'checkpoint_{self.job_id}.json'
            if os.path.exists(checkpoint_file):
                os.remove(checkpoint_file)
        except Exception:
            pass
        
        # Memory cleanup
        self.domain_cache.clear()
        gc.collect()
        
        logging.info("Cleanup completed")
    
    def _complete_job(self, stats):
        """Job'ı tamamla - enhanced reporting"""
        elapsed_time = time.time() - stats['start_time']
        
        # Detailed performance report
        report = f"""
        {'='*60}
        Job #{self.job_id} Completed
        {'='*60}
        Total Processed: {stats['total_processed']}
        Successful: {stats['successful']}
        Failed: {stats['failed']}
        Skipped: {stats['skipped']}
        Success Rate: {(stats['successful']/max(stats['total_processed'],1)*100):.1f}%
        Total Time: {elapsed_time:.2f} seconds
        Avg Time/Domain: {elapsed_time/max(stats['total_processed'],1):.2f} seconds
        Speed: {stats['total_processed']/max(elapsed_time,1):.2f} domains/second
        
        Performance Metrics:
        Peak Memory Usage: {self.performance_data['peak_memory']:.1f}%
        Average CPU Usage: {self.performance_data['avg_cpu']:.1f}%
        
        Domain Type Distribution:
        """
        
        for domain_type, count in stats['domain_types'].items():
            percentage = (count / max(stats['total_processed'], 1)) * 100
            report += f"\n  {domain_type}: {count} ({percentage:.1f}%)"
        
        report += "\n\nModule Performance:"
        
        for module_name, module_stats in stats['module_results'].items():
            total = module_stats['success'] + module_stats['failed']
            if total > 0:
                success_rate = (module_stats['success'] / total) * 100
                avg_time = module_stats['total_time'] / max(module_stats['success'], 1)
                report += f"\n  {module_name}:"
                report += f"\n    Success Rate: {success_rate:.1f}%"
                report += f"\n    Successful: {module_stats['success']}"
                report += f"\n    Failed: {module_stats['failed']}"
                report += f"\n    Skipped: {module_stats['skipped']}"
                report += f"\n    Avg Time: {avg_time:.2f}s"
        
        report += f"\n{'='*60}"
        
        logging.info(report)
        
        # Final job status update
        status = 'completed' if not self.shutdown_requested else 'interrupted'
        self.db.execute_query("""
            UPDATE scan_jobs 
            SET status = %s, completed_at = NOW(),
                total_time = %s, success_rate = %s
            WHERE id = %s
        """, (
            status, 
            elapsed_time, 
            (stats['successful']/max(stats['total_processed'],1)*100),
            self.job_id
        ))

# Backwards compatibility
BulkProcessor = OptimizedBulkProcessor