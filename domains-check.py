#!/usr/bin/env python3
"""
Advanced Domain Checker v2.0
Enhanced domain validation for WebAnalyzer bulk scanning
"""

import json
import socket
import requests
import argparse
import urllib3
import logging
import time
import concurrent.futures
from typing import List, Dict, Any
import dns.resolver
import ssl
from urllib.parse import urlparse
import threading

# SSL uyarılarını kapat
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
requests.packages.urllib3.disable_warnings()

# Logging ayarı
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('domain_checker.log'),
        logging.StreamHandler()
    ]
)

# Skip pattern listesi (bulk_processor ile uyumlu)
SKIP_PATTERNS = [
    'stun.l.google.com',
    '.cloudapp.azure.com', 
    'clients6.google.com',
    '.cdn.cloudflare.net',
    'rr1.sn-', 'rr2.sn-', 'rr3.sn-', 'rr4.sn-', 'rr5.sn-',
    'e-0014.e-msedge',
    's-part-',
    '.t-msedge.net',
    'perimeterx.map',
    'i.ytimg.com',
    'analytics-alv.google.com',
    'signaler-pa.clients',
    'westus-0.in.applicationinsights'
]

# Enhanced validation settings
VALIDATION_CONFIG = {
    'dns_timeout': 3,
    'http_timeout': 8,
    'ssl_timeout': 5,
    'max_workers': 10,
    'retry_attempts': 2,
    'backoff_delay': 1.0
}

class DomainChecker:
    def __init__(self, max_workers=10):
        self.max_workers = max_workers
        self.stats = {
            'total': 0,
            'valid': 0,
            'invalid': 0,
            'skipped': 0,
            'dns_failed': 0,
            'http_failed': 0,
            'ssl_failed': 0
        }
        self.lock = threading.Lock()

    def should_skip_domain(self, domain):
        """Enhanced skip pattern kontrolü"""
        domain_lower = domain.lower()
        
        # Skip pattern kontrolü
        for pattern in SKIP_PATTERNS:
            if pattern in domain_lower:
                return True, f"Matches skip pattern: {pattern}"
        
        # IP address kontrolü
        if self._is_ip_address(domain):
            return True, "IP address detected"
        
        # Localhost/internal kontrolü
        if any(internal in domain_lower for internal in ['localhost', '127.0.0.1', '0.0.0.0', '192.168.']):
            return True, "Internal/localhost domain"
        
        # Çok kısa veya çok uzun domain kontrolü
        if len(domain) < 4 or len(domain) > 253:
            return True, "Invalid domain length"
        
        return False, ""

    def _is_ip_address(self, domain):
        """IP adresi kontrolü"""
        try:
            socket.inet_aton(domain)
            return True
        except socket.error:
            return False

    def validate_dns(self, domain):
        """Advanced DNS validation"""
        try:
            # A record kontrolü
            resolver = dns.resolver.Resolver()
            resolver.timeout = VALIDATION_CONFIG['dns_timeout']
            resolver.lifetime = VALIDATION_CONFIG['dns_timeout']
            
            # A record
            try:
                a_records = resolver.resolve(domain, 'A')
                if not a_records:
                    return False, "No A records found"
            except dns.resolver.NXDOMAIN:
                return False, "Domain does not exist (NXDOMAIN)"
            except dns.resolver.NoAnswer:
                return False, "No A record answer"
            except Exception as e:
                return False, f"DNS resolution failed: {str(e)[:100]}"
            
            # MX record kontrolü (optional)
            try:
                mx_records = resolver.resolve(domain, 'MX')
                mx_exists = bool(mx_records)
            except:
                mx_exists = False
            
            return True, {
                'ip_addresses': [str(record) for record in a_records],
                'mx_exists': mx_exists,
                'dns_response_time': time.time()
            }
            
        except Exception as e:
            return False, f"DNS validation error: {str(e)[:100]}"

    def validate_http_connectivity(self, domain):
        """Enhanced HTTP connectivity check"""
        results = {
            'http_reachable': False,
            'https_reachable': False,
            'http_status': None,
            'https_status': None,
            'redirects_to_https': False,
            'response_time': None
        }
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'close'
        }
        
        # HTTPS check first (more common now)
        start_time = time.time()
        try:
            response = requests.head(
                f"https://{domain}", 
                timeout=VALIDATION_CONFIG['http_timeout'],
                headers=headers,
                verify=False,
                allow_redirects=True
            )
            results['https_reachable'] = True
            results['https_status'] = response.status_code
            results['response_time'] = time.time() - start_time
            
            if response.status_code < 500:
                return True, results
                
        except requests.RequestException as e:
            results['https_error'] = str(e)[:100]
        
        # HTTP check
        try:
            response = requests.head(
                f"http://{domain}",
                timeout=VALIDATION_CONFIG['http_timeout'],
                headers=headers,
                allow_redirects=False
            )
            results['http_reachable'] = True
            results['http_status'] = response.status_code
            
            # Check for HTTPS redirect
            if response.status_code in [301, 302, 307, 308]:
                location = response.headers.get('Location', '')
                if location.startswith('https://'):
                    results['redirects_to_https'] = True
            
            if response.status_code < 500:
                return True, results
                
        except requests.RequestException as e:
            results['http_error'] = str(e)[:100]
        
        # Eğer hiçbiri çalışmıyorsa
        if not results['http_reachable'] and not results['https_reachable']:
            return False, "No HTTP/HTTPS connectivity"
        
        return True, results

    def validate_ssl(self, domain):
        """SSL certificate validation"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((domain, 443), timeout=VALIDATION_CONFIG['ssl_timeout']) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    return True, {
                        'ssl_available': True,
                        'protocol_version': ssock.version(),
                        'cipher_suite': ssock.cipher()[0] if ssock.cipher() else 'Unknown'
                    }
                    
        except Exception as e:
            return False, f"SSL validation failed: {str(e)[:100]}"

    def validate_domain_comprehensive(self, domain):
        """Comprehensive domain validation"""
        validation_result = {
            'domain': domain,
            'valid': False,
            'skip_reason': None,
            'dns_valid': False,
            'http_valid': False,
            'ssl_valid': False,
            'validation_details': {},
            'errors': []
        }
        
        # Skip pattern kontrolü
        should_skip, skip_reason = self.should_skip_domain(domain)
        if should_skip:
            validation_result['skip_reason'] = skip_reason
            with self.lock:
                self.stats['skipped'] += 1
            return validation_result
        
        # DNS validation
        dns_valid, dns_result = self.validate_dns(domain)
        validation_result['dns_valid'] = dns_valid
        if dns_valid:
            validation_result['validation_details']['dns'] = dns_result
        else:
            validation_result['errors'].append(f"DNS: {dns_result}")
            with self.lock:
                self.stats['dns_failed'] += 1
        
        # HTTP connectivity check
        if dns_valid:
            http_valid, http_result = self.validate_http_connectivity(domain)
            validation_result['http_valid'] = http_valid
            if http_valid:
                validation_result['validation_details']['http'] = http_result
            else:
                validation_result['errors'].append(f"HTTP: {http_result}")
                with self.lock:
                    self.stats['http_failed'] += 1
            
            # SSL validation
            ssl_valid, ssl_result = self.validate_ssl(domain)
            validation_result['ssl_valid'] = ssl_valid
            if ssl_valid:
                validation_result['validation_details']['ssl'] = ssl_result
            else:
                validation_result['errors'].append(f"SSL: {ssl_result}")
                with self.lock:
                    self.stats['ssl_failed'] += 1
        
        # Overall validity
        validation_result['valid'] = dns_valid and http_valid
        
        with self.lock:
            if validation_result['valid']:
                self.stats['valid'] += 1
            else:
                self.stats['invalid'] += 1
        
        return validation_result

    def process_domains_parallel(self, domains):
        """Parallel domain processing"""
        valid_domains = []
        validation_results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all validation tasks
            future_to_domain = {
                executor.submit(self.validate_domain_comprehensive, entry.get("domain_name", "")): entry
                for entry in domains if entry.get("domain_name")
            }
            
            # Process results
            for future in concurrent.futures.as_completed(future_to_domain):
                entry = future_to_domain[future]
                try:
                    result = future.result(timeout=30)
                    validation_results.append(result)
                    
                    if result['valid']:
                        logging.info(f"✅ Valid domain: {result['domain']}")
                        valid_domains.append({"domain_name": result['domain']})
                    elif result['skip_reason']:
                        logging.info(f"⛔ Skipped: {result['domain']} - {result['skip_reason']}")
                    else:
                        logging.warning(f"❌ Invalid domain: {result['domain']} - {', '.join(result['errors'])}")
                        
                except concurrent.futures.TimeoutError:
                    logging.error(f"⏰ Timeout validating: {entry.get('domain_name', 'Unknown')}")
                    with self.lock:
                        self.stats['invalid'] += 1
                except Exception as e:
                    logging.error(f"💥 Error validating {entry.get('domain_name', 'Unknown')}: {e}")
                    with self.lock:
                        self.stats['invalid'] += 1
        
        return valid_domains, validation_results

    def generate_report(self, validation_results, output_dir="reports"):
        """Generate detailed validation report"""
        import os
        os.makedirs(output_dir, exist_ok=True)
        
        # Summary report
        summary = {
            'total_domains': self.stats['total'],
            'valid_domains': self.stats['valid'],
            'invalid_domains': self.stats['invalid'],
            'skipped_domains': self.stats['skipped'],
            'success_rate': (self.stats['valid'] / max(self.stats['total'], 1)) * 100,
            'failure_breakdown': {
                'dns_failures': self.stats['dns_failed'],
                'http_failures': self.stats['http_failed'],
                'ssl_failures': self.stats['ssl_failed']
            }
        }
        
        # Save detailed results
        with open(f"{output_dir}/validation_summary.json", "w") as f:
            json.dump(summary, f, indent=2)
        
        with open(f"{output_dir}/detailed_results.json", "w") as f:
            json.dump(validation_results, f, indent=2)
        
        logging.info(f"📊 Reports saved to {output_dir}/")
        return summary

def main():
    parser = argparse.ArgumentParser(
        description="Advanced Domain Checker v2.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python domain_checker.py --input domains.json --output valid_domains.json
  python domain_checker.py --input domains.json --output valid_domains.json --workers 15
  python domain_checker.py --input domains.json --output valid_domains.json --report-dir reports
        """
    )
    
    parser.add_argument("--input", required=True, help="Input JSON file with domains")
    parser.add_argument("--output", required=True, help="Output JSON file for valid domains")
    parser.add_argument("--workers", type=int, default=10, help="Number of parallel workers (default: 10)")
    parser.add_argument("--report-dir", default="reports", help="Directory for detailed reports")
    parser.add_argument("--timeout", type=int, default=8, help="HTTP timeout in seconds")
    
    args = parser.parse_args()
    
    # Update configuration
    VALIDATION_CONFIG['http_timeout'] = args.timeout
    
    # Initialize checker
    checker = DomainChecker(max_workers=args.workers)
    
    # Load domains
    try:
        with open(args.input, "r", encoding='utf-8') as f:
            domains = json.load(f)
        logging.info(f"📥 Loaded {len(domains)} domains from {args.input}")
        checker.stats['total'] = len(domains)
    except Exception as e:
        logging.error(f"❌ Failed to load input file: {e}")
        return 1
    
    # Process domains
    start_time = time.time()
    valid_domains, validation_results = checker.process_domains_parallel(domains)
    processing_time = time.time() - start_time
    
    # Save valid domains
    try:
        with open(args.output, "w", encoding='utf-8') as f:
            json.dump(valid_domains, f, indent=2, ensure_ascii=False)
        logging.info(f"💾 {len(valid_domains)} valid domains saved to {args.output}")
    except Exception as e:
        logging.error(f"❌ Failed to save output file: {e}")
        return 1
    
    # Generate report
    summary = checker.generate_report(validation_results, args.report_dir)
    
    # Final stats
    logging.info(f"""
🎉 Domain Validation Completed!
{'='*50}
Total Processed: {checker.stats['total']}
✅ Valid: {checker.stats['valid']} ({summary['success_rate']:.1f}%)
❌ Invalid: {checker.stats['invalid']}
⛔ Skipped: {checker.stats['skipped']}
⏱️  Processing Time: {processing_time:.2f} seconds
🚀 Speed: {checker.stats['total']/max(processing_time,1):.2f} domains/sec
{'='*50}
    """)
    
    return 0

if __name__ == "__main__":
    exit(main())