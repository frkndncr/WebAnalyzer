import nmap
import requests
import json
import time
import socket
import ssl
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
import logging
from datetime import datetime

# Loglama ayarları: Sadece ERROR seviyesini ekrana yaz
logging.basicConfig(level=logging.ERROR, format='[ERROR] %(message)s')
logger = logging.getLogger(__name__)

class AdvancedNetworkScanner:
    def __init__(self, timeout=10, aggressive_mode=False, output_file="scan_report.json"):
        logger.debug("Initializing AdvancedNetworkScanner...")
        try:
            self.nm = nmap.PortScanner()
            logger.debug("Nmap successfully loaded.")
        except nmap.PortScannerError:
            raise Exception("Nmap is not installed or not found in PATH")
        self.timeout = timeout
        self.aggressive_mode = aggressive_mode
        self.output_file = output_file
        self.exploit_db_url = "https://www.exploit-db.com/search"

    def advanced_dns_resolve(self, domain):
        logger.debug(f"Resolving DNS for: {domain}")
        try:
            ipv4 = socket.gethostbyname(domain)
            logger.debug(f"IPv4 found: {ipv4}")
            ipv6 = None
            try:
                ipv6 = socket.getaddrinfo(domain, None, socket.AF_INET6)[0][4][0]
                logger.debug(f"IPv6 found: {ipv6}")
            except:
                logger.debug("IPv6 not found.")
            
            dns_records = {'A': socket.gethostbyname_ex(domain)[2], 'MX': [], 'NS': []}
            resolver = dns.resolver.Resolver()
            try:
                dns_records['MX'] = [str(r.exchange) for r in resolver.resolve(domain, 'MX')]
                dns_records['NS'] = [str(r.target) for r in resolver.resolve(domain, 'NS')]
                logger.debug("MX and NS records retrieved.")
            except:
                logger.debug("MX or NS records not retrieved.")
            
            return {'ipv4': ipv4, 'ipv6': ipv6, 'dns_records': dns_records}
        except Exception as e:
            logger.error(f"DNS resolution failed: {str(e)}")
            return {'error': f"DNS resolution failed: {str(e)}"}

    def advanced_port_scan(self, target):
        scan_args = '-sV -Pn -A -T5' if self.aggressive_mode else '-sV -Pn -F -T5'
        logger.debug(f"Starting port scan on: {target} (Args: {scan_args})")
        
        results = {'open_ports': [], 'services': {}, 'os_detection': None, 'network_info': {}, 'scripts': {}, 'vulnerabilities': []}
        try:
            start_time = time.time()
            scan_result = self.nm.scan(target, arguments=scan_args)
            if target not in scan_result['scan']:
                logger.error("Target not found in scan results.")
                return {'error': 'No scan results for target'}
            
            host = scan_result['scan'][target]
            logger.debug("Scan completed, processing results...")

            if 'osmatch' in host and self.aggressive_mode:
                results['os_detection'] = [{'name': os.get('name', ''), 'accuracy': os.get('accuracy', 0)} for os in host['osmatch']]

            for proto in self.nm[target].all_protocols():
                ports = self.nm[target][proto].keys()
                for port in ports:
                    service = self.nm[target][proto][port]
                    port_info = {
                        'port': port, 'state': service.get('state', ''),
                        'service': service.get('name', 'unknown'), 'product': service.get('product', ''),
                        'version': service.get('version', ''), 'extrainfo': service.get('extrainfo', ''),
                        'cpe': service.get('cpe', [])
                    }
                    if 'script' in service:
                        results['scripts'][port] = service['script']
                    results['open_ports'].append(port)
                    results['services'][port] = port_info

            results['network_info'] = {
                'hostname': host.get('hostnames', [{}])[0].get('name', ''),
                'status': host.get('status', {}).get('state', ''),
                'addresses': host.get('addresses', {})
            }
            execution_time = time.time() - start_time
            logger.debug(f"Port scan results processed. Duration: {execution_time:.2f} seconds")
        except Exception as e:
            logger.error(f"Port scan error: {str(e)}")
            return {'error': f"Port scan failed: {str(e)}"}
        
        return results

    def fetch_zero_day_vulnerabilities(self, services):
        logger.debug("Starting zero-day vulnerability scan...")
        vulnerabilities = []
        
        def advanced_cve_search(service_name, version):
            all_vulns = []
            if not service_name or not version:
                return all_vulns
            try:
                logger.debug(f"Searching CVEs for: {service_name} {version}")
                nvd_params = {'keywordSearch': f"{service_name} {version}", 'resultsPerPage': 10}
                headers = {'User-Agent': 'AdvancedNetworkScanner/1.0'}
                response = requests.get('https://services.nvd.nist.gov/rest/json/cves/2.0', params=nvd_params, headers=headers, timeout=self.timeout)
                response.raise_for_status()
                nvd_data = response.json()
                for item in nvd_data.get('vulnerabilities', []):
                    cve = item.get('cve', {})
                    vuln = {
                        'source': 'NVD', 'cve_id': cve.get('id', 'N/A'),
                        'description': cve.get('descriptions', [{}])[0].get('value', ''),
                        'severity': self._calculate_severity(cve), 'published_date': cve.get('published', '')
                    }
                    all_vulns.append(vuln)
            except Exception as e:
                logger.error(f"CVE search error: {str(e)}")
            return all_vulns

        def exploit_db_search(service_name, version):
            all_exploits = []
            try:
                logger.debug(f"Searching Exploit-DB for: {service_name} {version}")
                params = {'q': f"{service_name} {version}"}
                headers = {'User-Agent': 'AdvancedNetworkScanner/1.0'}
                response = requests.get(self.exploit_db_url, params=params, headers=headers, timeout=self.timeout)
                if response.status_code == 200:
                    all_exploits.append({
                        'source': 'Exploit-DB',
                        'description': f"Potential exploit for {service_name} {version}",
                        'url': str(response.url)
                    })
            except Exception as e:
                logger.error(f"Exploit-DB search error: {str(e)}")
            return all_exploits

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            for port, service in services.items():
                futures.append(executor.submit(advanced_cve_search, service.get('service', ''), service.get('version', '')))
                futures.append(executor.submit(exploit_db_search, service.get('service', ''), service.get('version', '')))
            
            for future in as_completed(futures):
                vulnerabilities.extend(future.result())
        
        logger.debug(f"Found {len(vulnerabilities)} zero-day vulnerabilities and exploits.")
        return vulnerabilities

    def _calculate_severity(self, cve):
        try:
            metrics = cve.get('metrics', {}).get('cvssMetricV31', [{}])[0]
            base_score = metrics.get('cvssData', {}).get('baseScore', 0)
            return {'level': 'Critical' if base_score >= 9 else 'High' if base_score >= 7 else 'Medium' if base_score >= 4 else 'Low' if base_score > 0 else 'Unknown', 'score': base_score}
        except:
            return {'level': 'Unknown', 'score': 0}

    def ssl_advanced_check(self, target):
        logger.debug(f"Checking SSL/TLS for: {target}")
        try:
            context = ssl.create_default_context()
            with socket.create_connection((target, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=target) as secure_sock:
                    cert = secure_sock.getpeercert()
                    return {
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'subject': dict(x[0] for x in cert['subject']),
                        'version': secure_sock.version(),
                        'expiration': cert.get('notAfter'),
                        'start_date': cert.get('notBefore'),
                        'serial_number': cert.get('serialNumber')
                    }
        except Exception as e:
            logger.error(f"SSL check error: {str(e)}")
            return {'error': f"SSL check failed: {str(e)}"}

    def run_comprehensive_scan(self, domain):
        logger.debug(f"Starting comprehensive scan for domain: {domain}")
        results = {'domain': domain, 'dns_info': {}, 'port_scan': {}, 'zero_day_vulnerabilities': [], 'ssl_info': {}}

        results['dns_info'] = self.advanced_dns_resolve(domain)
        ip = results['dns_info'].get('ipv4')
        
        if not ip or 'error' in results['dns_info']:
            logger.error(f"IP not found for {domain}, scan aborted.")
            self._save_report(results)
            return results

        results['port_scan'] = self.advanced_port_scan(ip)
        results['zero_day_vulnerabilities'] = self.fetch_zero_day_vulnerabilities(results['port_scan'].get('services', {}))
        results['ssl_info'] = self.ssl_advanced_check(domain)

        # Raporu dosyaya kaydet
        self._save_report(results)
        logger.debug("Comprehensive scan completed.")
        return results

    def _save_report(self, results):
        try:
            with open(self.output_file, 'w') as f:
                json.dump(results, f, indent=2)
            logger.debug(f"Scan report saved to {self.output_file}")
            
            # CSV formatında da kaydet
            csv_file = self.output_file.replace('.json', '.csv')
            with open(csv_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Domain', 'Port', 'Service', 'Version', 'CVE/Exploit', 'Description', 'Severity'])
                for port in results['port_scan'].get('open_ports', []):
                    service = results['port_scan']['services'][port]
                    writer.writerow([results['domain'], port, service['service'], service['version'], '', '', ''])
                for vuln in results['zero_day_vulnerabilities']:
                    writer.writerow([results['domain'], '', '', '', vuln['cve_id'], vuln['description'], vuln['severity']['level']])
            logger.debug(f"CSV report saved to {csv_file}")
        except Exception as e:
            logger.error(f"Error saving report: {str(e)}")