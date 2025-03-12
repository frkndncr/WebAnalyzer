#!/usr/bin/env python3
"""
Optimize CloudflareBypass - Simple, effective real IP finder behind Cloudflare
By: HittSys
"""

import requests
import socket
import concurrent.futures
import time
import ipaddress
import re
import sys
import argparse
import random
import urllib3
from urllib.parse import urlparse

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Cloudflare IP ranges
CLOUDFLARE_RANGES = [
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
    '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
    '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
    '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22'
]

# IP history sources
IP_HISTORY_SOURCES = [
    {'url': 'https://viewdns.info/iphistory/?domain={domain}', 'name': 'ViewDNS'},
    {'url': 'https://securitytrails.com/domain/{domain}/history/a', 'name': 'SecurityTrails'},
    {'url': 'https://who.is/whois/{domain}', 'name': 'WhoIs'}, 
]

# Headers that might leak IPs
HEADERS_TO_CHECK = [
    'X-Forwarded-For', 'X-Real-IP', 'X-Origin-IP', 'CF-Connecting-IP', 
    'X-Server-IP', 'Server-IP', 'X-Backend-Server', 'X-Origin-Server'
]

# Known historical IPs database (add your own findings here)
KNOWN_IP_DATABASE = {
    'c4softwarestudio.com': [
        {'ip': '89.116.147.73', 'description': 'Hetzner hosted IP'},
        {'ip': '46.16.74.86', 'description': 'Alternative IP'},
        {'ip': '151.135.76.206', 'description': 'Microsoft Azure IP'}
    ]
}

class CloudflareBypass:
    def __init__(self, target, timeout=8, max_workers=10, verbose=False, quiet=False):
        self.target = target
        self.timeout = timeout
        self.max_workers = max_workers
        self.verbose = verbose
        self.quiet = quiet
        
        # IP regex
        self.ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
        
        # Setup target
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            self.domain = parsed.netloc
            self.target_url = target
        else:
            self.domain = target
            self.target_url = f"https://{target}"
        
        # Results
        self.found_ips = []
        self.cf_networks = self._parse_cf_ranges()
        
        # Random UA for each request
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36',
            'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
        ]
    
    def _parse_cf_ranges(self):
        """Parse Cloudflare IP ranges."""
        cf_networks = []
        for ip_range in CLOUDFLARE_RANGES:
            try:
                cf_networks.append(ipaddress.ip_network(ip_range))
            except:
                pass
        return cf_networks
    
    def log(self, message, level="info", always_show=False):
        """Log messages with different levels based on verbosity."""
        if self.quiet and not always_show:
            return
            
        if not self.verbose and level in ["info", "warning"] and not always_show:
            return
            
        level_prefixes = {
            "info": "[*]",
            "success": "[+]",
            "warning": "[!]",
            "error": "[-]"
        }
        
        prefix = level_prefixes.get(level, "[*]")
        print(f"{prefix} {message}")
    
    def is_cloudflare_ip(self, ip):
        """Check if an IP belongs to Cloudflare."""
        try:
            addr = ipaddress.ip_address(ip)
            for network in self.cf_networks:
                if addr in network:
                    return True
            return False
        except:
            return False
    
    def is_valid_ip(self, ip):
        """Check if a string is a valid IP address."""
        try:
            ipaddress.ip_address(ip)
            return True
        except:
            return False
    
    def is_private_ip(self, ip):
        """Check if an IP is private."""
        try:
            return ipaddress.ip_address(ip).is_private
        except:
            return False
    
    def check_direct_connection(self):
        """Check direct connection to the domain."""
        try:
            ip = socket.gethostbyname(self.domain)
            self.log(f"Domain resolves to IP: {ip}")
            
            # Check if it's a Cloudflare IP
            if self.is_cloudflare_ip(ip):
                self.log(f"IP {ip} belongs to Cloudflare - protection confirmed")
                return True
            else:
                self.log(f"IP {ip} is not a Cloudflare IP - direct access possible", "success", True)
                self.found_ips.append({
                    'ip': ip,
                    'source': 'direct_dns',
                    'confidence': 'Very High'
                })
                return False
        except Exception as e:
            self.log(f"Error resolving domain: {str(e)}", "error")
            return None
    
    def check_known_ips(self):
        """Check database of known IPs."""
        if self.domain in KNOWN_IP_DATABASE:
            self.log(f"Checking known IPs for {self.domain}")
            
            for ip_data in KNOWN_IP_DATABASE[self.domain]:
                ip = ip_data['ip']
                
                try:
                    if self.is_valid_ip(ip) and not self.is_cloudflare_ip(ip) and not self.is_private_ip(ip):
                        # Try socket connection
                        try:
                            socket_test = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            socket_test.settimeout(3)
                            result = socket_test.connect_ex((ip, 80))
                            socket_test.close()
                            
                            if result == 0:
                                # Try HTTP request
                                try:
                                    headers = {
                                        'User-Agent': random.choice(self.user_agents),
                                        'Host': self.domain
                                    }
                                    
                                    response = requests.get(
                                        f"http://{ip}/", 
                                        headers=headers,
                                        timeout=3,
                                        verify=False
                                    )
                                    
                                    if response.status_code == 200:
                                        confidence = 'High'
                                        
                                        # Check if content contains domain name
                                        if self.domain.lower() in response.text.lower():
                                            confidence = 'Very High'
                                            self.log(f"Confirmed active IP: {ip} ✓", "success", True)
                                        else:
                                            self.log(f"Found active IP: {ip}", "success", True)
                                        
                                        self.found_ips.append({
                                            'ip': ip,
                                            'source': 'database',
                                            'description': ip_data.get('description', ''),
                                            'confidence': confidence
                                        })
                                except:
                                    # Just socket connection works
                                    self.found_ips.append({
                                        'ip': ip,
                                        'source': 'database',
                                        'description': ip_data.get('description', ''),
                                        'confidence': 'Medium'
                                    })
                            else:
                                self.log(f"IP {ip} is not responsive", "info")
                        except:
                            pass
                except:
                    pass
    
    def check_common_subdomains(self):
        """Check common subdomains for direct IP access."""
        common_subdomains = [
            'direct', 'origin', 'api', 'mail', 'cpanel', 'server'
        ]
        
        # Domain-specific subdomains
        domain_parts = self.domain.split('.')
        name_part = domain_parts[0] if len(domain_parts) > 0 else ''
        
        if name_part:
            domain_specific = [
                f"origin-{name_part}", f"{name_part}-origin", 
                f"direct-{name_part}", f"{name_part}-direct"
            ]
            common_subdomains.extend(domain_specific)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {}
            for subdomain in common_subdomains:
                full_domain = f"{subdomain}.{self.domain}"
                futures[executor.submit(self._resolve_domain, full_domain)] = full_domain
            
            for future in concurrent.futures.as_completed(futures):
                subdomain = futures[future]
                try:
                    result = future.result()
                    if result:
                        ip, status = result
                        
                        if not self.is_cloudflare_ip(ip) and not self.is_private_ip(ip):
                            self.log(f"Found non-Cloudflare IP {ip} for subdomain {subdomain}", "success", True)
                            
                            confidence = 'Medium'
                            if status == 200:
                                confidence = 'High'
                            
                            self.found_ips.append({
                                'ip': ip,
                                'source': f'subdomain_{subdomain}',
                                'confidence': confidence
                            })
                except:
                    pass
    
    def _resolve_domain(self, domain):
        """Resolve a domain to its IP and check connectivity."""
        try:
            ip = socket.gethostbyname(domain)
            
            # Try HTTP connection to verify site is active
            try:
                response = requests.get(
                    f"http://{domain}/", 
                    headers={'User-Agent': random.choice(self.user_agents)},
                    timeout=3,
                    verify=False
                )
                return ip, response.status_code
            except:
                # If HTTP fails, just return the IP
                return ip, "failed_http"
        except:
            return None
    
    def check_ip_history(self):
        """Quick IP history check focused on finding real IPs."""
        self.log("Checking IP history")
        
        for source in IP_HISTORY_SOURCES:
            try:
                url = source['url'].format(domain=self.domain)
                
                headers = {
                    'User-Agent': random.choice(self.user_agents),
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Referer': 'https://www.google.com/'
                }
                
                response = requests.get(
                    url, 
                    headers=headers,
                    timeout=self.timeout,
                    verify=False
                )
                
                # Extract IP addresses from response
                if response.status_code == 200:
                    ips = self.ip_pattern.findall(response.text)
                    
                    # Filter unique IPs that aren't Cloudflare
                    unique_ips = set()
                    for ip in ips:
                        if (self.is_valid_ip(ip) and 
                            not self.is_cloudflare_ip(ip) and 
                            not self.is_private_ip(ip) and
                            ip not in unique_ips):
                            
                            unique_ips.add(ip)
                    
                    # Add to results
                    for ip in unique_ips:
                        self.log(f"Found historical IP {ip} from {source['name']}", "success", True)
                        self.found_ips.append({
                            'ip': ip,
                            'source': f'history_{source["name"]}',
                            'confidence': 'Medium'
                        })
                
                # Small delay
                time.sleep(1)
                
            except Exception as e:
                self.log(f"Error with {source['name']}: {str(e)}", "error")
    
    def quick_header_check(self):
        """Quick check for IP leaks in headers."""
        try:
            headers = {
                'User-Agent': random.choice(self.user_agents),
                'Accept': '*/*'
            }
            
            response = requests.get(
                self.target_url,
                headers=headers,
                timeout=self.timeout,
                verify=False
            )
            
            # Check headers for IP leaks
            for header in HEADERS_TO_CHECK:
                if header in response.headers:
                    ips = self.ip_pattern.findall(response.headers[header])
                    for ip in ips:
                        if (self.is_valid_ip(ip) and 
                            not self.is_cloudflare_ip(ip) and 
                            not self.is_private_ip(ip)):
                            
                            self.log(f"Found IP {ip} in header {header}", "success", True)
                            self.found_ips.append({
                                'ip': ip,
                                'source': f'header_{header}',
                                'confidence': 'High'
                            })
        except:
            pass
    
    def verify_ip(self, ip):
        """Verify an IP address with a simple connection test."""
        try:
            # Try a socket connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((ip, 80))
            sock.close()
            
            if result == 0:
                self.log(f"Verified: {ip} is responding ✓", "success")
                return "active"
            else:
                self.log(f"Warning: {ip} is not responding ✗", "warning")
                return "inactive"
        except:
            return "error"
    
    def verify_top_results(self, results, count=5):
        """Verify top IP results."""
        verified_results = []
        
        # Only verify up to 'count' results
        for ip_info in results[:count]:
            ip = ip_info['ip']
            status = self.verify_ip(ip)
            ip_info['status'] = status
            verified_results.append(ip_info)
        
        # Add remaining results as unverified
        for ip_info in results[count:]:
            ip_info['status'] = "unverified"
            verified_results.append(ip_info)
        
        return verified_results
    
    def run(self):
        """Run the bypass process to find real IPs."""
        start_time = time.time()
        
        self.log(f"Scanning {self.domain} for real IPs behind Cloudflare", "info", True)
        
        # Check for direct resolution
        is_protected = self.check_direct_connection()
        
        if is_protected != False:  # If protected or unknown
            # Check database of known IPs
            self.check_known_ips()
            
            # Run checks in parallel
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
                history_future = executor.submit(self.check_ip_history)
                subdomain_future = executor.submit(self.check_common_subdomains)
                header_future = executor.submit(self.quick_header_check)
                
                # Wait for all to complete
                for future in [history_future, subdomain_future, header_future]:
                    future.result()
        
        # Remove duplicates and sort by confidence
        unique_ips = {}
        confidence_levels = {
            'Very High': 4,
            'High': 3,
            'Medium': 2,
            'Low': 1
        }
        
        # Keep highest confidence entry for each IP
        for ip_info in self.found_ips:
            ip = ip_info['ip']
            confidence = ip_info.get('confidence', 'Low')
            conf_level = confidence_levels.get(confidence, 0)
            
            if ip not in unique_ips or conf_level > confidence_levels.get(unique_ips[ip].get('confidence', 'Low'), 0):
                unique_ips[ip] = ip_info
        
        # Convert back to list and sort
        results = list(unique_ips.values())
        results.sort(key=lambda x: confidence_levels.get(x.get('confidence', 'Low'), 0), reverse=True)
        
        # Verify top results
        verified_results = self.verify_top_results(results)
        
        # Calculate scan time
        scan_time = time.time() - start_time
        
        return {
            'target': self.domain,
            'cloudflare_protected': is_protected,
            'real_ips': verified_results,
            'scan_time': scan_time
        }


def main():
    parser = argparse.ArgumentParser(description='CloudflareBypass - Find real IPs behind Cloudflare')
    parser.add_argument('target', help='Target domain or URL')
    parser.add_argument('-t', '--timeout', type=int, default=8, help='Request timeout in seconds (default: 8)')
    parser.add_argument('-w', '--workers', type=int, default=10, help='Maximum concurrent workers (default: 10)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show detailed scan progress')
    parser.add_argument('-q', '--quiet', action='store_true', help='Only show results, no progress info')
    
    args = parser.parse_args()
    
    if not args.quiet:
        print("\n=== CloudflareBypass Tool ===")
        print(f"Target: {args.target}")
        print("=" * 30 + "\n")
    
    bypass = CloudflareBypass(
        target=args.target,
        timeout=args.timeout,
        max_workers=args.workers,
        verbose=args.verbose,
        quiet=args.quiet
    )
    
    try:
        results = bypass.run()
        
        if not args.quiet:
            print("\n" + "=" * 30)
            print(f"Results for {results['target']}:")
            print(f"Scan time: {results['scan_time']:.1f} seconds")
            print(f"Cloudflare protection: {'Yes' if results['cloudflare_protected'] else 'No'}")
            print("=" * 30)
        
        if results['real_ips']:
            print("\nReal IPs:")
            for i, ip_info in enumerate(results['real_ips'], 1):
                status = "✓" if ip_info.get('status') == "active" else "✗" if ip_info.get('status') == "inactive" else "?"
                desc = f" - {ip_info['description']}" if 'description' in ip_info else ""
                
                print(f"{i}. {ip_info['ip']} [{status}] ({ip_info.get('confidence', 'Unknown')}){desc}")
            
            print("\nTest commands:")
            
            # Only show active IPs in test commands
            active_ips = [ip for ip in results['real_ips'] if ip.get('status') == "active"]
            
            if active_ips:
                for ip_info in active_ips[:3]:  # Show top 3 active IPs
                    print(f"curl -H 'Host: {results['target']}' http://{ip_info['ip']}/")
            else:
                # If no active IPs, show top 3 from all results
                for ip_info in results['real_ips'][:3]:
                    print(f"curl -H 'Host: {results['target']}' http://{ip_info['ip']}/")
        else:
            print("\nNo real IPs found. The target has strong Cloudflare protection.")
        
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()