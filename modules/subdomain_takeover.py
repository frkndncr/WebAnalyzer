# modules/subdomain_takeover.py
import requests
import dns.resolver
import socket
import logging
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
import ssl
import whois
from datetime import datetime

class SubdomainTakeover:
    def __init__(self, domain, logger=None, output_dir=None, timeout=10, max_workers=20, verify_ssl=False):
        """
        Initialize the Subdomain Takeover scanner
        
        Args:
            domain (str): The main domain to scan
            logger (logging.Logger, optional): Logger instance
            output_dir (str, optional): Directory to save results
            timeout (int, optional): Request timeout in seconds
            max_workers (int, optional): Maximum number of concurrent workers
            verify_ssl (bool, optional): Whether to verify SSL certificates
        """
        self.domain = domain
        self.logger = logger or logging.getLogger(__name__)
        self.timeout = timeout
        self.max_workers = max_workers
        self.verify_ssl = verify_ssl
        self.output_dir = output_dir or os.path.join(os.getcwd(), "logs", domain)
        
        # Create output directory if it doesn't exist
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Comprehensive database of vulnerable services with fingerprints
        # Format: 'Service': ['CNAME pattern', 'Error message pattern', 'Additional indicators']
        self.vulnerable_services = {
            'AWS S3 Bucket': ['s3.amazonaws.com', 'NoSuchBucket', 'The specified bucket does not exist'],
            'AWS CloudFront': ['cloudfront.net', 'The request could not be satisfied', 'Bad request'],
            'GitHub Pages': ['github.io', 'There isn\'t a GitHub Pages site here', '404: Not Found'],
            'Heroku': ['herokuapp.com', 'No such app', 'heroku'],
            'Vercel': ['vercel.app', '404: Not Found', 'The deployment could not be found'],
            'Netlify': ['netlify.app', 'Not found', 'netlify'],
            'Azure App Service': ['azurewebsites.net', 'Microsoft Azure App Service', '404 Not Found'],
            'Azure TrafficManager': ['trafficmanager.net', 'Page not found', 'Not found'],
            'Zendesk': ['zendesk.com', 'Help Center Closed', 'Zendesk'],
            'Shopify': ['myshopify.com', 'Sorry, this shop is currently unavailable', 'Shopify'],
            'Fastly': ['fastly.net', 'Fastly error: unknown domain', 'Fastly'],
            'Pantheon': ['pantheonsite.io', 'The gods are wise', '404 Not Found'],
            'Tumblr': ['tumblr.com', 'There\'s nothing here', 'Tumblr'],
            'WordPress': ['wordpress.com', 'Do you want to register', 'WordPress'],
            'Acquia': ['acquia-sites.com', 'No site found', 'The requested URL was not found'],
            'Ghost': ['ghost.io', 'The thing you were looking for is no longer here', 'Ghost'],
            'Cargo': ['cargocollective.com', '404 Not Found', 'Cargo'],
            'Webflow': ['webflow.io', 'The page you are looking for doesn\'t exist', 'Webflow'],
            'Surge.sh': ['surge.sh', '404 Not Found', 'Surge'],
            'Squarespace': ['squarespace.com', 'Website Expired', 'Squarespace'],
            'Fly.io': ['fly.dev', '404 Not Found', 'Fly.io'],
            'Brightcove': ['bcvp0rtal.com', 'Brightcove Error', 'Brightcove'],
            'Unbounce': ['unbounce.com', 'The requested URL was not found', 'Unbounce'],
            'Strikingly': ['strikinglydns.com', '404 Not Found', 'Strikingly'],
            'UptimeRobot': ['stats.uptimerobot.com', '404 Not Found', 'UptimeRobot'],
            'UserVoice': ['uservoice.com', 'This UserVoice is currently being set up', 'UserVoice'],
            'Pingdom': ['stats.pingdom.com', '404 Not Found', 'Pingdom'],
            'Amazon CloudFront': ['cloudfront.net', 'The request could not be satisfied', 'CloudFront'],
            'Desk': ['desk.com', 'Please try again', 'Desk'],
            'Tilda': ['tilda.ws', '404 Not Found', 'Tilda'],
            'Helpjuice': ['helpjuice.com', '404 Not Found', 'Helpjuice'],
            'HelpScout': ['helpscoutdocs.com', 'No settings were found', 'HelpScout'],
            'Campaign Monitor': ['createsend.com', '404 Not Found', 'Campaign Monitor'],
            'Digital Ocean': ['digitalocean.app', '404 Not Found', 'Digital Ocean'],
            'AWS Elastic Beanstalk': ['elasticbeanstalk.com', '404 Not Found', 'Elastic Beanstalk'],
            'Readthedocs': ['readthedocs.io', 'Not Found', 'readthedocs'],
            'BitBucket': ['bitbucket.io', '404 Not Found', 'BitBucket'],
            'Intercom': ['custom.intercom.help', '404 Not Found', 'Intercom'],
            'Firebase': ['firebaseapp.com', '404 Not Found', 'Firebase'],
            'Kinsta': ['kinsta.cloud', '404 Not Found', 'Kinsta'],
            'LaunchRock': ['launchrock.com', '404 Not Found', 'LaunchRock'],
            'GetResponse': ['gr8.com', '404 Not Found', 'GetResponse'],
            'Aftership': ['aftership.app', '404 Not Found', 'Aftership']
        }
        
        # HTTP headers for requests
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }
        
    def get_domain_registration_info(self, domain):
        """
        Get domain registration information to check for expired domains
        
        Args:
            domain (str): Domain to check
            
        Returns:
            dict: Domain registration information or None if error
        """
        try:
            w = whois.whois(domain)
            result = {
                "registrar": w.registrar,
                "creation_date": None,
                "expiration_date": None,
                "updated_date": None,
                "is_registered": True if w.registrar else False
            }
            
            # Handle dates properly
            if w.creation_date:
                if isinstance(w.creation_date, list):
                    result["creation_date"] = w.creation_date[0].strftime("%Y-%m-%d") if isinstance(w.creation_date[0], datetime) else str(w.creation_date[0])
                else:
                    result["creation_date"] = w.creation_date.strftime("%Y-%m-%d") if isinstance(w.creation_date, datetime) else str(w.creation_date)
                    
            if w.expiration_date:
                if isinstance(w.expiration_date, list):
                    result["expiration_date"] = w.expiration_date[0].strftime("%Y-%m-%d") if isinstance(w.expiration_date[0], datetime) else str(w.expiration_date[0])
                else:
                    result["expiration_date"] = w.expiration_date.strftime("%Y-%m-%d") if isinstance(w.expiration_date, datetime) else str(w.expiration_date)
            
            if w.updated_date:
                if isinstance(w.updated_date, list):
                    result["updated_date"] = w.updated_date[0].strftime("%Y-%m-%d") if isinstance(w.updated_date[0], datetime) else str(w.updated_date[0])
                else:
                    result["updated_date"] = w.updated_date.strftime("%Y-%m-%d") if isinstance(w.updated_date, datetime) else str(w.updated_date)
            
            return result
        except Exception as e:
            self.logger.debug(f"Error getting WHOIS for {domain}: {str(e)}")
            return None
        
    def check_dns_configuration(self, subdomain):
        """
        Check DNS configuration for a subdomain, including A, AAAA, CNAME records
        
        Args:
            subdomain (str): Subdomain to check
            
        Returns:
            dict: DNS configuration information
        """
        dns_info = {
            "a_records": [],
            "aaaa_records": [],
            "cname_records": [],
            "mx_records": [],
            "txt_records": [],
            "ns_records": [],
            "has_valid_dns": False
        }
        
        # Check A records
        try:
            answers = dns.resolver.resolve(subdomain, 'A')
            dns_info["a_records"] = [str(answer) for answer in answers]
            dns_info["has_valid_dns"] = True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers) as e:
            self.logger.debug(f"No A records for {subdomain}: {str(e)}")
        
        # Check AAAA records
        try:
            answers = dns.resolver.resolve(subdomain, 'AAAA')
            dns_info["aaaa_records"] = [str(answer) for answer in answers]
            dns_info["has_valid_dns"] = True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers) as e:
            self.logger.debug(f"No AAAA records for {subdomain}: {str(e)}")
        
        # Check CNAME records
        try:
            answers = dns.resolver.resolve(subdomain, 'CNAME')
            dns_info["cname_records"] = [str(answer.target).rstrip('.') for answer in answers]
            dns_info["has_valid_dns"] = True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers) as e:
            self.logger.debug(f"No CNAME records for {subdomain}: {str(e)}")
        
        # Check MX records
        try:
            answers = dns.resolver.resolve(subdomain, 'MX')
            dns_info["mx_records"] = [str(answer.exchange).rstrip('.') for answer in answers]
            dns_info["has_valid_dns"] = True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers) as e:
            self.logger.debug(f"No MX records for {subdomain}: {str(e)}")
        
        # Check TXT records
        try:
            answers = dns.resolver.resolve(subdomain, 'TXT')
            dns_info["txt_records"] = [str(answer).strip('"') for answer in answers]
            dns_info["has_valid_dns"] = True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers) as e:
            self.logger.debug(f"No TXT records for {subdomain}: {str(e)}")
            
        # Check NS records
        try:
            answers = dns.resolver.resolve(subdomain, 'NS')
            dns_info["ns_records"] = [str(answer).rstrip('.') for answer in answers]
            dns_info["has_valid_dns"] = True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers) as e:
            self.logger.debug(f"No NS records for {subdomain}: {str(e)}")
        
        return dns_info
        
    def check_website_availability(self, subdomain):
        """
        Check if a website is available via HTTP/HTTPS
        
        Args:
            subdomain (str): Subdomain to check
            
        Returns:
            dict: Website availability information
        """
        result = {
            "http_status": None,
            "https_status": None,
            "response_time": None,
            "http_response": None,
            "https_response": None,
            "http_headers": None,
            "https_headers": None,
            "ssl_info": None,
            "is_accessible": False,
            "redirect_chain": []
        }
        
        # Try HTTP
        try:
            start_time = time.time()
            http_response = requests.get(
                f"http://{subdomain}", 
                headers=self.headers, 
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=True
            )
            response_time = time.time() - start_time
            
            result["http_status"] = http_response.status_code
            result["response_time"] = response_time
            result["http_headers"] = dict(http_response.headers)
            result["http_response"] = http_response.text[:500]  # Store first 500 chars
            
            # Track redirect chain
            if http_response.history:
                result["redirect_chain"] = [{"url": r.url, "status_code": r.status_code} for r in http_response.history]
                result["redirect_chain"].append({"url": http_response.url, "status_code": http_response.status_code})
            
            if 200 <= http_response.status_code < 400:
                result["is_accessible"] = True
        except requests.RequestException as e:
            self.logger.debug(f"HTTP error for {subdomain}: {str(e)}")
            result["http_status"] = "Error"
        
        # Try HTTPS
        try:
            https_response = requests.get(
                f"https://{subdomain}", 
                headers=self.headers, 
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=True
            )
            
            result["https_status"] = https_response.status_code
            result["https_headers"] = dict(https_response.headers)
            result["https_response"] = https_response.text[:500]  # Store first 500 chars
            
            # Track redirect chain if not already tracked
            if https_response.history and not result["redirect_chain"]:
                result["redirect_chain"] = [{"url": r.url, "status_code": r.status_code} for r in https_response.history]
                result["redirect_chain"].append({"url": https_response.url, "status_code": https_response.status_code})
            
            if 200 <= https_response.status_code < 400:
                result["is_accessible"] = True
                
            # Get SSL information
            try:
                hostname = subdomain
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((hostname, 443), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        result["ssl_info"] = {
                            "issuer": dict(x[0] for x in cert['issuer']),
                            "subject": dict(x[0] for x in cert['subject']),
                            "version": cert['version'],
                            "notBefore": cert['notBefore'],
                            "notAfter": cert['notAfter']
                        }
                        
                        # Check for SAN (Subject Alternative Names)
                        if 'subjectAltName' in cert:
                            result["ssl_info"]["subjectAltName"] = cert['subjectAltName']
            except Exception as e:
                self.logger.debug(f"SSL info error for {subdomain}: {str(e)}")
        except requests.RequestException as e:
            self.logger.debug(f"HTTPS error for {subdomain}: {str(e)}")
            result["https_status"] = "Error"
        
        return result
    
    def check_for_misconfigurations(self, dns_info, website_info):
        """
        Look for additional misconfigurations that could indicate takeover vulnerability
        
        Args:
            dns_info (dict): DNS configuration information
            website_info (dict): Website availability information
            
        Returns:
            dict: Misconfiguration information if found, None otherwise
        """
        # Check for dangling records (CNAME that doesn't resolve)
        if dns_info.get("cname_records") and not dns_info.get("a_records") and not website_info.get("is_accessible"):
            cname = dns_info["cname_records"][0]
            try:
                socket.gethostbyname(cname)
            except socket.gaierror:
                return {
                    "type": "Dangling CNAME",
                    "details": f"CNAME record points to {cname} which does not resolve to an IP"
                }
        
        # Check for NS delegation to non-existent nameserver
        if dns_info.get("ns_records"):
            for ns in dns_info["ns_records"]:
                try:
                    socket.gethostbyname(ns)
                except socket.gaierror:
                    return {
                        "type": "Dangling NS",
                        "details": f"NS record points to {ns} which does not resolve to an IP"
                    }
        
        # Check for missing SPF but has MX records
        has_spf = False
        for txt in dns_info.get("txt_records", []):
            if "v=spf1" in txt:
                has_spf = True
                break
        
        if dns_info.get("mx_records") and not has_spf:
            return {
                "type": "Missing SPF",
                "details": "Domain has MX records but no SPF record, potential email security issue"
            }
        
        # Check for suspicious redirects
        if website_info.get("redirect_chain"):
            for redirect in website_info["redirect_chain"]:
                if any(service in redirect["url"] for service in ["s3.amazonaws.com", "github.io", "herokuapp.com"]):
                    return {
                        "type": "Suspicious Redirect",
                        "details": f"Redirects to potentially vulnerable service: {redirect['url']}"
                    }
        
        return None
        
    def check_takeover_vulnerability(self, subdomain):
        """
        Check a subdomain for takeover vulnerabilities
        
        Args:
            subdomain (str): The subdomain to check
            
        Returns:
            dict: Vulnerability information or None if no vulnerability found
        """
        self.logger.info(f"Checking takeover vulnerability for {subdomain}")
        try:
            # Check DNS configuration
            dns_info = self.check_dns_configuration(subdomain)
            
            # Check website availability
            website_info = self.check_website_availability(subdomain)
            
            # Check domain registration
            whois_info = self.get_domain_registration_info(subdomain)
            
            # Check for additional misconfigurations
            misconfiguration = self.check_for_misconfigurations(dns_info, website_info)
            
            # Initialize vulnerability detection
            vulnerability_detected = False
            vulnerability_details = {}
            
            # Case 1: CNAME points to a service, but content matches error fingerprint
            if dns_info["cname_records"]:
                for cname in dns_info["cname_records"]:
                    for service, fingerprints in self.vulnerable_services.items():
                        cname_pattern = fingerprints[0]
                        error_pattern = fingerprints[1]
                        additional_pattern = fingerprints[2] if len(fingerprints) > 2 else None
                        
                        if cname_pattern.lower() in cname.lower():
                            # Check if website content contains error message
                            http_content = website_info.get("http_response", "")
                            https_content = website_info.get("https_response", "")
                            content = http_content or https_content or ""
                            
                            if error_pattern.lower() in content.lower() or (additional_pattern and additional_pattern.lower() in content.lower()):
                                vulnerability_detected = True
                                vulnerability_details = {
                                    "type": "CNAME Error Pattern",
                                    "service": service,
                                    "cname": cname,
                                    "error_pattern": error_pattern,
                                    "confidence": "High",
                                    "description": f"The subdomain has a CNAME record pointing to {service} ({cname}) and returns an error message indicating the resource doesn't exist."
                                }
                                break
                    
                    if vulnerability_detected:
                        break
            
            # Case 2: CNAME exists but doesn't resolve (dangling CNAME)
            if not vulnerability_detected and dns_info["cname_records"] and not website_info["is_accessible"] and not dns_info["a_records"]:
                for cname in dns_info["cname_records"]:
                    try:
                        # Try to resolve the CNAME target
                        socket.gethostbyname(cname)
                    except socket.gaierror:
                        # CNAME target doesn't resolve - potential dangling CNAME
                        vulnerability_detected = True
                        vulnerability_details = {
                            "type": "Dangling CNAME",
                            "cname": cname,
                            "confidence": "Medium",
                            "description": f"The subdomain has a CNAME record pointing to {cname} which doesn't resolve to an IP address."
                        }
                        
                        # Try to identify the service
                        for service, fingerprints in self.vulnerable_services.items():
                            cname_pattern = fingerprints[0]
                            if cname_pattern.lower() in cname.lower():
                                vulnerability_details["service"] = service
                                vulnerability_details["confidence"] = "High"
                                vulnerability_details["description"] = f"The subdomain has a CNAME record pointing to {service} ({cname}) which doesn't resolve to an IP address."
                                break
                        break
            
            # Case 3: DNS records exist but website returns specific error codes
            if not vulnerability_detected and dns_info["has_valid_dns"] and website_info.get("http_status") in [404, 500, 502, 503]:
                # Check if any common third-party hosting is detected
                if any(provider in str(dns_info) for provider in ['aws', 'amazon', 'azure', 'heroku', 'github', 'vercel']):
                    vulnerability_detected = True
                    vulnerability_details = {
                        "type": "Third-Party Service Error",
                        "http_status": website_info.get("http_status"),
                        "confidence": "Medium",
                        "description": f"The subdomain has valid DNS records pointing to a third-party service, but returns a {website_info.get('http_status')} error code."
                    }
                else:
                    # This is a lower confidence indicator
                    vulnerability_detected = True
                    vulnerability_details = {
                        "type": "DNS Record with Error Response",
                        "http_status": website_info.get("http_status"),
                        "confidence": "Low",
                        "description": f"The subdomain has valid DNS records but returns a {website_info.get('http_status')} error code."
                    }
            
            # Case 4: Additional misconfigurations
            if not vulnerability_detected and misconfiguration:
                vulnerability_detected = True
                vulnerability_details = {
                    "type": misconfiguration["type"],
                    "confidence": "Medium" if misconfiguration["type"] in ["Dangling CNAME", "Dangling NS", "Suspicious Redirect"] else "Low",
                    "description": misconfiguration["details"]
                }
            
            # If a vulnerability was detected, build the complete result
            if vulnerability_detected:
                result = {
                    "subdomain": subdomain,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "dns_info": dns_info,
                    "website_info": website_info,
                    "whois_info": whois_info,
                    "vulnerable": True,
                    "service": vulnerability_details.get("service", "Unknown"),
                    "vulnerability_type": vulnerability_details.get("type", "Unknown"),
                    "confidence": vulnerability_details.get("confidence", "Low"),
                    "cname": vulnerability_details.get("cname", None),
                    "description": vulnerability_details.get("description", None),
                    "exploitation_difficulty": self.assess_exploitation_difficulty(vulnerability_details, dns_info, website_info),
                    "mitigation": self.suggest_mitigation(vulnerability_details)
                }
                
                # Save vulnerability data as JSON
                output_file = os.path.join(self.output_dir, f"takeover_{subdomain.replace('.', '_')}.json")
                with open(output_file, "w") as f:
                    json.dump(result, f, indent=4)
                
                self.logger.warning(f"Potential {result['confidence']} confidence takeover vulnerability found in {subdomain} ({result['service']})")
                return result
            
            return None
        except Exception as e:
            self.logger.error(f"Error checking {subdomain}: {str(e)}")
            return None
    
    def assess_exploitation_difficulty(self, vulnerability_details, dns_info, website_info):
        """
        Assess the difficulty of exploiting the vulnerability
        
        Args:
            vulnerability_details (dict): Details of the vulnerability
            dns_info (dict): DNS configuration information
            website_info (dict): Website availability information
            
        Returns:
            str: Difficulty assessment (Easy, Medium, Hard)
        """
        vuln_type = vulnerability_details.get("type", "")
        service = vulnerability_details.get("service", "Unknown")
        
        if vuln_type == "CNAME Error Pattern":
            # Services that are typically easy to claim
            easy_services = ["GitHub Pages", "Heroku", "Vercel", "Netlify", "Surge.sh"]
            if service in easy_services:
                return "Easy"
            
            # Services that require account ownership or validation
            medium_services = ["AWS S3 Bucket", "Firebase", "Ghost", "WordPress"]
            if service in medium_services:
                return "Medium"
                
            return "Hard"
            
        elif vuln_type == "Dangling CNAME":
            # If the CNAME points to a custom domain on a third-party service
            if service != "Unknown":
                return "Medium"
            return "Hard"
            
        elif "DNS Record with Error" in vuln_type:
            return "Hard"
            
        elif "Dangling NS" in vuln_type:
            return "Medium"
            
        elif "Suspicious Redirect" in vuln_type:
            return "Medium"
            
        return "Medium"
    
    def suggest_mitigation(self, vulnerability_details):
        """
        Suggest mitigation strategies based on the vulnerability
        
        Args:
            vulnerability_details (dict): Details of the vulnerability
            
        Returns:
            str: Mitigation suggestion
        """
        vuln_type = vulnerability_details.get("type", "")
        service = vulnerability_details.get("service", "Unknown")
        
        if vuln_type == "CNAME Error Pattern":
            return f"Remove the CNAME record or reclaim the resource on {service}. Ensure you've properly set up the service before pointing DNS records to it."
            
        elif vuln_type == "Dangling CNAME":
            return "Remove the CNAME record that points to a non-existent endpoint. If the service is still needed, recreate the resource at the target service."
            
        elif "DNS Record with Error" in vuln_type:
            return "Verify that the resource exists on the target service. If the service is no longer used, remove the DNS record."
            
        elif "Dangling NS" in vuln_type:
            return "Update your NS records to point to valid nameservers. Remove delegations to nameservers that no longer exist."
            
        elif "Suspicious Redirect" in vuln_type:
            return "Check your redirect chain and ensure it doesn't point to services you don't control. Update your configuration to remove unintended redirects."
            
        elif "Missing SPF" in vuln_type:
            return "Add an SPF record to protect against email spoofing. For example: 'v=spf1 mx -all'"
            
        return "Review the DNS configuration and remove any references to services or resources that are no longer in use."
    
    def get_vulnerable_services_info(self):
        """
        Get information about the vulnerable services being checked
        
        Returns:
            dict: Information about vulnerable services
        """
        return {
            "services_count": len(self.vulnerable_services),
            "services": list(self.vulnerable_services.keys())
        }
    
    def scan(self, subdomains):
        """
        Scan a list of subdomains for takeover vulnerabilities
        
        Args:
            subdomains (list): List of subdomains to check
            
        Returns:
            dict: Scan results
        """
        self.logger.info(f"Starting subdomain takeover scan for {len(subdomains)} subdomains of {self.domain}")
        
        results = []
        start_time = time.time()
        
        # Create results directory
        os.makedirs(self.output_dir, exist_ok=True)
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_subdomain = {executor.submit(self.check_takeover_vulnerability, subdomain): subdomain for subdomain in subdomains}
            
            for future in future_to_subdomain:
                result = future.result()
                if result:
                    results.append(result)
        
        # Sort results by confidence level
        confidence_order = {"High": 0, "Medium": 1, "Low": 2}
        results.sort(key=lambda x: confidence_order.get(x.get("confidence", "Low"), 3))
        
        # Calculate statistics
        scan_time = time.time() - start_time
        high_confidence = sum(1 for r in results if r.get("confidence") == "High")
        medium_confidence = sum(1 for r in results if r.get("confidence") == "Medium")
        low_confidence = sum(1 for r in results if r.get("confidence") == "Low")
        
        # Generate summary JSON
        summary = {
            "scan_info": {
                "domain": self.domain,
                "subdomains_scanned": len(subdomains),
                "vulnerable_subdomains": len(results),
                "scan_time_seconds": round(scan_time, 2),
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "services_checked": len(self.vulnerable_services)
            },
        "statistics": {
                        "vulnerable_subdomains_count": len(results),
                        "high_confidence": high_confidence,
                        "medium_confidence": medium_confidence,
                        "low_confidence": low_confidence,
                        "by_vulnerability_type": {},
                        "by_service": {}
                    },
                    "vulnerable_subdomains": results
                }
                
        # Count by vulnerability type and service
        vuln_types = {}
        services = {}
        
        for result in results:
            vuln_type = result.get("vulnerability_type", "Unknown")
            service = result.get("service", "Unknown")
            
            if vuln_type in vuln_types:
                vuln_types[vuln_type] += 1
            else:
                vuln_types[vuln_type] = 1
                
            if service in services:
                services[service] += 1
            else:
                services[service] = 1
        
        summary["statistics"]["by_vulnerability_type"] = vuln_types
        summary["statistics"]["by_service"] = services
        
        # Save summary to file
        summary_file = os.path.join(self.output_dir, f"takeover_summary_{self.domain}.json")
        with open(summary_file, "w") as f:
            json.dump(summary, f, indent=4)
        
        self.logger.info(f"Completed subdomain takeover scan. Found {len(results)} potentially vulnerable subdomains")
        self.logger.info(f"Summary saved to {summary_file}")
        
        return summary

    def run(self, subdomains=None):
        """
        Run the subdomain takeover scanner
        
        Args:
            subdomains (list, optional): List of subdomains to check. If None, try to 
                                    get subdomains from a file or other sources.
            
        Returns:
            dict: Scan results
        """
        if not subdomains:
            # Try to load subdomains from a file based on domain name
            subdomain_file = f"subdomains_{self.domain}.txt"
            if os.path.exists(subdomain_file):
                with open(subdomain_file, "r") as f:
                    subdomains = [line.strip() for line in f if line.strip()]
                self.logger.info(f"Loaded {len(subdomains)} subdomains from {subdomain_file}")
            else:
                self.logger.warning(f"No subdomains provided and {subdomain_file} not found")
                return {
                    "error": "No subdomains provided",
                    "domain": self.domain
                }
        
        # Run the scan
        return self.scan(subdomains)