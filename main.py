# Provides functions to interact with the operating system
import os
# Used to handle JSON data for saving and reading results
import json
# Import the datetime class for handling dates and times
from datetime import datetime
import time
import logging
import asyncio
import sys
import io
import warnings
# Import the importlib.util module to assist with dynamic module loading if necessary
import importlib.util
# Import is_dataclass and asdict from the dataclasses module to work with dataclass instances
from dataclasses import is_dataclass, asdict
# Import utility functions from utils/utils.py
from utils.utils import clear_terminal, save_results_to_json, display_banner
# Importing the module for fetching domain-related information using WHOIS services
from modules.domain_info import get_domain_info
# Importing the module for fetching DNS records such as A, MX, TXT, and NS
from modules.domain_dns import DNSAnalyzer  # Assuming the file is named dns_analyzer.py
# Importing the module for discovering subdomains using Subfinder
from modules.subfinder_tool import run_subfinder
# Importing the module for performing SEO and analytics tag analysis
from modules.seo_analysis import analyze_advanced_seo
# Importing the module for detecting web technologies like frontend and backend frameworks
from modules.web_technologies import detect_web_technologies
# Importing the module for conducting advanced security analysis like WAF detection and SSL checks
from modules.security_analysis import analyze_security
# Import GlobalDomainScraper class from the 'contact_spy' module in the 'modules' package
from modules.contact_spy import GlobalDomainScraper
# Import SubdomainTakeover class from the 'subdomain_takeover' module in the 'modules' package
from modules.subdomain_takeover import SubdomainTakeover
# Import AdvancedContentScanner class from the 'advanced_content_scanner' module in the 'modules' package
from modules.advanced_content_scanner import AdvancedContentScanner
# Import CloudflareBypass class from the 'cloudflare_bypass' module in the 'modules' package
from modules.cloudflare_bypass import CloudflareBypass
# Import AdvancedNetworkScanner class from the 'nmap_zero_day' module in the 'modules' package
from modules.nmap_zero_day import UltraAdvancedNetworkScanner

def _check_modules(silent=True):
    """
    Check if all required modules are available and importable.
    Returns True if all modules are loaded successfully, False otherwise.
    """
    modules = {
        "Domain Information": "modules.domain_info",
        "Nmap Zero Day Scan": "modules.nmap_zero_day",
        "DNS Records": "modules.domain_dns",
        "SEO Analysis": "modules.seo_analysis",
        "Web Technologies": "modules.web_technologies",
        "Security Analysis": "modules.security_analysis",
        "Advanced Content Scan": "modules.advanced_content_scanner",
        "Contact Spy": "modules.contact_spy",
        "Subdomain Discovery": "modules.subfinder_tool",
        "Subdomain Takeover": "modules.subdomain_takeover",
        "CloudFlare Bypass": "modules.cloudflare_bypass"
    }

    all_modules_loaded = True
    for module_name, module_path in modules.items():
        try:
            __import__(module_path)
            if not silent:
                print(f"\033[92m[✔] {module_name}: Loaded successfully.\033[0m")
        except ImportError:
            if not silent:
                print(f"\033[91m[✘] {module_name}: Not found or failed to load.\033[0m")
            all_modules_loaded = False

    return all_modules_loaded

def run_subdomain_takeover_module(domain, subdomains, output_dir=None):
    """
    Run the subdomain takeover module

    Args:
        domain (str): The target domain
        subdomains (list): List of subdomains to check
        output_dir (str, optional): Directory to save results

    Returns:
        dict: Scan results
    """
    print(f"Starting subdomain takeover module for {domain}")

    if not subdomains:
        print(f"No subdomains provided for {domain}")
        return {"error": "No subdomains provided", "domain": domain}

    # Initialize the scanner
    scanner = SubdomainTakeover(
        domain,
        logger=None,  # Logger yok
        output_dir=output_dir,
        timeout=10,
        max_workers=20,
        verify_ssl=False
    )

    # Run the scan
    results = scanner.scan(subdomains)

    # Print summary to console
    if results["vulnerable_subdomains"]:
        high_confidence = results["statistics"]["high_confidence"]
        medium_confidence = results["statistics"]["medium_confidence"]
        low_confidence = results["statistics"]["low_confidence"]

        print("\n\033[93m" + "=" * 50 + "\033[0m")
        print("\033[93m--- SUBDOMAIN TAKEOVER VULNERABILITIES ---\033[0m")
        print("\033[93m" + "=" * 50 + "\033[0m")
        print(f"\033[94mTotal Vulnerable Subdomains:\033[0m {len(results['vulnerable_subdomains'])}")
        print(f"\033[91mHigh Confidence:\033[0m {high_confidence}")
        print(f"\033[93mMedium Confidence:\033[0m {medium_confidence}")
        print(f"\033[94mLow Confidence:\033[0m {low_confidence}")

        if high_confidence > 0:
            print("\n\033[91mCritical Vulnerabilities:\033[0m")
            for subdomain in results["vulnerable_subdomains"]:
                if subdomain["confidence"] == "High":
                    print(
                        f"  \033[91m{subdomain['subdomain']}\033[0m - {subdomain['vulnerability_type']} ({subdomain['service']})")
                    print(f"    → \033[93mExploitation Difficulty:\033[0m {subdomain['exploitation_difficulty']}")
                    print(f"    → \033[92mMitigation:\033[0m {subdomain['mitigation']}")

        print(f"\n\033[94mDetailed results saved to:\033[0m {output_dir}/takeover_summary_{domain}.json")
    else:
        print("\n\033[92mNo subdomain takeover vulnerabilities found.\033[0m")

    return results

def run_advanced_content_scanner(domain, output_dir=None):
    """
    Run the Advanced Content Scanner

    Args:
        domain (str): The target domain
        output_dir (str, optional): Directory to save results

    Returns:
        dict: Scan results
    """
    logging.disable(logging.CRITICAL)
    warnings.filterwarnings('ignore')

    old_stdout = sys.stdout
    old_stderr = sys.stderr
    stdout_capture = io.StringIO()
    stderr_capture = io.StringIO()
    sys.stdout = stdout_capture
    sys.stderr = stderr_capture

    try:
        # Initialize the scanner
        scanner = AdvancedContentScanner(
            domain,
            output_dir=output_dir,
            max_depth=2,
            max_pages=100,
            timeout=10,
            max_workers=10,
            verify_ssl=False
        )

        # Run the scan
        results = scanner.run()
        sys.stdout = old_stdout
        sys.stderr = old_stderr

        high_secrets = [s for s in results["secrets"] if s["severity"] == "High"]
        high_js_vulns = [v for v in results["js_vulnerabilities"] if v["severity"] == "High"]
        high_ssrf = [v for v in results["ssrf_vulnerabilities"] if v["severity"] == "High"]

        unique_secret_sources = len(set(s["source_url"] for s in high_secrets))
        unique_js_vuln_sources = len(set(v["source_url"] for v in high_js_vulns))
        unique_ssrf_sources = len(set(v["source_url"] for v in high_ssrf))

        print(f"\033[94mTotal URLs Crawled:\033[0m {results['summary']['total_urls_crawled']}")
        print(f"\033[94mTotal JS Files Analyzed:\033[0m {results['summary']['total_js_files']}")
        print(f"\033[94mTotal API Endpoints Found:\033[0m {results['summary']['total_api_endpoints']}")
        print(f"\033[91mHigh Severity Secrets Found:\033[0m {len(high_secrets)} (in {unique_secret_sources} files)")
        print(f"\033[91mHigh Severity JS Vulnerabilities:\033[0m {len(high_js_vulns)} (in {unique_js_vuln_sources} files)")
        print(f"\033[91mHigh Severity SSRF Vulnerabilities:\033[0m {len(high_ssrf)} (in {unique_ssrf_sources} endpoints)")

        if high_secrets:
            print("\n\033[91mTop High Severity Secrets:\033[0m")
            by_source = {}
            for s in high_secrets:
                if s["source_url"] not in by_source:
                    by_source[s["source_url"]] = []
                by_source[s["source_url"]].append(s)

            for i, (source, secrets) in enumerate(sorted(by_source.items(), key=lambda x: len(x[1]), reverse=True)[:3]):
                count = len(secrets)
                types = ", ".join(set(s["type"] for s in secrets[:3]))
                if len(set(s["type"] for s in secrets)) > 3:
                    types += " and more"
                print(f"  \033[91m{i + 1}. {source}\033[0m: {count} secrets ({types})")

        if high_js_vulns:
            print("\n\033[91mTop High Severity JS Vulnerabilities:\033[0m")
            by_type = {}
            for v in high_js_vulns:
                if v["type"] not in by_type:
                    by_type[v["type"]] = []
                by_type[v["type"]].append(v)

            for i, (vuln_type, vulns) in enumerate(sorted(by_type.items(), key=lambda x: len(x[1]), reverse=True)[:3]):
                count = len(vulns)
                sources = ", ".join(set(v["source_url"] for v in vulns[:3]))
                if len(set(v["source_url"] for v in vulns)) > 3:
                    sources += " and more"
                print(f"  \033[91m{i + 1}. {vuln_type}\033[0m: {count} instances ({sources})")

        if high_ssrf:
            print("\n\033[91mSSRF Vulnerabilities:\033[0m")
            for i, vuln in enumerate(high_ssrf[:3]):
                print(f"  \033[91m{i + 1}. {vuln['type']}\033[0m in {vuln['source_url']}")
        print(f"\n\033[94mDetailed findings saved to:\033[0m {scanner._save_findings()}")

        return results
    except Exception as e:
        sys.stdout = old_stdout
        sys.stderr = old_stderr
        print(f"\033[91mError during scan: {str(e)}\033[0m")
        return None
    finally:
        logging.disable(logging.NOTSET)
        warnings.resetwarnings()

def select_modules():
    """
    Allows user to select which modules to run or choose to run all modules.
    Returns a list of selected module names and a boolean indicating if all modules should run.
    """
    modules = [
        "Domain Information",
        "DNS Records",
        "Nmap Zero Day Scan",
        "SEO Analysis",
        "Web Technologies",
        "Security Analysis",
        "Advanced Content Scan",
        "Contact Spy",
        "Subdomain Discovery",
        "Subdomain Takeover",
        "CloudFlare Bypass"
    ]

    print("\033[93m" + "=" * 50 + "\033[0m")
    print("\033[93m>>>        MODULE SELECTION MENU        <<<\033[0m")
    print("\033[93m" + "=" * 50 + "\033[0m")

    # Display module options
    for i, module in enumerate(modules, 1):
        print(f"\033[94m[{i}] {module}\033[0m")

    print("\033[94m[A] Run ALL Modules\033[0m")
    print("\033[94m[Q] Quit\033[0m")

    while True:
        # Get user input
        choice = input(
            "\033[92mEnter module numbers (comma-separated) or 'A' for all, 'Q' to quit: \033[0m").upper().strip()

        # Quit option
        if choice == 'Q':
            print("\033[91mExiting module selection.\033[0m")
            return [], False

        # All modules option
        if choice == 'A':
            print("\033[92m[✔] All modules selected!\033[0m")
            return modules, True

        # Individual module selection
        try:
            # Split input and remove any whitespace
            selected_numbers = [num.strip() for num in choice.split(',')]

            # Validate and collect selected modules
            selected_modules = []
            for num in selected_numbers:
                try:
                    index = int(num) - 1
                    if 0 <= index < len(modules):
                        selected_modules.append(modules[index])
                    else:
                        print(f"\033[91m[✘] Invalid selection: {num}\033[0m")
                        break
                except ValueError:
                    print(f"\033[91m[✘] Invalid selection: {num}\033[0m")
                    break
            else:
                # If no invalid selections were found
                if selected_modules:
                    print("\033[92m[✔] Modules selected successfully:\033[0m")
                    for module in selected_modules:
                        print(f"\033[94m- {module}\033[0m")
                    return selected_modules, False

        except Exception:
            print("\033[91m[✘] Invalid input. Please enter valid module numbers.\033[0m")

def run_cloudflare_bypass(domain):
    """
    Run the CloudFlare Bypass module to find real IP addresses behind CloudFlare.

    Args:
        domain (str): The domain to analyze
    """
    from modules.cloudflare_bypass import CloudflareBypass
    print("\n")
    print("\033[93m" + "=" * 50 + "\033[0m")
    print("\033[93m>>>           CLOUDFLARE BYPASS           <<<\033[0m")
    print("\033[93m" + "=" * 50 + "\033[0m")

    print(f"\033[94m[*] Scanning {domain} for real IPs behind CloudFlare\033[0m")

    # CloudFlare Bypass modülünü başlat
    bypass = CloudflareBypass(target=domain, verbose=True)
    results = bypass.run()

    # Sonuçları göster
    print("\033[93m" + "=" * 50 + "\033[0m")
    print(f"\033[93m>>> RESULTS FOR {results['target']} <<<\033[0m")
    print(f"\033[94mScan time: {results['scan_time']:.1f} seconds\033[0m")
    print(f"\033[94mCloudFlare protected: {'Yes' if results['cloudflare_protected'] else 'No'}\033[0m")
    print("\033[93m" + "=" * 50 + "\033[0m")

    if results['real_ips']:
        print("\033[92m[+] REAL IP ADDRESSES:\033[0m")
        for i, ip_info in enumerate(results['real_ips'], 1):
            status = "✓" if ip_info.get('status') == "active" else "✗" if ip_info.get('status') == "inactive" else "?"
            desc = f" - {ip_info['description']}" if 'description' in ip_info else ""
            confidence = ip_info.get('confidence', 'Unknown')

            # Confidence rengini belirle
            if confidence == 'Very High':
                confidence_color = "\033[92m"  # Yeşil
            elif confidence == 'High':
                confidence_color = "\033[93m"  # Sarı
            elif confidence == 'Medium':
                confidence_color = "\033[33m"  # Turuncu
            else:
                confidence_color = "\033[91m"  # Kırmızı

            status_color = "\033[92m" if status == "✓" else "\033[91m" if status == "✗" else "\033[93m"

            print(
                f"\033[94m{i}. \033[97m{ip_info['ip']} {status_color}[{status}]\033[0m {confidence_color}({confidence})\033[0m{desc}")

        print("\n\033[92m[+] TEST COMMANDS:\033[0m")

        # Sadece aktif IP'leri göster
        active_ips = [ip for ip in results['real_ips'] if ip.get('status') == "active"]

        if active_ips:
            for ip_info in active_ips[:3]:  # İlk 3 aktif IP'yi göster
                print(f"\033[94mcurl -H 'Host: {results['target']}' http://{ip_info['ip']}/\033[0m")
        else:
            # Aktif IP yoksa tüm sonuçlardan ilk 3'ünü göster
            for ip_info in results['real_ips'][:3]:
                print(f"\033[94mcurl -H 'Host: {results['target']}' http://{ip_info['ip']}/\033[0m")
    else:
        print("\033[91m[-] No real IPs found. The target has strong CloudFlare protection.\033[0m")

async def main():
    # Clear terminal and display banner
    clear_terminal()
    display_banner()

    if not _check_modules():
        print("\033[91m[✘] Some modules are missing. Please install the required modules and try again.\033[0m")
        return

    print("\033[92m[✔] All required modules are successfully loaded!\033[0m\n")
    print("\033[94mWhat's Next:\033[0m Prepare to analyze the domain for detailed insights.\n")

    # Prompt user for domain input
    api_key = "at_14sqNbh0sbZ61CY1Bl0meKYgVKrL8"
    domain = input("\033[92mPlease enter a domain name (e.g., example.com): \033[0m")

    # Select modules to run
    selected_modules, run_all = select_modules()

    # Collect results in a dictionary
    all_results = {}
    print(f"\n\033[94m[➤] Starting analysis for: {domain}\033[0m")

    # Variable to track if subdomain discovery has been run
    subdomains_discovered = False

    # Domain Information
    if run_all or "Domain Information" in selected_modules:
        print("\n\033[93m" + "="*40 + "\033[0m")
        print("\033[93m--- DOMAIN INFORMATION ---\033[0m")
        print("\033[93m" + "="*40 + "\033[0m")
        domain_info = get_domain_info(domain, api_key)
        all_results["Domain Information"] = domain_info

        # Key details to display first
        keys_to_display_first = [
            "Domain",
            "Registrar",
            "Creation Date",
            "Expiration Date",
            "Last Updated Date",
            "Server Provider",
            "Physical Location",
        ]

        # Print primary details
        for key in keys_to_display_first:
            if key in domain_info and domain_info[key] not in ["Unknown", "Not available"]:
                print(f"\033[94m{key}:\033[0m {domain_info[key]}")

        # Print additional details
        for key, value in domain_info.items():
            if key in keys_to_display_first:
                continue  # Skip already displayed keys
            elif isinstance(value, dict):  # Dictionary details (e.g., SSL info)
                print(f"\033[94m{key}:\033[0m")
                for subkey, subvalue in value.items():
                    print(f"  - {subkey}: {subvalue}")
            elif isinstance(value, list):  # List details (e.g., Domain Status)
                print(f"\033[94m{key}:\033[0m")
                for item in value:
                    print(f"  - {item}")
            elif value not in ["Unknown", "Not available"]:
                print(f"\033[94m{key}:\033[0m {value}")
    
    # DNS Information
    if run_all or "DNS Records" in selected_modules:
        print("\n\033[93m" + "="*40 + "\033[0m")
        print("\033[93m--- DNS INFORMATION ---\033[0m")
        print("\033[93m" + "="*40 + "\033[0m")

        analyzer = DNSAnalyzer() # Speed Mood
        start_time = time.time()
        dns_records = analyzer.get_dns_records(domain)
        print("DNS Records:")
        for record_type, records in dns_records["records"].items():
            print(f"{record_type}:")
            for record in records:
                print(f"  - {record}")

        print("\nFull Report:")
        print(analyzer.generate_report(domain, color=True))
        # Print response time
        print(f"\033[94mResponse Time:\033[0m {dns_records['response_time_ms']} ms")
        print(f"Total execution time: {round((time.time() - start_time) * 1000, 2)} ms")
        all_results["DNS Records"] = dns_records

    #Cloud Flare Bypass
    if "CloudFlare Bypass" in selected_modules or run_all:
            run_cloudflare_bypass(domain)

    # SEO and Analytics Tag Analysis
    if run_all or "SEO Analysis" in selected_modules:
        print("\n\033[93m" + "=" * 40 + "\033[0m")
        print("\033[93m--- SEO and Analytics Tags ---\033[0m")
        print("\033[93m" + "=" * 40 + "\033[0m")

        seo_tags = analyze_advanced_seo(domain)
        all_results["SEO Analysis"] = seo_tags
        # Meta Tags
        print("\n\033[94mMeta Tags:\033[0m")
        for key, value in seo_tags.get("Meta Tags", {}).items():
            print(f"  {key}: {value}")

        # Open Graph Tags
        print("\n\033[94mOpen Graph Tags:\033[0m")
        for key, value in seo_tags.get("Open Graph Tags", {}).items():
            print(f"  {key}: {value}")

        # Twitter Tags
        print("\n\033[94mTwitter Tags:\033[0m")
        for key, value in seo_tags.get("Twitter Tags", {}).items():
            print(f"  {key}: {value}")

        # Additional SEO tag sections preserved from original script...

    # Web Technologies Detection
    if run_all or "Web Technologies" in selected_modules:
        print("\n\033[93m" + "=" * 40 + "\033[0m")
        print("\033[93m--- Web Technologies Detection ---\033[0m")
        print("\033[93m" + "=" * 40 + "\033[0m")
        technologies = detect_web_technologies(domain)
        all_results["Web Technologies"] = technologies
        for key, value in technologies.items():
            if isinstance(value, list) and value:  # If it's a list and not empty
                print(f"\033[94m{key}:\033[0m {', '.join(value)}")
            elif value:
                print(f"\033[94m{key}:\033[0m {value}")
            else:
                print(f"\033[94m{key}:\033[0m Not Detected")

    # Advanced Security Analysis
    if run_all or "Security Analysis" in selected_modules:
        print("\n\033[93m" + "=" * 40 + "\033[0m")
        print("\033[93m--- Security Analysis ---\033[0m")
        print("\033[93m" + "=" * 40 + "\033[0m")

        security_info = analyze_security(domain)
        all_results["Security Analysis"] = security_info
        # WAF Detection
        print("\033[94mWeb Application Firewall:\033[0m", security_info.get("Web Application Firewall", "Not Detected"))
        # Security Headers
        print("\n\033[94mSecurity Headers:\033[0m")
        for key, value in security_info.get("Security Headers", {}).items():
            print(f"  {key}: {value}")
        # SSL Info
        print("\n\033[94mSSL Info:\033[0m")
        for key, value in security_info.get("SSL Info", {}).items():
            print(f"  {key}: {value}")
        # CORS Policy
        print("\n\033[94mCORS Policy:\033[0m", security_info.get("CORS Policy", "Not Found"))
            
    # Advanced Content Scan
    if run_all or "Advanced Content Scan" in selected_modules:
        print("\n\033[93m" + "="*40 + "\033[0m")
        print("\033[93m--- ADVANCED CONTENT SCAN ---\033[0m")
        print("\033[93m" + "="*40 + "\033[0m")
        print(f"Starting advanced content scan for {domain} wait please")
        content_scan_results = run_advanced_content_scanner(domain, output_dir=f"logs/{domain}")
        all_results["Advanced Content Scan"] = content_scan_results

    # Contact Scan
    if run_all or "Contact Spy" in selected_modules:
        print("\n\033[93m" + "=" * 40 + "\033[0m")
        print("\033[93m--- Contact Scan ---\033[0m")
        print("\033[93m" + "=" * 40 + "\033[0m")
        
        try:
            contact_scraper = GlobalDomainScraper(domain, max_pages=100, log_dir="logs")
            contact_results = contact_scraper.crawl()
            
            if "error" in contact_results:
                print(f"\033[91m[ERROR] Contact scan failed: {contact_results['error']}\033[0m")
            else:
                summary = contact_results.get('summary', {})
                print("\nContact Scan Summary:")
                print(f"Pages scanned: {contact_results.get('pages_scanned', 0)}")
                print(f"Total emails found: {summary.get('total_emails', 0)}")
                print(f"Total phone numbers found: {summary.get('total_phones', 0)}")
                print(f"Total social media profiles found: {summary.get('total_social_media', 0)}")
                
                contact_scraper.export_results(contact_results, output_format='json')
                print(f"\033[94mResults saved to: logs/{domain}/contact_scan.json\033[0m")
                print(f"\033[94mLog file: logs/scraper.log\033[0m")
            
            all_results["Contact Scan"] = contact_results
        
        except Exception as e:
            print(f"\033[91m[ERROR] Unexpected error in Contact Scan: {str(e)}\033[0m")
            all_results["Contact Scan"] = {"error": str(e)}

        save_results_to_json(domain, all_results)
        print("\nScan completed.")

    # Subdomain Discovery
    subdomains = []
    if run_all or "Subdomain Takeover" in selected_modules or "Subdomain Discovery" in selected_modules:
        print("\n\033[93m" + "="*40 + "\033[0m")
        print("\033[93m--- SUBDOMAIN DISCOVERY ---\033[0m")
        print("\033[93m" + "="*40 + "\033[0m")
        subdomains = run_subfinder(domain)
        all_results["Subdomains"] = subdomains

        if subdomains:
            print(f"\033[94mTotal Subdomains Found:\033[0m {len(subdomains)}")
            print(f"\033[94mSaved to File:\033[0m subdomains_{domain}.txt")
        else:
            print("\033[91mNo subdomains found or Subfinder could not be executed.\033[0m")

    # Subdomain Takeover
    if run_all or "Subdomain Takeover" in selected_modules:
        print("\n\033[93m" + "="*40 + "\033[0m")
        print("\033[93m--- SUBDOMAIN TAKEOVER ANALYSIS ---\033[0m")
        print("\033[93m" + "="*40 + "\033[0m")
        
        if subdomains:
            takeover_results = run_subdomain_takeover_module(domain, subdomains)
            all_results["Subdomain Takeover"] = takeover_results
        else:
            print("\033[91mSkipping subdomain takeover scan as no subdomains were found.\033[0m")

    #Nmap & Zero Day Scanner
    if run_all or "Nmap Zero Day Scan" in selected_modules:
        print("\n\033[93m" + "="*40 + "\033[0m")
        print("\033[93m--- ADVANCED NETWORK & ZERO-DAY SCAN ---\033[0m")
        print("\033[93m" + "="*40 + "\033[0m")
        print("Starting scan...")
       
        try:
            scanner = UltraAdvancedNetworkScanner(domain=domain, timeout=10, aggressive_mode=False)
            start_time = time.time()
           
            scan_results = await scanner.run_comprehensive_scan(domain)
           
            # Open Ports and Services
            print("\nOpen Ports and Services:")
            for port in scan_results['port_scan'].get('open_ports', []):
                service = scan_results['port_scan']['services'][port]
                print(f"  - Port: {port}, Service: {service['service']}, Version: {service['version']}, State: {service.get('state', 'open')}")
           
            # Zero-Day Vulnerabilities
            print("\nZero-Day Vulnerabilities:")
            for vuln in scan_results['zero_day_vulnerabilities']:
                print(f"  - {vuln.get('id', 'N/A')}: {vuln.get('description', 'No details available')} (Severity: {vuln.get('severity', {}).get('level', 'Unknown')})")
           
            execution_time = time.time() - start_time
            print(f"\nScan completed in {execution_time:.2f} seconds")
            all_results["Nmap Zero Day Scan"] = scan_results

        except Exception as e:
            print(f"[ERROR] An error occurred: {str(e)}")
            
    # Save results
    save_results_to_json(domain, all_results)

if __name__ == "__main__":
    asyncio.run(main())
