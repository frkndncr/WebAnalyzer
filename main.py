# Provides functions to interact with the operating system
import os
# Used to handle JSON data for saving and reading results
import json
# Import the datetime class for handling dates and times
from datetime import datetime
# Import the importlib.util module to assist with dynamic module loading if necessary
import importlib.util
# Import is_dataclass and asdict from the dataclasses module to work with dataclass instances
from dataclasses import is_dataclass, asdict
# Importing the module for fetching domain-related information using WHOIS services
from modules.domain_info import get_domain_info
# Importing the module for fetching DNS records such as A, MX, TXT, and NS
from modules.domain_dns import get_dns_records
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

def clear_terminal():
    """
    Clear the terminal screen.
    """
    os.system('cls' if os.name == 'nt' else 'clear')


def save_results_to_json(domain, results, logs_dir="logs"):
    """
    Save all analysis results to a JSON file.
    """
    # Create logs directory and domain folder
    if not os.path.exists(logs_dir):
        os.makedirs(logs_dir)
    domain_dir = os.path.join(logs_dir, domain)
    if not os.path.exists(domain_dir):
        os.makedirs(domain_dir)

    # Custom encoder: if an object is a dataclass, convert it to a dict.
    # Also convert sets to lists.
    def custom_encoder(obj):
        if is_dataclass(obj):
            return asdict(obj)
        if isinstance(obj, set):
            return list(obj)
        raise TypeError(f"Object of type {obj.__class__.__name__} is not JSON serializable")

    # Save results to JSON file
    output_file = os.path.join(domain_dir, "results.json")
    with open(output_file, "w", encoding="utf-8") as json_file:
        json.dump(results, json_file, indent=4, default=custom_encoder)
    print("\n\033[92m" + "=" * 50 + "\033[0m")
    print("\033[92m[✔] Analysis results have been successfully saved!\033[0m")
    print(f"\033[94m[➤] Location:\033[0m \033[93m{output_file}\033[0m")
    print("\033[92m" + "=" * 50 + "\033[0m")

def display_banner():

    banner = """
    \033[92m


        ██╗    ██╗███████╗██████╗     ████████╗ ██████╗  ██████╗ ██╗     ███████╗
        ██║    ██║██╔════╝██╔══██╗    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██╔════╝
        ██║ █╗ ██║█████╗  ██████╔╝       ██║   ██║   ██║██║   ██║██║     ███████╗
        ██║███╗██║██╔══╝  ██╔══██╗       ██║   ██║   ██║██║   ██║██║     ╚════██║
        ╚███╔███╔╝███████╗██████╔╝       ██║   ╚██████╔╝╚██████╔╝███████╗███████║
        ╚══╝╚══╝ ╚══════╝╚═════╝        ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝╚══════╝
                                                                                
        Welcome to the Web Analysis Tool                                  
        Analyze domains with precision and style!    
            Coder Furkan DINCER @f3rrkan                    
    \033[0m
    """
    print(banner)


def check_modules():
    """
    Check if all required modules are available and importable.
    Returns True if all modules are loaded successfully, False otherwise.
    """
    modules = {
        "Domain Info Module": "modules.domain_info",
        "DNS Records Module": "modules.domain_dns",
        "Subfinder Tool Module": "modules.subfinder_tool",
        "SEO Analysis Module": "modules.seo_analysis",
        "Web Technologies Module": "modules.web_technologies",
        "Security Analysis Module": "modules.security_analysis",
        "Contact Spy Module": "modules.contact_spy",  # Eklenen modül
    }

    print("\033[93m" + "=" * 50 + "\033[0m")
    print("\033[93m>>>           MODULE CHECK STARTING          <<<\033[0m")
    print("\033[93m" + "=" * 50 + "\033[0m")

    all_modules_loaded = True
    for module_name, module_path in modules.items():
        try:
            __import__(module_path)
            print(f"\033[92m[✔] {module_name}: Loaded successfully.\033[0m")
        except ImportError:
            print(f"\033[91m[✘] {module_name}: Not found or failed to load.\033[0m")
            all_modules_loaded = False

    print("\033[93m" + "=" * 50 + "\033[0m")
    return all_modules_loaded

def main():
    # Clear terminal and display banner
    clear_terminal()
    display_banner()

    if not check_modules():
        print("\033[91m[✘] Some modules are missing. Please install the required modules and try again.\033[0m")
        return

    print("\033[92m[✔] All required modules are successfully loaded!\033[0m\n")

    print("\033[94mWhat's Next:\033[0m Prepare to analyze the domain for detailed insights.\n")
    print("\033[94mFeatures to be analyzed:\033[0m")
    features = [
        "Domain WHOIS Information",
        "DNS Records",
        "Subdomains",
        "SEO and Analytics Tags",
        "Web Technologies",
        "Security Analysis",
        "Contact Spy",

    ]
    for feature in features:
        print(f"  \033[96m- {feature}\033[0m")

    print("\n\033[93m" + "=" * 50 + "\033[0m")

    # Prompt user for domain input
    api_key = "at_14sqNbh0sbZ61CY1Bl0meKYgVKrL8"
    domain = input("\033[92mPlease enter a domain name (e.g., example.com): \033[0m")

    # Collect results in a dictionary
    all_results = {}
    print(f"\n\033[94m[➤] Starting analysis for: {domain}\033[0m")


    # Domain Information
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

    # SEO and Analytics Tag Analysis
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

    # Verification Tags
    print("\n\033[94mVerification Tags:\033[0m")
    for key, value in seo_tags.get("Verification Tags", {}).items():
        print(f"  {key}: {value}")

    # Analytics Tools
    print("\n\033[94mAnalytics Tools:\033[0m")
    for key, value in seo_tags.get("Analytics Tools", {}).items():
        if isinstance(value, list):
            print(f"  {key}: {', '.join(value) if value else 'Not Found'}")
        else:
            print(f"  {key}: {'Detected' if value else 'Not Detected'}")



    # JavaScript Frameworks
    print("\n\033[94mJavaScript Frameworks:\033[0m")
    frameworks = seo_tags.get("JavaScript Frameworks", [])
    print(f"  {'Detected: ' + ', '.join(frameworks) if frameworks else 'Not Found'}")

    # Structured Data
    print("\n\033[94mStructured Data:\033[0m")
    structured_data = seo_tags.get("Structured Data", [])
    if structured_data:
        print(f"  Found {len(structured_data)} structured data entries")
    else:
        print("  Not Found")

    # Performance Metrics
    print("\n\033[94mPerformance Metrics:\033[0m")
    for key, value in seo_tags.get("Performance Metrics", {}).items():
        print(f"  {key}: {value}")

    # Security Headers
    print("\n\033[94mSecurity Headers:\033[0m")
    for key, value in seo_tags.get("Security Headers", {}).items():
        print(f"  {key}: {value}")


    # Web Technologies Detection
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

    # Contact Scan – Yeni modülümüzün entegrasyonu
    print("\n\033[93m" + "=" * 40 + "\033[0m")
    print("\033[93m--- Contact Scan ---\033[0m")
    print("\033[93m" + "=" * 40 + "\033[0m")
    # GlobalDomainScraper, domain ve max_pages parametresiyle başlatılıyor
    contact_scraper = GlobalDomainScraper(domain, max_pages=100)
    contact_results = contact_scraper.crawl()
    
    # Özet bilgileri ekrana yazdırma
    summary = contact_results.get('summary', {})
    print("\nContact Scan Summary:")
    print(f"Pages scanned: {contact_results.get('pages_scanned', 0)}")
    print(f"Total emails found: {summary.get('total_emails', 0)}")
    print(f"Total phone numbers found: {summary.get('total_phones', 0)}")
    print(f"Total social media profiles found: {summary.get('total_social_media', 0)}")
    
    # Sonuçları dışa aktar
    # (Export işlemi, modül içinde loglanıyor; JSON veya CSV formatı seçilebilir)
    contact_scraper.export_results(contact_results, output_format='json')
    
    # Tüm sonuçları all_results sözlüğüne ekleyelim
    all_results["Contact Scan"] = contact_results

    # Diğer modüllerin sonuçlarını da all_results içine ekleyebilirsiniz...
    
    # Sonuçları kaydet (örneğin, JSON dosyasına)
    save_results_to_json(domain, all_results)
    print("\nScan completed.")

    # Subdomain Discovery
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

    save_results_to_json(domain, all_results)
if __name__ == "__main__":
    main()
