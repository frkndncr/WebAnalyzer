# main.py - Complete updated version with IP rotation and rate limiting protection
import os
import json
from datetime import datetime
import time
import logging
import asyncio
import sys
import io
import warnings

# Import utility functions
from utils.utils import clear_terminal, save_results_to_json, display_banner
from utils.module_wrapper import ModuleExecutor, safe_module_execution

# Session manager'ı opsiyonel yap
try:
    from utils.session_manager import get_session_manager
    SESSION_MANAGER_AVAILABLE = True
except ImportError:
    SESSION_MANAGER_AVAILABLE = False
    print("⚠️  Session manager not available, using basic delays")

try:
    from config import get_config
    CONFIG_AVAILABLE = True
except ImportError:
    CONFIG_AVAILABLE = False
    print("⚠️  Config module not available, using defaults")

# Import all modules
from modules.domain_info import get_domain_info
from modules.domain_dns import DNSAnalyzer
from modules.subfinder_tool import run_subfinder
from modules.seo_analysis import analyze_advanced_seo
from modules.web_technologies import detect_web_technologies
from modules.security_analysis import analyze_security
from modules.contact_spy import GlobalDomainScraper
from modules.subdomain_takeover import SubdomainTakeover
from modules.advanced_content_scanner import AdvancedContentScanner
from modules.cloudflare_bypass import CloudflareBypass
from modules.nmap_zero_day import UltraAdvancedNetworkScanner
from modules.geo_analysis import analyze_geo

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('webanalyzer.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def _check_modules(silent=True):
    """Check if all required modules are available and importable."""
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
        "CloudFlare Bypass": "modules.cloudflare_bypass",
        "GEO Analysis": "modules.geo_analysis"
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

# Wrap module functions with safe execution
@safe_module_execution(delay_type='light')
def safe_get_domain_info(domain):
    """Safe wrapper for domain info retrieval"""
    if CONFIG_AVAILABLE:
        config = get_config()
        api_key = config.whois_api_key or "at_14sqNbh0sbZ61CY1Bl0meKYgVKrL8"
    else:
        api_key = os.getenv('WHOIS_API_KEY', 'at_14sqNbh0sbZ61CY1Bl0meKYgVKrL8')
    
    result = get_domain_info(domain, api_key)
    
    # Display results
    if result and isinstance(result, dict):
        key_fields = [
            "Domain", "Registrar", "Creation Date", "Expiration Date", 
            "Last Updated Date", "Server Provider", "Physical Location"
        ]
        
        for key in key_fields:
            if key in result and result[key] not in ["Unknown", "Not available"]:
                print(f"\033[94m{key}:\033[0m {result[key]}")
        
        # Print additional details
        for key, value in result.items():
            if key in key_fields:
                continue
            elif isinstance(value, dict):
                print(f"\033[94m{key}:\033[0m")
                for subkey, subvalue in value.items():
                    print(f"  - {subkey}: {subvalue}")
            elif isinstance(value, list):
                print(f"\033[94m{key}:\033[0m")
                for item in value:
                    print(f"  - {item}")
            elif value not in ["Unknown", "Not available"]:
                print(f"\033[94m{key}:\033[0m {value}")
    
    return result

@safe_module_execution(delay_type='light')  
def safe_dns_analysis(domain):
    """Safe wrapper for DNS analysis"""
    analyzer = DNSAnalyzer()
    start_time = time.time()
    dns_records = analyzer.get_dns_records(domain)
    execution_time = time.time() - start_time
    
    # Display results
    print("DNS Records:")
    for record_type, records in dns_records["records"].items():
        print(f"{record_type}:")
        for record in records:
            print(f"  - {record}")
    
    print("\nFull Report:")
    print(analyzer.generate_report(domain, color=True))
    print(f"\033[94mResponse Time:\033[0m {dns_records['response_time_ms']} ms")
    print(f"Total execution time: {round(execution_time * 1000, 2)} ms")
    
    return dns_records

@safe_module_execution(delay_type='medium')
def safe_seo_analysis(domain):
    """Safe wrapper for SEO analysis"""
    seo_results = analyze_advanced_seo(domain)
    
    # Check for error
    if "Error" in seo_results:
        print(f"\033[91mSEO Analysis Error: {seo_results['Error']}\033[0m")
        return seo_results
    
    # Display key results with better formatting
    print("\n\033[94m📊 SEO SCORE:\033[0m")
    seo_score = seo_results.get("SEO Score", {})
    print(f"  Score: {seo_score.get('Score', 'N/A')}")
    print(f"  Grade: {seo_score.get('Grade', 'N/A')}")
    
    print("\n\033[94m🔍 BASIC SEO:\033[0m")
    basic_seo = seo_results.get("Basic SEO", {})
    title = basic_seo.get("Title", {})
    print(f"  Title: {title.get('text', 'N/A')[:80]}... ({title.get('status', 'Unknown')})")
    
    meta_desc = basic_seo.get("Meta Description", {})
    print(f"  Meta Description: {meta_desc.get('status', 'Unknown')} ({meta_desc.get('length', 0)} chars)")
    
    print("\n\033[94m📱 SOCIAL MEDIA:\033[0m")
    social = seo_results.get("Social Media", {})
    og = social.get("Open Graph", {})
    twitter = social.get("Twitter Cards", {})
    
    og_found = sum(1 for v in og.values() if v != "Not Found")
    twitter_found = sum(1 for v in twitter.values() if v != "Not Found")
    
    print(f"  Open Graph tags: {og_found}/6 found")
    print(f"  Twitter Cards: {twitter_found}/5 found")
    
    print("\n\033[94m⚡ PERFORMANCE:\033[0m")
    performance = seo_results.get("Performance Metrics", {})
    print(f"  Load Time: {performance.get('Load Time', 'N/A')} ({performance.get('Load Time Status', 'Unknown')})")
    print(f"  Content Size: {performance.get('Content Size', 'N/A')}")
    
    print("\n\033[94m🛡️ SECURITY:\033[0m")
    security = seo_results.get("Security & Headers", {})
    print(f"  Security Headers: {security.get('Security Score', 'N/A')}")
    print(f"  Status: {security.get('Security Status', 'Unknown')}")
    
    print("\n\033[94m📄 SEO FILES:\033[0m")
    resources = seo_results.get("SEO Resources", {})
    print(f"  robots.txt: {resources.get('robots.txt', 'Unknown')}")
    print(f"  sitemap.xml: {resources.get('sitemap.xml', 'Unknown')}")
    
    print("\n\033[94m📊 ANALYTICS:\033[0m")
    analytics = seo_results.get("Analytics & Tracking", {})
    ga = analytics.get("Google Analytics", {})
    print(f"  Google Analytics: {'Found' if ga.get('GA4') or ga.get('Universal Analytics') else 'Not Found'}")
    print(f"  Google Tag Manager: {analytics.get('Google Tag Manager', 'Unknown')}")
    
    return seo_results

@safe_module_execution(delay_type='medium')
def safe_web_technologies(domain):
    """Safe wrapper for web technologies detection"""
    technologies = detect_web_technologies(domain)
    
    # Display results
    for key, value in technologies.items():
        if isinstance(value, list) and value:
            print(f"\033[94m{key}:\033[0m {', '.join(value)}")
        elif value:
            print(f"\033[94m{key}:\033[0m {value}")
        else:
            print(f"\033[94m{key}:\033[0m Not Detected")
    
    return technologies

@safe_module_execution(delay_type='heavy')
def safe_security_analysis(domain):
    """Safe wrapper for security analysis"""
    security_info = analyze_security(domain)
    
    # Yeni formatlı çıktıyı göster
    if "Error" not in security_info:
        # Yeni format_security_report fonksiyonunu kullan
        try:
            from modules.security_analysis import format_security_report
            print(format_security_report(security_info))
        except ImportError:
            # Fallback - temel bilgileri göster
            score_data = security_info.get("security_score", {})
            print(f"\033[94mSecurity Score:\033[0m {score_data.get('overall_score', 0)}/100 ({score_data.get('grade', 'F')})")
            print(f"\033[94mRisk Level:\033[0m {score_data.get('risk_level', 'Unknown')}")
            
            waf_data = security_info.get("waf_detection", {})
            waf_status = "Detected" if waf_data.get("detected", False) else "Not Detected"
            if waf_data.get("detected", False):
                provider = waf_data.get("primary_waf", {}).get("provider", "Unknown")
                waf_status = f"Detected ({provider})"
            print(f"\033[94mWeb Application Firewall:\033[0m {waf_status}")
            
            ssl_data = security_info.get("ssl_analysis", {})
            if ssl_data.get("ssl_available", False):
                print(f"\033[94mSSL Grade:\033[0m {ssl_data.get('overall_grade', 'Unknown')}")
            else:
                print(f"\033[94mSSL:\033[0m Not Available")
            
            headers_data = security_info.get("security_headers", {})
            print(f"\033[94mSecurity Headers Score:\033[0m {headers_data.get('score', 0)}/100")
    else:
        print(f"\033[91mError:\033[0m {security_info['Error']}")
    
    return security_info

@safe_module_execution(delay_type='medium')
def safe_geo_analysis(domain):
    """Safe wrapper for GEO analysis"""
    geo_results = analyze_geo(domain)
    
    if "Error" in geo_results:
        print(f"\033[91mGEO Analysis Error: {geo_results['Error']}\033[0m")
        return geo_results
        
    print("\n\033[94m📊 GEO SCORE:\033[0m")
    geo_score = geo_results.get("GEO Score", {})
    print(f"  Score: {geo_score.get('Score', 'N/A')}")
    print(f"  Grade: {geo_score.get('Grade', 'N/A')}")
    
    print("\n\033[94m🤖 LLMs Optimization (llms.txt):\033[0m")
    llms = geo_results.get("LLMs Optimization (llms.txt)", {})
    print(f"  Status: {llms.get('status', 'Unknown')}")
    if llms.get('status') == 'Found':
        print(f"  Files: {llms.get('files', 'None')}")
        
    print("\n\033[94m⚙️ WebMCP Integration:\033[0m")
    webmcp = geo_results.get("WebMCP Integration", {})
    print(f"  Status: {webmcp.get('status', 'Unknown')}")
    if webmcp.get('status') == 'Found':
        print(f"  Endpoints: {webmcp.get('endpoints', 'None')}")
        print(f"  HTML Features: {webmcp.get('html_features', 'None')}")
        
    print("\n\033[94m🕷️ AI Crawler Directives:\033[0m")
    crawlers = geo_results.get("AI Crawler Directives", {})
    print(f"  Status: {crawlers.get('status', 'Unknown')}")
    
    return geo_results

@safe_module_execution(delay_type='heavy')
def safe_cloudflare_bypass(domain):
    """Safe wrapper for CloudFlare bypass"""
    print(f"\033[94m[*] Scanning {domain} for real IPs behind CloudFlare\033[0m")
    
    bypass = CloudflareBypass(target=domain, verbose=True)
    results = bypass.run()
    
    # Display results
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

            confidence_color = "\033[92m" if confidence == 'Very High' else "\033[93m" if confidence == 'High' else "\033[33m" if confidence == 'Medium' else "\033[91m"
            status_color = "\033[92m" if status == "✓" else "\033[91m" if status == "✗" else "\033[93m"

            print(f"\033[94m{i}. \033[97m{ip_info['ip']} {status_color}[{status}]\033[0m {confidence_color}({confidence})\033[0m{desc}")

        print("\n\033[92m[+] TEST COMMANDS:\033[0m")
        active_ips = [ip for ip in results['real_ips'] if ip.get('status') == "active"]

        if active_ips:
            for ip_info in active_ips[:3]:
                print(f"\033[94mcurl -H 'Host: {results['target']}' http://{ip_info['ip']}/\033[0m")
        else:
            for ip_info in results['real_ips'][:3]:
                print(f"\033[94mcurl -H 'Host: {results['target']}' http://{ip_info['ip']}/\033[0m")
    else:
        print("\033[91m[-] No real IPs found. The target has strong CloudFlare protection.\033[0m")
    
    return results

@safe_module_execution(delay_type='heavy')
def safe_advanced_content_scan(domain):
    """Safe wrapper for Advanced Content Scanner v4.0 — Nirvana Edition"""
    logging.disable(logging.CRITICAL)
    warnings.filterwarnings('ignore')

    old_stdout = sys.stdout
    old_stderr = sys.stderr
    sys.stdout = io.StringIO()
    sys.stderr = io.StringIO()

    try:
        scanner = AdvancedContentScanner(
            domain,
            output_dir=f"logs/{domain}",
            max_depth=2,
            max_pages=100,
            timeout=10,
            max_workers=10,
            verify_ssl=False,
            log_level="ERROR",
            min_severity="Low",
            active_scan=True,
            fuzz_forms=True,
            test_auth_bypass=True,
            test_cors=True,
            taint_tracking=True,
            headless=False,
            adaptive_waf=True,
            build_exploit_chains=True,
        )
        results = scanner.run()

    except Exception as e:
        sys.stdout = old_stdout
        sys.stderr = old_stderr
        print(f"\033[91mError during scan: {str(e)}\033[0m")
        return {"error": str(e)}
    finally:
        sys.stdout = old_stdout
        sys.stderr = old_stderr
        logging.disable(logging.NOTSET)
        warnings.resetwarnings()

    # ── helpers ──
    def by_sev(lst, *sevs):
        return [x for x in lst if x.get("severity", "").lower() in [s.lower() for s in sevs]]

    def unique_sources(lst):
        return len(set(x.get("source_url", "") for x in lst))

    summary  = results.get("summary", {})
    secrets  = results.get("secrets", [])
    js_vulns = results.get("js_vulnerabilities", [])
    ssrf     = results.get("ssrf_vulnerabilities", [])
    active   = results.get("active_vulnerabilities", [])
    headers  = results.get("security_headers", [])
    exposed  = results.get("exposed_endpoints", [])
    chains   = results.get("exploit_chains", [])

    # ── Risk header ──
    grade = summary.get("security_grade", "?")
    risk  = summary.get("overall_risk_score", 0)
    grade_color = "\033[91m" if grade in ("F","D") else "\033[93m" if grade == "C" else "\033[92m"
    waf   = summary.get("detected_waf", "None")
    print(f"\033[1m{'─'*50}\033[0m")
    print(f"\033[1mSecurity Grade: {grade_color}{grade}\033[0m  Risk Score: {grade_color}{risk}/10\033[0m  WAF: \033[94m{waf}\033[0m")
    print(f"\033[1m{'─'*50}\033[0m\n")

    # ── L1 crawl stats ──
    print(f"\033[94mURLs Crawled:\033[0m {summary.get('total_urls_crawled', 0)}   "
          f"\033[94mJS Files:\033[0m {summary.get('total_js_files', 0)}   "
          f"\033[94mAPI Endpoints:\033[0m {summary.get('total_api_endpoints', 0)}")

    # ── Secrets ──
    top_sec   = by_sev(secrets, "Critical") + by_sev(secrets, "High")
    crit_s    = by_sev(secrets, "Critical")
    crit_tag  = f" (\033[91m{len(crit_s)} Critical\033[0m)" if crit_s else ""
    print(f"\033[91mSecrets Found:\033[0m {len(top_sec)}{crit_tag} (in {unique_sources(top_sec)} files)")

    # ── JS vulns ──
    top_js    = by_sev(js_vulns, "High", "Critical")
    taint_ct  = sum(1 for v in js_vulns if "Taint" in v.get("type", ""))
    print(f"\033[91mJS Vulnerabilities:\033[0m {len(top_js)} high+ ({taint_ct} taint flows)")

    # ── Active vulns ──
    crit_act  = by_sev(active, "Critical")
    high_act  = by_sev(active, "High")
    sqli_ct   = sum(1 for a in active if "SQL" in a.get("type", ""))
    xss_ct    = sum(1 for a in active if "XSS" in a.get("type", ""))
    ssti_ct   = sum(1 for a in active if "SSTI" in a.get("type", ""))
    cors_ct   = sum(1 for a in active if "CORS" in a.get("type", ""))
    bypass_ct = sum(1 for a in active if "Bypass" in a.get("type", ""))
    nuclei_ct = sum(1 for a in active if "Nuclei" in a.get("type", ""))
    act_tag   = f" (\033[91m{len(crit_act)} Critical\033[0m)" if crit_act else ""
    print(f"\033[91mActive Vulnerabilities:\033[0m {len(active)}{act_tag}  "
          f"SQLi:{sqli_ct}  XSS:{xss_ct}  SSTI:{ssti_ct}  CORS:{cors_ct}  403bp:{bypass_ct}  Nuclei:{nuclei_ct}")

    # ── SSRF ──
    confirmed_ssrf = [v for v in ssrf if v.get("confirmed")]
    conf_tag = f" (\033[91m{len(confirmed_ssrf)} Confirmed\033[0m)" if confirmed_ssrf else ""
    print(f"\033[91mSSRF:\033[0m {len(ssrf)}{conf_tag}")

    # ── Exposed endpoints ──
    crit_exp = by_sev(exposed, "Critical")
    if exposed:
        exp_tag = f" (\033[91m{len(crit_exp)} Critical\033[0m)" if crit_exp else ""
        print(f"\033[91mExposed Endpoints:\033[0m {len(exposed)}{exp_tag}")

    # ── Security headers ──
    hdr_high = by_sev(headers, "High", "Critical")
    print(f"\033[93mSecurity Header Issues:\033[0m {len(headers)} total, {len(hdr_high)} high/critical")

    # ── Exploit chains ──
    if chains:
        print(f"\n\033[91m⚡ EXPLOIT CHAINS BUILT: {len(chains)}\033[0m")
        for c in chains[:3]:
            sev_c = "\033[91mCRITICAL\033[0m" if c.get("severity") == "Critical" else "\033[93mHIGH\033[0m"
            print(f"  [{sev_c}] {c.get('title', '')}  (risk={c.get('risk_score', 0)})")
            print(f"    MITRE: {c.get('mitre', 'N/A')}")

    # ── Critical secrets detail ──
    if top_sec:
        print("\n\033[91mTop Secrets:\033[0m")
        by_source = {}
        for s in top_sec:
            by_source.setdefault(s["source_url"], []).append(s)
        for i, (src, items) in enumerate(
            sorted(by_source.items(), key=lambda x: len(x[1]), reverse=True)[:3], 1
        ):
            types   = ", ".join(dict.fromkeys(s["type"] for s in items[:3]))
            sev_lbl = "\033[91mCRITICAL\033[0m" if any(s["severity"] == "Critical" for s in items) else "\033[93mHIGH\033[0m"
            print(f"  {i}. [{sev_lbl}] {src[:80]}")
            print(f"     {len(items)} secret(s): {types}")

    # ── Critical active vulns detail ──
    if crit_act or high_act:
        print("\n\033[91mTop Active Vulnerabilities:\033[0m")
        for a in (crit_act + high_act)[:4]:
            sev_lbl = "\033[91mCRITICAL\033[0m" if a.get("severity") == "Critical" else "\033[93mHIGH\033[0m"
            print(f"  [{sev_lbl}] {a.get('type', '')} @ {a.get('source_url', '')[:60]}")
            print(f"    Param: {a.get('parameter', '')}  Evidence: {a.get('evidence', '')[:60]}")

    # ── Confirmed SSRF ──
    if confirmed_ssrf:
        print("\n\033[91m⚠  CONFIRMED SSRF:\033[0m")
        for v in confirmed_ssrf[:2]:
            print(f"  • {v['source_url'][:80]}")
            print(f"    PoC: {v.get('poc', '')[:100]}")

    # ── Critical exposed endpoints ──
    if crit_exp:
        print("\n\033[91mCritical Exposed Endpoints:\033[0m")
        for e in crit_exp[:4]:
            print(f"  • \033[91m{e.get('url', '')[:80]}\033[0m  [{e.get('endpoint_type', '')}]")
            print(f"    {e.get('evidence', '')[:80]}")

    # ── Missing security headers ──
    if hdr_high:
        print("\n\033[93mMissing Critical Security Headers:\033[0m")
        for h in hdr_high[:4]:
            print(f"  • \033[93m{h['header_name']}\033[0m — {h.get('recommendation', '')}")

    saved_path = scanner._save_findings()
    if saved_path:
        print(f"\n\033[94mDetailed findings saved to:\033[0m {saved_path}")

    return results

@safe_module_execution(delay_type='heavy')
def safe_elite_api_scan(domain):
    """Elite Bug Bounty API Scanner wrapper - Compatible with existing module"""
    try:
        # Import mevcut modülden - eski yapıya uyumlu
        from modules.api_security_scanner import run_scanner
        import asyncio
        import nest_asyncio
        
        # Event loop sorunlarını çöz
        nest_asyncio.apply()
        
        print("\n" + "="*60)
        print(" ELITE BUG BOUNTY SCANNER")
        print(" Using Custom Payload Collection")
        print(" Target: " + domain)
        print("="*60)
        
        try:
            # Mevcut modül yapısını kullan
            scanner = run_scanner(domain, threads=30, aggressive=8)
            
            # Check if scanner is async (new version) or sync (old version)
            if hasattr(scanner, 'scan'):
                # New version - scanner object returned
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                
                try:
                    results = loop.run_until_complete(scanner.scan())
                finally:
                    loop.close()
            else:
                # Old version - results directly returned
                results = scanner
            
        except Exception as e:
            # Fallback: Try direct class instantiation
            print(f"[INFO] Trying alternative approach...")
            from modules.api_security_scanner import BugBountyScanner
            
            scanner_obj = BugBountyScanner(domain, threads=30, aggressive=8)
            
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            try:
                results = loop.run_until_complete(scanner_obj.scan())
            finally:
                loop.close()
        
        # Handle results regardless of format
        if isinstance(results, dict):
            # New format
            vulns = results.get('vulnerabilities', [])
            endpoints_found = results.get('endpoints_found', 0)
            endpoints_tested = results.get('endpoints_tested', 0)
        else:
            # Old format fallback
            vulns = getattr(results, 'vulnerabilities', [])
            endpoints_found = len(getattr(results, 'endpoints_found', []))
            endpoints_tested = endpoints_found
        
        # Process vulnerabilities
        critical = [v for v in vulns if v.get('severity') == 'CRITICAL']
        high = [v for v in vulns if v.get('severity') == 'HIGH']
        medium = [v for v in vulns if v.get('severity') == 'MEDIUM']
        low = [v for v in vulns if v.get('severity') == 'LOW']
        
        # Calculate risk metrics
        risk_score = calculate_risk_score(len(critical), len(high), len(medium), len(low))
        security_grade = get_security_grade(risk_score)
        
        # Enhanced summary
        print("\n" + "="*40)
        print(" SCAN SUMMARY")
        print("="*40)
        print(f" Endpoints Found: {endpoints_found}")
        print(f" Endpoints Tested: {endpoints_tested}")
        print(f" Total Vulnerabilities: {len(vulns)}")
        print(f" Risk Score: {risk_score}/100")
        print(f" Security Grade: {security_grade}")
        
        # Vulnerability breakdown
        if critical:
            print(f"\n CRITICAL: {len(critical)} vulnerabilities")
            for vuln in critical[:3]:
                vuln_type = vuln.get('type', 'Unknown')
                endpoint = vuln.get('endpoint', '')[:50]
                print(f"  • {vuln_type}: {endpoint}")
            if len(critical) > 3:
                print(f"  • ... and {len(critical) - 3} more")
                
        if high:
            print(f"\n HIGH: {len(high)} vulnerabilities")
            for vuln in high[:2]:
                vuln_type = vuln.get('type', 'Unknown')
                endpoint = vuln.get('endpoint', '')[:50]
                print(f"  • {vuln_type}: {endpoint}")
            if len(high) > 2:
                print(f"  • ... and {len(high) - 2} more")
        
        if medium:
            print(f"\n MEDIUM: {len(medium)} vulnerabilities")
        
        if low:
            print(f"\n LOW: {len(low)} vulnerabilities")
        
        # Return standardized format
        return {
            'target': domain,
            'endpoints_found': endpoints_found,
            'endpoints_tested': endpoints_tested,
            'vulnerabilities': vulns,
            'risk_metrics': {
                'risk_score': risk_score,
                'security_grade': security_grade,
                'vulnerability_breakdown': {
                    'critical': len(critical),
                    'high': len(high), 
                    'medium': len(medium),
                    'low': len(low)
                }
            }
        }
        
    except ImportError as e:
        error_msg = f"Module import failed: {str(e)}"
        print(f"[ERROR] {error_msg}")
        print("[INFO] Available functions in module:")
        try:
            import modules.api_security_scanner as scanner_module
            available_functions = [name for name in dir(scanner_module) if not name.startswith('_')]
            print(f"[INFO] Functions: {', '.join(available_functions)}")
        except:
            pass
        return {"error": error_msg}
        
    except Exception as e:
        error_msg = f"Scanner execution failed: {str(e)}"
        print(f"[ERROR] {error_msg}")
        import traceback
        traceback.print_exc()
        return {"error": error_msg}

def calculate_risk_score(critical, high, medium, low):
    """Risk skoru hesapla"""
    score = (critical * 30) + (high * 20) + (medium * 10) + (low * 5)
    return min(score, 100)

def get_security_grade(score):
    """Güvenlik notu belirle"""
    if score == 0:
        return "A+"
    elif score <= 10:
        return "A"
    elif score <= 25:
        return "B"
    elif score <= 50:
        return "C"  
    elif score <= 75:
        return "D"
    else:
        return "F"

@safe_module_execution(delay_type='heavy')
def safe_contact_spy(domain):
    """Safe wrapper for contact information discovery"""
    try:
        # Suppress SSL warnings
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        contact_scraper = GlobalDomainScraper(domain, max_pages=15, log_dir="logs")
        contact_results = contact_scraper.crawl()
        
        if "error" in contact_results:
            print(f"\033[91m[ERROR] Contact scan failed: {contact_results['error']}\033[0m")
            return contact_results
        
        # Display results
        summary = contact_results.get('summary', {})
        pages_scanned = contact_results.get('pages_scanned', 0)
        
        print(f"\n\033[94mPages Scanned:\033[0m {pages_scanned}")
        print(f"\033[94mEmails Found:\033[0m {summary.get('total_emails', 0)}")
        print(f"\033[94mPhones Found:\033[0m {summary.get('total_phones', 0)}")
        print(f"\033[94mSocial Media Profiles:\033[0m {summary.get('total_social_media', 0)}")
        
        # Show unique emails
        unique_emails = summary.get('unique_emails', [])
        if unique_emails:
            print(f"\n\033[92m📧 Email Addresses:\033[0m")
            for email in unique_emails:
                print(f"  • {email}")
        
        # Show unique phones
        unique_phones = summary.get('unique_phones', [])
        if unique_phones:
            print(f"\n\033[92m📞 Phone Numbers:\033[0m")
            for phone in unique_phones:
                print(f"  • {phone}")
        
        # Show social media by platform
        social_by_platform = contact_results.get('social_media_by_platform', {})
        if social_by_platform:
            print(f"\n\033[92m🌐 Social Media Profiles:\033[0m")
            for platform, profiles in social_by_platform.items():
                print(f"  \033[93m{platform}:\033[0m")
                for profile in profiles[:3]:  # Show first 3 per platform
                    print(f"    • @{profile['username']} - {profile['url']}")
                if len(profiles) > 3:
                    print(f"    • ... and {len(profiles) - 3} more")
        
        # Export results
        contact_scraper.export_results(contact_results, output_format='json')
        print(f"\n\033[94mDetailed results saved to:\033[0m logs/{domain}/contact_scan.json")
        
        return contact_results
    
    except Exception as e:
        print(f"\033[91m[ERROR] Unexpected error in Contact Scan: {str(e)}\033[0m")
        return {"error": str(e)}

@safe_module_execution(delay_type='heavy')
def safe_subdomain_discovery(domain):
    """Safe wrapper for subdomain discovery"""
    subdomains = run_subfinder(domain)

    if subdomains:
        print(f"\033[94mTotal Subdomains Found:\033[0m {len(subdomains)}")
        print(f"\033[94mSaved to File:\033[0m subdomains_{domain}.txt")
        
        # Display first 10 subdomains
        print(f"\033[94mFirst 10 Subdomains:\033[0m")
        for i, subdomain in enumerate(subdomains[:10], 1):
            print(f"  {i}. {subdomain}")
        if len(subdomains) > 10:
            print(f"  ... and {len(subdomains) - 10} more")
    else:
        print("\033[91mNo subdomains found or Subfinder could not be executed.\033[0m")
    
    return subdomains

@safe_module_execution(delay_type='heavy')
def safe_subdomain_takeover(domain):
    """Safe wrapper for subdomain takeover analysis"""
    # First get subdomains
    subdomains = run_subfinder(domain)
    
    if not subdomains:
        print(f"No subdomains provided for {domain}")
        return {"error": "No subdomains provided", "domain": domain}

    print(f"Starting subdomain takeover module for {domain}")
    
    scanner = SubdomainTakeover(
        domain,
        logger=None,
        output_dir=f"logs/{domain}",
        timeout=10,
        max_workers=20,
        verify_ssl=False
    )

    results = scanner.scan(subdomains)

    # Display results
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
                    print(f"  \033[91m{subdomain['subdomain']}\033[0m - {subdomain['vulnerability_type']} ({subdomain['service']})")
                    print(f"    → \033[93mExploitation Difficulty:\033[0m {subdomain['exploitation_difficulty']}")
                    print(f"    → \033[92mMitigation:\033[0m {subdomain['mitigation']}")

        print(f"\n\033[94mDetailed results saved to:\033[0m logs/{domain}/takeover_summary_{domain}.json")
    else:
        print("\n\033[92mNo subdomain takeover vulnerabilities found.\033[0m")

    return results

@safe_module_execution(delay_type='heavy')
async def safe_nmap_scan(domain):
    """Safe wrapper for Nmap zero-day scanning"""
    print("Starting scan...")
    
    try:
        scanner = UltraAdvancedNetworkScanner(domain=domain, timeout=10, aggressive_mode=False)
        start_time = time.time()
       
        scan_results = await scanner.run_comprehensive_scan(domain)
       
        # Display results
        print("\nOpen Ports and Services:")
        for port in scan_results['port_scan'].get('open_ports', []):
            service = scan_results['port_scan']['services'][port]
            print(f"  - Port: {port}, Service: {service['service']}, Version: {service['version']}, State: {service.get('state', 'open')}")
       
        print("\nZero-Day Vulnerabilities:")
        for vuln in scan_results['zero_day_vulnerabilities']:
            print(f"  - {vuln.get('id', 'N/A')}: {vuln.get('description', 'No details available')} (Severity: {vuln.get('severity', {}).get('level', 'Unknown')})")
       
        execution_time = time.time() - start_time
        print(f"\nScan completed in {execution_time:.2f} seconds")
        
        return scan_results

    except Exception as e:
        print(f"[ERROR] An error occurred: {str(e)}")
        return {"error": str(e)}

def select_modules():
    """Module selection interface"""
    modules = [
        "Domain Information",
        "DNS Records", 
        "Nmap Zero Day Scan",
        "SEO Analysis",
        "Web Technologies",
        "Security Analysis",
        "Advanced Content Scan",
        "API Security Scanner",
        "Contact Spy",
        "Subdomain Discovery",
        "Subdomain Takeover",
        "CloudFlare Bypass",
        "GEO Analysis"
    ]

    print("\033[93m" + "=" * 50 + "\033[0m")
    print("\033[93m>>>        MODULE SELECTION MENU        <<<\033[0m")
    print("\033[93m" + "=" * 50 + "\033[0m")

    for i, module in enumerate(modules, 1):
        print(f"\033[94m[{i}] {module}\033[0m")

    print("\033[94m[A] Run ALL Modules\033[0m")
    print("\033[94m[Q] Quit\033[0m")

    while True:
        choice = input(
            "\033[92mEnter module numbers (comma-separated) or 'A' for all, 'Q' to quit: \033[0m"
        ).upper().strip()

        if choice == 'Q':
            print("\033[91mExiting module selection.\033[0m")
            return [], False

        if choice == 'A':
            print("\033[92m[✔] All modules selected!\033[0m")
            return modules, True

        try:
            selected_numbers = [num.strip() for num in choice.split(',')]
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
                if selected_modules:
                    print("\033[92m[✔] Modules selected successfully:\033[0m")
                    for module in selected_modules:
                        print(f"\033[94m- {module}\033[0m")
                    return selected_modules, False

        except Exception:
            print("\033[91m[✘] Invalid input. Please enter valid module numbers.\033[0m")

async def execute_modules_with_display(domain, selected_modules):
    """Execute modules and display results inline"""
    results = {}
    executor = ModuleExecutor()
    
    # Module function mapping
    module_functions = {
        "Domain Information": safe_get_domain_info,
        "DNS Records": safe_dns_analysis,
        "SEO Analysis": safe_seo_analysis,
        "Web Technologies": safe_web_technologies,
        "Security Analysis": safe_security_analysis,
        "Advanced Content Scan": safe_advanced_content_scan,
        "API Security Scanner": safe_elite_api_scan,
        "Contact Spy": safe_contact_spy,
        "Subdomain Discovery": safe_subdomain_discovery,
        "Subdomain Takeover": safe_subdomain_takeover,
        "CloudFlare Bypass": safe_cloudflare_bypass,
        "Nmap Zero Day Scan": safe_nmap_scan,
        "GEO Analysis": safe_geo_analysis,
    }
    
    # Module weights for delay calculation
    module_weights = {
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
        'GEO Analysis': 'medium',
    }
    
    print(f"\n🚀 Starting analysis for: {domain}")
    print(f"📋 Modules to execute: {len(selected_modules)}")
    print("🛡️  IP rotation and rate limiting protection enabled!")
    print("=" * 60)
    
    for i, module_name in enumerate(selected_modules, 1):
        if module_name in module_functions:
            print(f"\n\033[93m{'='*50}\033[0m")
            print(f"\033[93m[{i}/{len(selected_modules)}] --- {module_name.upper()} ---\033[0m")
            print(f"\033[93m{'='*50}\033[0m")
            
            # Get delay type for this module
            delay_type = module_weights.get(module_name, 'medium')
            
            # Execute module with inline result display
            if module_name == "Nmap Zero Day Scan":
                result = await module_functions[module_name](domain)
            else:
                result = module_functions[module_name](domain)
            
            results[module_name] = result
            
            # Show progress
            progress = (i / len(selected_modules)) * 100
            print(f"\n✅ Progress: {progress:.1f}% ({i}/{len(selected_modules)})")
            
            # Inter-module delay handled by the safe wrappers
        else:
            logger.warning(f"Module function not found for: {module_name}")
    
    # Final summary
    summary = executor.get_execution_summary()
    print("\n" + "=" * 60)
    print("📊 EXECUTION SUMMARY")
    print("=" * 60)
    print(f"✅ Successful modules: {summary.get('successful', len(selected_modules))}")
    print(f"❌ Failed modules: {summary.get('failed', 0)}")
    print(f"⏱️  Total modules: {len(selected_modules)}")
    
    # Cleanup
    executor.cleanup()
    
    return results

async def main():
    """Main application entry point"""
    # Clear terminal and display banner
    clear_terminal()
    display_banner()

    # Check modules
    if not _check_modules():
        print("\033[91m[✘] Some modules are missing. Please install required modules.\033[0m")
        return

    print("\033[92m[✔] All required modules loaded successfully!\033[0m")
    print("\033[94m🛡️  Advanced IP rotation and rate limiting protection enabled!\033[0m\n")

    # Get domain input
    domain = input("\033[92mPlease enter a domain name (e.g., example.com): \033[0m").strip()
    
    if not domain:
        print("\033[91m[✘] No domain provided. Exiting.\033[0m")
        return

    # Select modules
    selected_modules, run_all = select_modules()
    if not selected_modules:
        return

    # Execute modules with inline display and IP rotation
    print(f"\n🔒 Starting secure analysis with IP rotation protection...")
    results = await execute_modules_with_display(domain, selected_modules)
    
    # Save results to JSON
    try:
        save_results_to_json(domain, results)
        print(f"\n💾 Results saved to: logs/{domain}/results.json")
    except Exception as e:
        logger.error(f"Failed to save results: {e}")
    
    print(f"\n🎉 Analysis completed for {domain}!")
    print("🛡️  IP rotation and rate limiting protection was active throughout the scan.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\033[91m[✘] Analysis interrupted by user.\033[0m")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        print(f"\033[91m[✘] An unexpected error occurred: {e}\033[0m")
    finally:
        # Cleanup
        if SESSION_MANAGER_AVAILABLE:
            try:
                from utils.session_manager import close_session_manager
                close_session_manager()
            except Exception:
                pass
        print("🧹 Cleanup completed.")
