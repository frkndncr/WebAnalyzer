from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.responses import PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import os
import json
import asyncio

# WebAnalyzer dependencies
from utils.utils import save_results_to_json
from utils.module_wrapper import execute_modules_safely, ModuleExecutor

# Modules
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
from modules.archive_spy import ArchiveSpy
from modules.phishing_detector import PhishingDetector
from modules.ssl_association import SSLAssociation
from modules.attack_path_planner import AttackPathPlanner

app = FastAPI(title="WebAnalyzer API", description="FastAPI Backend for WebAnalyzer React Panel")

# Add CORS so React frontend can fetch
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global dictionary to track active scans
ACTIVE_SCANS = {}

class ScanRequest(BaseModel):
    domain: str
    modules: list[str]

# Dictionary of modules manually replicated from main.py
def get_safe_wrapper(module_func):
    async def wrapper(domain):
        return module_func(domain)
    return wrapper

@app.get("/api/results/{domain}")
async def get_results(domain: str):
    """Retrieve saved JSON results for a domain"""
    result_path = os.path.join("logs", domain, "results.json")
    if os.path.exists(result_path):
        with open(result_path, "r", encoding="utf-8") as f:
            return json.load(f)
    raise HTTPException(status_code=404, detail="Results not found")

@app.get("/api/status/{domain}")
async def get_status(domain: str):
    """Retrieve realtime progression status of a scan"""
    if domain in ACTIVE_SCANS:
        return ACTIVE_SCANS[domain]
    
    result_path = os.path.join("logs", domain, "results.json")
    if os.path.exists(result_path):
        try:
            with open(result_path, "r", encoding="utf-8") as f:
                saved = json.load(f)
            scan_info = saved.get("scan_info", {})
            return {
                "total": scan_info.get("total_modules", 1),
                "completed": scan_info.get("successful_modules", 1),
                "current_module": "Finished",
                "results": saved.get("results", {})
            }
        except Exception:
            return {"total": 1, "completed": 1, "current_module": "Finished", "results": {}}
        
    raise HTTPException(status_code=404, detail="Scan not found or not active")

@app.post("/api/scan")
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Starts an background scan and returns immediately"""
    
    # Redefine the dictionary to pass to execute_modules_safely
    module_functions = {
        "Domain Information": lambda d: get_domain_info(d),
        "DNS Records": lambda d: DNSAnalyzer().get_dns_records(d),
        "SEO Analysis": analyze_advanced_seo,
        "Web Technologies": detect_web_technologies,
        "Security Analysis": analyze_security,
        "Advanced Content Scan": lambda d: AdvancedContentScanner(d).run(),
        "Contact Spy": lambda d: GlobalDomainScraper(d).crawl(),
        "Subdomain Discovery": lambda d: run_subfinder(d),
        "Subdomain Takeover": lambda d: SubdomainTakeover(d).run(run_subfinder(d)),
        "CloudFlare Bypass": lambda d: CloudflareBypass(d).run(),
        "Nmap Zero Day Scan": lambda d: UltraAdvancedNetworkScanner(domain=d).run_comprehensive_scan(d),
        "GEO Analysis": analyze_geo,
        "Web Archive Spy": lambda d: ArchiveSpy(d).run(),
        "Phishing Domain Protection": lambda d: PhishingDetector(d).run(),
        "SSL SAN Association": lambda d: SSLAssociation(d).run(),
        "Attack Path Planner": lambda d: AttackPathPlanner(d).run()
    }
    
    # Initialize the memory state for tracking
    ACTIVE_SCANS[request.domain] = {
        "total": len(request.modules),
        "completed": 0,
        "current_module": "Initializing...",
        "results": {}
    }
    
    # We will submit a background task to process
    background_tasks.add_task(run_scan_background, request.domain, request.modules, module_functions)
    
    return {"status": "Scan started via Background Task", "domain": request.domain, "modules": request.modules}


async def run_scan_background(domain: str, selected_modules: list[str], module_functions: dict):
    """Background task function to avoid blocking the HTTP request"""
    executor = ModuleExecutor()
    results = {}
    
    module_weights = {
        'Domain Information': 'light', 'DNS Records': 'light', 
        'SEO Analysis': 'medium', 'Web Technologies': 'medium',
        'Security Analysis': 'heavy', 'Advanced Content Scan': 'heavy',
        'Contact Spy': 'heavy', 'Subdomain Discovery': 'heavy',
        'Subdomain Takeover': 'heavy', 'CloudFlare Bypass': 'heavy',
        'Nmap Zero Day Scan': 'heavy', 'GEO Analysis': 'light',
        'Web Archive Spy': 'heavy', 'Phishing Domain Protection': 'heavy',
        'SSL SAN Association': 'medium', 'Attack Path Planner': 'medium'
    }
    
    for module_name in selected_modules:
        if module_name in module_functions:
            ACTIVE_SCANS[domain]["current_module"] = module_name
            func = module_functions[module_name]
            delay_type = module_weights.get(module_name, 'medium')
            
            # For simplicity, we just safely execute it synchronously here
            try:
                if asyncio.iscoroutinefunction(func):
                    res = await func(domain)
                else:
                    res = func(domain)
                    if asyncio.iscoroutine(res):
                        res = await res
                results[module_name] = res
                ACTIVE_SCANS[domain]["results"][module_name] = res
            except Exception as e:
                results[module_name] = {"error": str(e)}
                ACTIVE_SCANS[domain]["results"][module_name] = {"error": str(e)}
                
            ACTIVE_SCANS[domain]["completed"] += 1

    ACTIVE_SCANS[domain]["current_module"] = "Writing to disk..."
    # Save logic directly to logs/domain/results.json
    save_results_to_json(domain, results)
    
    ACTIVE_SCANS[domain]["current_module"] = "Finished"
    executor.cleanup()


# ─── Advanced Content Scanner per-section scanning ───

class ACSSectionRequest(BaseModel):
    domain: str
    section: str

class ACSAllRequest(BaseModel):
    domain: str

ACS_SECTION_TASKS = {}

@app.post("/api/scan/section")
async def scan_acs_section(request: ACSSectionRequest, background_tasks: BackgroundTasks):
    """Run a single ACS section for a domain"""
    task_key = f"{request.domain}::{request.section}"
    ACS_SECTION_TASKS[task_key] = {"status": "running", "result": None, "error": None}
    background_tasks.add_task(_run_acs_section, request.domain, request.section, task_key)
    return {"status": "started", "section": request.section}

@app.get("/api/scan/section/status")
async def acs_section_status(domain: str, section: str):
    """Check status of a single ACS section scan"""
    task_key = f"{domain}::{section}"
    if task_key in ACS_SECTION_TASKS:
        return ACS_SECTION_TASKS[task_key]
    raise HTTPException(status_code=404, detail="Section task not found")

@app.post("/api/scan/acs-all")
async def scan_acs_all(request: ACSAllRequest, background_tasks: BackgroundTasks):
    """Run the full Advanced Content Scanner"""
    task_key = f"{request.domain}::acs_full"
    ACS_SECTION_TASKS[task_key] = {"status": "running", "result": None, "error": None}
    background_tasks.add_task(_run_acs_full, request.domain, task_key)
    return {"status": "started", "domain": request.domain}

@app.get("/api/scan/acs-all/status")
async def acs_all_status(domain: str):
    """Check full ACS scan status"""
    task_key = f"{domain}::acs_full"
    if task_key in ACS_SECTION_TASKS:
        return ACS_SECTION_TASKS[task_key]
    raise HTTPException(status_code=404, detail="ACS scan not found")

def _run_acs_section(domain: str, section: str, task_key: str):
    """Background: run a single ACS conceptual section"""
    try:
        scanner = AdvancedContentScanner(domain)
        # Map section IDs to scanner methods
        section_map = {
            "overview": lambda s: {"version": s.VERSION, "domain": s.domain, "status": "ready"},
            "data_classes": lambda s: {"classes": ["SecretFinding", "JSVulnFinding", "SSRFVulnFinding", "ActiveVulnFinding", "SecurityHeaderFinding", "ExposedEndpoint"], "status": "inspected"},
            "pattern_registry": lambda s: {"secret_patterns": len(s.patterns.SECRETS), "js_categories": len(s.patterns.JS_SECURITY), "ssrf_params": len(s.patterns.SSRF_PARAMS), "sensitive_paths": len(s.patterns.SENSITIVE_PATHS), "status": "loaded"},
            "crawl_engine": lambda s: _run_crawl(s),
            "secret_scanner": lambda s: {"secrets": s.findings.get("secrets", []), "total": len(s.findings.get("secrets", [])), "status": "scanned"},
            "js_analysis": lambda s: {"js_vulnerabilities": s.findings.get("js_vulnerabilities", []), "total": len(s.findings.get("js_vulnerabilities", [])), "status": "analyzed"},
            "ssrf_detection": lambda s: {"ssrf_vulnerabilities": s.findings.get("ssrf_vulnerabilities", []), "total": len(s.findings.get("ssrf_vulnerabilities", [])), "status": "probed"},
            "active_testing": lambda s: _run_active(s),
            "headless_browser": lambda s: _run_headless(s),
            "exploit_chains": lambda s: _run_chains(s),
            "waf_detection": lambda s: _run_waf(s),
            "utilities": lambda s: {"helpers": ["_entropy", "_mask", "_shash", "_fp_value", "_fp_context", "_sev_passes", "_is_new", "_next_id", "_risk_score"], "status": "ready"},
            "main_flow": lambda s: _run_full_flow(s),
        }
        
        if section in section_map:
            result = section_map[section](scanner)
            ACS_SECTION_TASKS[task_key] = {"status": "completed", "result": result, "error": None}
        else:
            ACS_SECTION_TASKS[task_key] = {"status": "error", "result": None, "error": f"Unknown section: {section}"}
    except Exception as e:
        ACS_SECTION_TASKS[task_key] = {"status": "error", "result": None, "error": str(e)}


def _run_crawl(scanner):
    duration = scanner.crawl_website()
    return {
        "urls_crawled": len(scanner.visited_urls),
        "js_files": len(scanner.js_files),
        "api_endpoints": len(scanner.api_endpoints),
        "secrets": len(scanner.findings.get("secrets", [])),
        "js_vulnerabilities": len(scanner.findings.get("js_vulnerabilities", [])),
        "security_headers": len(scanner.findings.get("security_headers", [])),
        "duration": duration,
        "status": "crawled",
    }

def _run_active(scanner):
    scanner.crawl_website()
    if hasattr(scanner, '_scan_sensitive_paths'):
        scanner._scan_sensitive_paths()
    if hasattr(scanner, '_test_cors'):
        scanner._test_cors()
    if hasattr(scanner, '_test_auth_bypass'):
        scanner._test_auth_bypass()
    return {
        "active_vulnerabilities": [f.__dict__ if hasattr(f, '__dict__') else f for f in scanner.findings.get("active_vulnerabilities", [])],
        "exposed_endpoints": [f.__dict__ if hasattr(f, '__dict__') else f for f in scanner.findings.get("exposed_endpoints", [])],
        "total_active": len(scanner.findings.get("active_vulnerabilities", [])),
        "total_exposed": len(scanner.findings.get("exposed_endpoints", [])),
        "status": "tested",
    }

def _run_headless(scanner):
    scanner.crawl_website()
    if hasattr(scanner, '_run_headless_scan'):
        scanner._run_headless_scan()
    return {
        "dynamic_routes": list(getattr(scanner, '_dynamic_routes', set())),
        "status": "scanned",
    }

def _run_chains(scanner):
    scanner.crawl_website()
    if hasattr(scanner, '_build_exploit_chains'):
        scanner._build_exploit_chains()
    return {
        "exploit_chains": scanner.findings.get("exploit_chains", []),
        "total": len(scanner.findings.get("exploit_chains", [])),
        "status": "built",
    }

def _run_waf(scanner):
    # Must crawl first — WAF headers are often only on internal pages, not the base URL
    scanner.crawl_website()
    waf = getattr(scanner, '_detected_waf', None)
    blocked = getattr(scanner, '_waf_triggered_count', 0) > 0
    return {
        "detected_waf": waf or "Not Detected",
        "is_blocked": blocked,
        "rate_limit": scanner.rate_limit,
        "pages_scanned": len(scanner.visited_urls),
        "status": "detected",
    }

def _run_full_flow(scanner):
    results = scanner.run()
    return results

def _run_acs_full(domain: str, task_key: str):
    """Background: run the entire ACS pipeline"""
    try:
        scanner = AdvancedContentScanner(domain)
        results = scanner.run()
        ACS_SECTION_TASKS[task_key] = {"status": "completed", "result": results, "error": None}
    except Exception as e:
        ACS_SECTION_TASKS[task_key] = {"status": "error", "result": None, "error": str(e)}

@app.get("/api/recent-scans")
async def get_recent_scans():
    """Retrieve list of recently scanned domains with their summary"""
    from datetime import datetime
    scans = []
    logs_dir = "logs"
    if os.path.exists(logs_dir):
        for domain in os.listdir(logs_dir):
            domain_path = os.path.join(logs_dir, domain)
            if os.path.isdir(domain_path):
                result_file = os.path.join(domain_path, "results.json")
                if os.path.exists(result_file):
                    try:
                        mtime = os.path.getmtime(result_file)
                        scan_date = datetime.fromtimestamp(mtime).isoformat()
                        
                        with open(result_file, "r", encoding="utf-8") as f:
                            raw_res = json.load(f)
                        res = raw_res.get("results", raw_res) if isinstance(raw_res, dict) else {}
                        sec_res = res.get("Security Analysis", {})
                        score = sec_res.get("security_score", None) if isinstance(sec_res, dict) else None
                        grade = sec_res.get("security_grade", None) if isinstance(sec_res, dict) else None
                        vuln_count = sec_res.get("vulnerabilities_found", 0) if isinstance(sec_res, dict) else 0
                        
                        scans.append({
                            "domain": domain,
                            "scan_date": scan_date,
                            "score": score,
                            "grade": grade,
                            "vulnerabilities": vuln_count
                        })
                    except Exception:
                        pass
    scans.sort(key=lambda x: x["scan_date"], reverse=True)
    return scans[:20]

@app.get("/api/stats")
async def get_global_stats():
    """Retrieve global system statistics from DB (or logs fallback)"""
    try:
        from database.db_manager import db_manager
        # Attempt to run query. If DB is offline, this will raise error.
        stats = db_manager.execute_query("SELECT COUNT(*) as total_jobs, SUM(total_domains) as total_domains FROM scan_jobs", commit=False)
        vulns = db_manager.execute_query("SELECT COUNT(*) as count FROM vulnerabilities", commit=False)
        
        return {
            "source": "database",
            "total_jobs": stats[0]["total_jobs"] if stats else 0,
            "total_domains": stats[0]["total_domains"] if stats else 0,
            "total_vulnerabilities": vulns[0]["count"] if vulns else 0,
            "status": "connected"
        }
    except Exception:
        total_scans = 0
        logs_dir = "logs"
        if os.path.exists(logs_dir):
            total_scans = len([d for d in os.listdir(logs_dir) if os.path.isdir(os.path.join(logs_dir, d))])
        return {
            "source": "logs",
            "total_jobs": 0,
            "total_domains": total_scans,
            "total_vulnerabilities": 0,
            "status": "standalone",
            "note": "DB connection offline, showing local logs cache"
        }

@app.get('/api/threat-intel/{domain}')
async def get_threat_intel(domain: str, background_tasks: BackgroundTasks, force: bool = False):
    """Extract comprehensive threat intelligence from all scan modules"""
    result_path = os.path.join('logs', domain, 'results.json')
    intel = {
        'domain': domain,
        'mitre_techniques': [],
        'iocs': [],
        'cves': [],
        'risk_score': 0,
        'security_grade': None,
        'attack_surface': 0,
        'vuln_density': 0,
        'exposure_level': 0,
        'scan_date': None,
        'has_data': False,
        'attack_path': {'graph': {'nodes': [], 'edges': []}, 'exploit_chains': []},
        'archive_secrets': [],
        'is_scanning': False,
        'scan_progress': None,
    }

    should_trigger = False
    if force or not os.path.exists(result_path):
        should_trigger = True
    else:
        try:
            with open(result_path, 'r', encoding='utf-8') as f:
                raw_res = json.load(f)
            res = raw_res.get('results', raw_res) if isinstance(raw_res, dict) else {}
            if not res or not isinstance(res, dict):
                should_trigger = True
        except Exception:
            should_trigger = True

    if should_trigger:
        if os.path.exists(result_path):
            try:
                os.remove(result_path)
            except Exception:
                pass
        
        if domain in ACTIVE_SCANS:
            if ACTIVE_SCANS[domain].get('current_module') == 'Finished':
                ACTIVE_SCANS.pop(domain, None)
            else:
                intel['is_scanning'] = True
                intel['scan_progress'] = {
                    'total': ACTIVE_SCANS[domain].get('total', 16),
                    'completed': ACTIVE_SCANS[domain].get('completed', 0),
                    'current_module': ACTIVE_SCANS[domain].get('current_module', 'Initializing...')
                }
                return intel

        if domain not in ACTIVE_SCANS:
            modules_list = [
                "Domain Information", "DNS Records", "SEO Analysis", "Web Technologies",
                "Security Analysis", "Advanced Content Scan", "Contact Spy", "Subdomain Discovery",
                "Subdomain Takeover", "CloudFlare Bypass", "Nmap Zero Day Scan", "GEO Analysis",
                "Web Archive Spy", "Phishing Domain Protection", "SSL SAN Association", "Attack Path Planner"
            ]
            module_functions = {
                "Domain Information": lambda d: get_domain_info(d),
                "DNS Records": lambda d: DNSAnalyzer().get_dns_records(d),
                "SEO Analysis": analyze_advanced_seo,
                "Web Technologies": detect_web_technologies,
                "Security Analysis": analyze_security,
                "Advanced Content Scan": lambda d: AdvancedContentScanner(d).run(),
                "Contact Spy": lambda d: GlobalDomainScraper(d).crawl(),
                "Subdomain Discovery": lambda d: run_subfinder(d),
                "Subdomain Takeover": lambda d: SubdomainTakeover(d).run(run_subfinder(d)),
                "CloudFlare Bypass": lambda d: CloudflareBypass(d).run(),
                "Nmap Zero Day Scan": lambda d: UltraAdvancedNetworkScanner(domain=d).run_comprehensive_scan(d),
                "GEO Analysis": analyze_geo,
                "Web Archive Spy": lambda d: ArchiveSpy(d).run(),
                "Phishing Domain Protection": lambda d: PhishingDetector(d).run(),
                "SSL SAN Association": lambda d: SSLAssociation(d).run(),
                "Attack Path Planner": lambda d: AttackPathPlanner(d).run()
            }
            ACTIVE_SCANS[domain] = {
                "total": len(modules_list),
                "completed": 0,
                "current_module": "Initializing Auto Scan...",
                "results": {}
            }
            background_tasks.add_task(run_scan_background, domain, modules_list, module_functions)
            intel['is_scanning'] = True
            intel['scan_progress'] = {
                'total': len(modules_list),
                'completed': 0,
                'current_module': 'Initializing Auto Scan...'
            }
        return intel

    try:
        mtime = os.path.getmtime(result_path)
        from datetime import datetime
        intel['scan_date'] = datetime.fromtimestamp(mtime).isoformat()
    except Exception:
        pass

    with open(result_path, 'r', encoding='utf-8') as f:
        raw_res = json.load(f)
    res = raw_res.get('results', raw_res) if isinstance(raw_res, dict) else {}

    intel['has_data'] = True

    # ── Security Analysis → CVEs + risk score ──
    sec = res.get('Security Analysis', {})
    if isinstance(sec, dict):
        score_val = sec.get('security_score', 0)
        if isinstance(score_val, dict):
            intel['risk_score'] = score_val.get('overall_score', 0)
            intel['security_grade'] = score_val.get('grade', None)
        else:
            intel['risk_score'] = score_val
            intel['security_grade'] = sec.get('security_grade', None)
        vulns = sec.get('vulnerabilities', [])
        if isinstance(vulns, list):
            for v in vulns:
                if isinstance(v, dict):
                    sev = (v.get('severity', 'Medium') or 'Medium').upper()
                    intel['cves'].append({
                        'id': v.get('type', v.get('title', 'Unknown')),
                        'severity': sev,
                        'cvss': 9.5 if sev == 'CRITICAL' else 7.5 if sev == 'HIGH' else 5.0 if sev == 'MEDIUM' else 2.5,
                        'description': v.get('description', v.get('detail', '')),
                        'status': 'Detected',
                    })

    # ── Advanced Content Scan → more CVEs + IOCs ──
    acs = res.get('Advanced Content Scan', {})
    if isinstance(acs, dict):
        for key in ['secrets', 'js_vulnerabilities', 'active_vulnerabilities', 'ssrf_vulnerabilities']:
            findings = acs.get(key, [])
            if isinstance(findings, list):
                for f in findings:
                    if isinstance(f, dict):
                        sev = (f.get('severity', 'Medium') or 'Medium').upper()
                        intel['cves'].append({
                            'id': f.get('type', f.get('vuln_type', key.replace('_', ' ').title())),
                            'severity': sev,
                            'cvss': 9.5 if sev == 'CRITICAL' else 7.5 if sev == 'HIGH' else 5.0 if sev == 'MEDIUM' else 2.5,
                            'description': f.get('description', f.get('value', '')),
                            'status': 'Confirmed' if f.get('confirmed') else 'Detected',
                        })
                        # Extract IOCs from findings
                        url = f.get('source_url', f.get('url', ''))
                        if url:
                            intel['iocs'].append({
                                'type': 'URL',
                                'value': url[:80],
                                'confidence': 85 if sev in ('CRITICAL', 'HIGH') else 60,
                                'firstSeen': intel['scan_date'] or '',
                                'source': 'WebAnalyzer ACS',
                            })
        # Exposed endpoints as IOCs
        for ep in acs.get('exposed_endpoints', []):
            if isinstance(ep, dict):
                intel['iocs'].append({
                    'type': 'URL',
                    'value': ep.get('url', ep.get('path', ''))[:80],
                    'confidence': 90,
                    'firstSeen': intel['scan_date'] or '',
                    'source': 'Sensitive Path Scanner',
                })

    # ── Nmap → IOCs (open ports / IPs) ──
    nmap = res.get('Nmap Zero Day Scan', {})
    if isinstance(nmap, dict):
        for port_info in nmap.get('open_ports', nmap.get('ports', [])):
            if isinstance(port_info, dict):
                ip = port_info.get('ip', port_info.get('host', ''))
                if ip:
                    intel['iocs'].append({
                        'type': 'IP Address',
                        'value': f"{ip}:{port_info.get('port', '?')}",
                        'confidence': 95,
                        'firstSeen': intel['scan_date'] or '',
                        'source': 'Nmap Port Scanner',
                    })

    # ── Contact Spy → email IOCs ──
    contact = res.get('Contact Spy', {})
    if isinstance(contact, dict):
        for email in contact.get('emails', []):
            if isinstance(email, str):
                intel['iocs'].append({'type': 'Email', 'value': email, 'confidence': 70, 'firstSeen': intel['scan_date'] or '', 'source': 'Contact Spy'})

    # ── Subdomain Takeover → IOCs ──
    takeover = res.get('Subdomain Takeover', {})
    if isinstance(takeover, dict):
        for sub in takeover.get('vulnerable_subdomains', takeover.get('results', [])):
            if isinstance(sub, dict):
                intel['iocs'].append({
                    'type': 'Domain',
                    'value': sub.get('subdomain', sub.get('domain', '')),
                    'confidence': 95,
                    'firstSeen': intel['scan_date'] or '',
                    'source': 'Subdomain Takeover',
                })

    # ── Web Archive Spy → historical secrets ──
    archive = res.get('Web Archive Spy', {})
    if isinstance(archive, dict) and 'secrets' in archive:
        intel['archive_secrets'] = archive['secrets']
        # Also expose found secrets as CVEs / findings
        for sec_item in archive['secrets']:
            intel['cves'].append({
                'id': sec_item.get('type', 'Historical Leak'),
                'severity': sec_item.get('severity', 'High').upper(),
                'cvss': 8.5,
                'description': f"Exposed credentials found in archive of {sec_item.get('file_url', '')} (Value: {sec_item.get('value', '')})",
                'status': 'Historical Cache',
            })

    # ── Attack Path Planner → exploit graph and chains ──
    path_plan = res.get('Attack Path Planner', {})
    if isinstance(path_plan, dict):
        if 'graph' in path_plan:
            intel['attack_path']['graph'] = path_plan['graph']
        if 'exploit_chains' in path_plan:
            intel['attack_path']['exploit_chains'] = path_plan['exploit_chains']

    # ── MITRE ATT&CK Mapping ──
    mitre_map = {
        'TA0043': {'name': 'Reconnaissance', 'detected': 0},
        'TA0042': {'name': 'Resource Development', 'detected': 0},
        'TA0001': {'name': 'Initial Access', 'detected': 0},
        'TA0002': {'name': 'Execution', 'detected': 0},
        'TA0003': {'name': 'Persistence', 'detected': 0},
        'TA0004': {'name': 'Privilege Escalation', 'detected': 0},
        'TA0005': {'name': 'Defense Evasion', 'detected': 0},
        'TA0006': {'name': 'Credential Access', 'detected': 0},
        'TA0007': {'name': 'Discovery', 'detected': 0},
        'TA0008': {'name': 'Lateral Movement', 'detected': 0},
        'TA0009': {'name': 'Collection', 'detected': 0},
        'TA0010': {'name': 'Exfiltration', 'detected': 0},
        'TA0040': {'name': 'Impact', 'detected': 0},
    }
    # Map findings to MITRE
    for cve in intel['cves']:
        cid = (cve.get('id', '') or '').lower()
        if any(k in cid for k in ['xss', 'injection', 'rce', 'command']):
            mitre_map['TA0002']['detected'] += 1
        if any(k in cid for k in ['auth', 'bypass', 'credential', 'password', 'secret', 'api_key', 'token']):
            mitre_map['TA0006']['detected'] += 1
        if any(k in cid for k in ['ssrf', 'redirect', 'cors']):
            mitre_map['TA0001']['detected'] += 1
        if any(k in cid for k in ['header', 'csp', 'hsts', 'clickjack']):
            mitre_map['TA0005']['detected'] += 1
        if any(k in cid for k in ['disclosure', 'exposed', 'leak', 'information']):
            mitre_map['TA0009']['detected'] += 1
        if any(k in cid for k in ['sqli', 'sql']):
            mitre_map['TA0001']['detected'] += 1
            mitre_map['TA0009']['detected'] += 1

    # Discovery gets a count from recon modules
    if res.get('DNS Records'):
        mitre_map['TA0043']['detected'] += 1
    if res.get('Subdomain Discovery'):
        mitre_map['TA0043']['detected'] += 1
        mitre_map['TA0007']['detected'] += 1
    if res.get('Nmap Zero Day Scan'):
        mitre_map['TA0043']['detected'] += 1
        mitre_map['TA0007']['detected'] += 1
    if res.get('Web Technologies'):
        mitre_map['TA0043']['detected'] += 1

    intel['mitre_techniques'] = [{'id': k, **v} for k, v in mitre_map.items()]

    # ── Composite scores ──
    total_vulns = len(intel['cves'])
    intel['attack_surface'] = min(10, round(len(intel['iocs']) * 0.8, 1))
    intel['vuln_density'] = min(10, round(total_vulns * 1.2, 1))
    intel['exposure_level'] = min(10, round(intel['risk_score'] * 1.0, 1)) if intel['risk_score'] else 0

    # Deduplicate IOCs by value
    seen = set()
    unique_iocs = []
    for ioc in intel['iocs']:
        if ioc['value'] not in seen:
            seen.add(ioc['value'])
            unique_iocs.append(ioc)
    intel['iocs'] = unique_iocs[:50]  # limit to 50

    return intel


@app.get('/api/network-map/{domain}')
async def get_network_map(domain: str, background_tasks: BackgroundTasks, force: bool = False):
    """Retrieve comprehensive network topology data for a domain"""
    result_path = os.path.join('logs', domain, 'results.json')
    network = {
        'domain': domain,
        'dns_records': {},
        'subdomains': [],
        'technologies': {},
        'ports': [],
        'domain_info': {},
        'ssl_info': {},
        'subdomain_takeover': [],
        'has_data': False,
        'phishing_domains': [],
        'associated_sans': [],
        'is_scanning': False,
        'scan_progress': None,
    }

    should_trigger = False
    if force or not os.path.exists(result_path):
        should_trigger = True
    else:
        try:
            with open(result_path, 'r', encoding='utf-8') as f:
                raw_res = json.load(f)
            res = raw_res.get('results', raw_res) if isinstance(raw_res, dict) else {}
            if not res or not isinstance(res, dict):
                should_trigger = True
        except Exception:
            should_trigger = True

    if should_trigger:
        if os.path.exists(result_path):
            try:
                os.remove(result_path)
            except Exception:
                pass
        
        if domain in ACTIVE_SCANS:
            if ACTIVE_SCANS[domain].get('current_module') == 'Finished':
                ACTIVE_SCANS.pop(domain, None)
            else:
                network['is_scanning'] = True
                network['scan_progress'] = {
                    'total': ACTIVE_SCANS[domain].get('total', 16),
                    'completed': ACTIVE_SCANS[domain].get('completed', 0),
                    'current_module': ACTIVE_SCANS[domain].get('current_module', 'Initializing...')
                }
                return network

        if domain not in ACTIVE_SCANS:
            modules_list = [
                "Domain Information", "DNS Records", "SEO Analysis", "Web Technologies",
                "Security Analysis", "Advanced Content Scan", "Contact Spy", "Subdomain Discovery",
                "Subdomain Takeover", "CloudFlare Bypass", "Nmap Zero Day Scan", "GEO Analysis",
                "Web Archive Spy", "Phishing Domain Protection", "SSL SAN Association", "Attack Path Planner"
            ]
            module_functions = {
                "Domain Information": lambda d: get_domain_info(d),
                "DNS Records": lambda d: DNSAnalyzer().get_dns_records(d),
                "SEO Analysis": analyze_advanced_seo,
                "Web Technologies": detect_web_technologies,
                "Security Analysis": analyze_security,
                "Advanced Content Scan": lambda d: AdvancedContentScanner(d).run(),
                "Contact Spy": lambda d: GlobalDomainScraper(d).crawl(),
                "Subdomain Discovery": lambda d: run_subfinder(d),
                "Subdomain Takeover": lambda d: SubdomainTakeover(d).run(run_subfinder(d)),
                "CloudFlare Bypass": lambda d: CloudflareBypass(d).run(),
                "Nmap Zero Day Scan": lambda d: UltraAdvancedNetworkScanner(domain=d).run_comprehensive_scan(d),
                "GEO Analysis": analyze_geo,
                "Web Archive Spy": lambda d: ArchiveSpy(d).run(),
                "Phishing Domain Protection": lambda d: PhishingDetector(d).run(),
                "SSL SAN Association": lambda d: SSLAssociation(d).run(),
                "Attack Path Planner": lambda d: AttackPathPlanner(d).run()
            }
            ACTIVE_SCANS[domain] = {
                "total": len(modules_list),
                "completed": 0,
                "current_module": "Initializing Auto Scan...",
                "results": {}
            }
            background_tasks.add_task(run_scan_background, domain, modules_list, module_functions)
            network['is_scanning'] = True
            network['scan_progress'] = {
                'total': len(modules_list),
                'completed': 0,
                'current_module': 'Initializing Auto Scan...'
            }
        return network

    with open(result_path, 'r', encoding='utf-8') as f:
        raw_res = json.load(f)
    res = raw_res.get('results', raw_res) if isinstance(raw_res, dict) else {}

    network['has_data'] = True

    # ── DNS Records ──
    dns = res.get('DNS Records', {})
    if isinstance(dns, dict):
        network['dns_records'] = dns

    # ── Subdomains ──
    subs = res.get('Subdomain Discovery', [])
    if isinstance(subs, list):
        network['subdomains'] = [s if isinstance(s, str) else s.get('subdomain', s.get('domain', str(s))) for s in subs]
    elif isinstance(subs, dict):
        network['subdomains'] = subs.get('subdomains', subs.get('results', []))

    # ── Subdomain Takeover ──
    takeover = res.get('Subdomain Takeover', {})
    if isinstance(takeover, dict):
        network['subdomain_takeover'] = takeover.get('vulnerable_subdomains', takeover.get('results', []))
    elif isinstance(takeover, list):
        network['subdomain_takeover'] = takeover

    # ── Technologies (categorized) ──
    tech = res.get('Web Technologies', {})
    if isinstance(tech, dict):
        network['technologies'] = tech
    elif isinstance(tech, list):
        network['technologies'] = {'detected': tech}

    # ── Port Scan (Nmap) ──
    nmap = res.get('Nmap Zero Day Scan', {})
    if isinstance(nmap, dict):
        network['ports'] = nmap.get('open_ports', nmap.get('ports', nmap.get('results', [])))
        if not isinstance(network['ports'], list):
            network['ports'] = []

    # ── Domain Info ──
    dinfo = res.get('Domain Information', {})
    if isinstance(dinfo, dict):
        network['domain_info'] = dinfo

    # ── SSL / Security headers ──
    sec = res.get('Security Analysis', {})
    if isinstance(sec, dict):
        ssl_data = {}
        for v in sec.get('vulnerabilities', sec.get('findings', [])):
            if isinstance(v, dict):
                vtype = (v.get('type', '') or '').lower()
                if 'ssl' in vtype or 'tls' in vtype or 'certificate' in vtype or 'https' in vtype:
                    ssl_data['issues'] = ssl_data.get('issues', [])
                    ssl_data['issues'].append(v.get('description', v.get('detail', '')))
        network['ssl_info'] = ssl_data

    # ── Phishing Domain Protection → typosquatted domains ──
    phish = res.get('Phishing Domain Protection', {})
    if isinstance(phish, dict) and 'phishing_domains' in phish:
        network['phishing_domains'] = phish['phishing_domains']

    # ── SSL SAN Association → associated certificate hostnames ──
    ssl_assoc = res.get('SSL SAN Association', {})
    if isinstance(ssl_assoc, dict) and 'associated_domains' in ssl_assoc:
        network['associated_sans'] = ssl_assoc['associated_domains']

    return network


@app.get('/api/vulnerability-stats')
async def get_vulnerability_stats():
    """Aggregate vulnerability severity statistics across all scans"""
    stats = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'total': 0}
    logs_dir = 'logs'
    if os.path.exists(logs_dir):
        for domain in os.listdir(logs_dir):
            result_file = os.path.join(logs_dir, domain, 'results.json')
            if os.path.exists(result_file):
                try:
                    with open(result_file, 'r', encoding='utf-8') as f:
                        res = json.load(f)
                    sec = res.get('Security Analysis', {})
                    if isinstance(sec, dict):
                        for v in sec.get('vulnerabilities', []):
                            if isinstance(v, dict):
                                sev = (v.get('severity', 'medium') or 'medium').lower()
                                if sev in stats:
                                    stats[sev] += 1
                                stats['total'] += 1
                except Exception:
                    pass
    return stats


@app.get('/api/system-health')
async def get_system_health():
    """Return current system health and runtime info"""
    import platform
    import sys
    return {
        'api_status': 'online',
        'python_version': sys.version.split()[0],
        'platform': platform.system(),
        'active_scans': len(ACTIVE_SCANS),
        'pending_tasks': len(ACS_SECTION_TASKS),
        'version': '3.6.2'
    }


@app.get('/api/export/{domain}/{fmt}')
async def export_results(domain: str, fmt: str):
    """Export scan results in JSON or CSV format"""
    result_path = os.path.join('logs', domain, 'results.json')
    if not os.path.exists(result_path):
        raise HTTPException(status_code=404, detail='Results not found')
    with open(result_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    if fmt == 'json':
        return data
    elif fmt == 'csv':
        lines = ['Module,Status,Findings']
        for module, result in data.items():
            count = len(result) if isinstance(result, list) else (
                len(result.get('vulnerabilities', [])) if isinstance(result, dict) and 'vulnerabilities' in result else 1
            )
            lines.append(f'{module},completed,{count}')
        return PlainTextResponse(content='\n'.join(lines), media_type='text/csv')
    else:
        raise HTTPException(status_code=400, detail=f'Unsupported format: {fmt}')


@app.get("/")
async def root():
    return {
        "status": "online",
        "name": "WebAnalyzer API",
        "version": "3.6.2",
        "docs_url": "/docs"
    }
