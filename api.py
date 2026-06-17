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
        "Advanced Content Scan": lambda d: AdvancedContentScanner(d).scan(),
        "Contact Spy": lambda d: GlobalDomainScraper(d).run(),
        "Subdomain Discovery": lambda d: run_subfinder(d),
        "Subdomain Takeover": lambda d: SubdomainTakeover(d).run(),
        "CloudFlare Bypass": lambda d: CloudflareBypass(d).run(),
        "Nmap Zero Day Scan": lambda d: UltraAdvancedNetworkScanner(d).run_scan(),
        "GEO Analysis": analyze_geo
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
        'Nmap Zero Day Scan': 'heavy', 'GEO Analysis': 'light'
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
                            res = json.load(f)
                            
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
async def get_threat_intel(domain: str):
    """Extract security-related findings as threat intelligence"""
    result_path = os.path.join('logs', domain, 'results.json')
    intel = {'domain': domain, 'mitre_techniques': [], 'iocs': [], 'cves': [], 'risk_score': 0}
    if os.path.exists(result_path):
        with open(result_path, 'r', encoding='utf-8') as f:
            res = json.load(f)
        sec = res.get('Security Analysis', {})
        if isinstance(sec, dict):
            intel['risk_score'] = sec.get('security_score', 0)
            vulns = sec.get('vulnerabilities', [])
            if isinstance(vulns, list):
                for v in vulns:
                    if isinstance(v, dict):
                        intel['cves'].append({
                            'id': v.get('type', 'Unknown'),
                            'severity': v.get('severity', 'Medium'),
                            'description': v.get('description', '')
                        })
    return intel


@app.get('/api/network-map/{domain}')
async def get_network_map(domain: str):
    """Retrieve network topology data for a domain"""
    result_path = os.path.join('logs', domain, 'results.json')
    network = {'domain': domain, 'dns_records': {}, 'subdomains': [], 'technologies': {}, 'ports': []}
    if os.path.exists(result_path):
        with open(result_path, 'r', encoding='utf-8') as f:
            res = json.load(f)
        network['dns_records'] = res.get('DNS Records', {})
        network['subdomains'] = res.get('Subdomain Discovery', [])
        network['technologies'] = res.get('Web Technologies', {})
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
        'version': '3.3.0'
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
        "version": "3.3.0",
        "docs_url": "/docs"
    }
