from fastapi import FastAPI, BackgroundTasks, HTTPException
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
        "Domain Information": lambda d: get_domain_info(d, os.getenv('WHOIS_API_KEY', 'default_key')),
        "DNS Records": lambda d: DNSAnalyzer().get_dns_records(d),
        "SEO Analysis": analyze_advanced_seo,
        "Web Technologies": detect_web_technologies,
        "Security Analysis": analyze_security,
        "Advanced Content Scan": lambda d: AdvancedContentScanner(d).scan(),
        "Contact Spy": lambda d: GlobalDomainScraper(d).run(),
        "Subdomain Discovery": lambda d: run_subfinder(d, output_dir=f"logs/{d}"),
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
