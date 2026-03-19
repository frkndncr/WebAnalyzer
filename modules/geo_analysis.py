# modules/geo_analysis.py - Generative Engine Optimization (GEO) Analysis
import requests
from bs4 import BeautifulSoup
import urllib3
import re
from typing import Dict, Any

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def analyze_geo(domain: str) -> Dict[str, Any]:
    """
    Perform Generative Engine Optimization (GEO) Analysis for the given domain.
    Checks for llms.txt, WebMCP endpoints, and AI crawler directives.
    """
    url = f"https://{domain}" if not domain.startswith('http') else domain
    parsed_domain = domain.replace('https://', '').replace('http://', '').split('/')[0]
    
    results = {
        "LLMs Optimization (llms.txt)": _check_llms_txt(url),
        "WebMCP Integration": _check_webmcp(url),
        "AI Crawler Directives": _check_ai_crawlers(url)
    }
    
    results["GEO Score"] = _calculate_geo_score(results)
    return results

def _check_llms_txt(base_url: str) -> Dict[str, str]:
    """Check for standard llms.txt and llms-full.txt files"""
    paths_to_check = [
        "/llms.txt",
        "/llms-full.txt",
        "/.well-known/llms.txt"
    ]
    
    found_files = []
    
    for path in paths_to_check:
        try:
            req_url = f"{base_url.rstrip('/')}{path}"
            response = requests.get(req_url, timeout=10, verify=False)
            if response.status_code == 200 and 'text/plain' in response.headers.get('Content-Type', '').lower():
                found_files.append(path)
        except requests.RequestException:
            pass
            
    if found_files:
        return {
            "status": "Found",
            "files": ", ".join(found_files)
        }
    return {
        "status": "Not Found",
        "files": "None"
    }

def _check_webmcp(base_url: str) -> Dict[str, Any]:
    """Check for WebMCP (Model Context Protocol) integration"""
    endpoints_to_check = [
        "/.well-known/mcp",
        "/mcp.json"
    ]
    
    found_endpoints = []
    
    # Check standard endpoints
    for endpoint in endpoints_to_check:
        try:
            req_url = f"{base_url.rstrip('/')}{endpoint}"
            response = requests.get(req_url, timeout=10, verify=False)
            if response.status_code == 200:
                found_endpoints.append(endpoint)
        except requests.RequestException:
            pass
            
    # Check HTML for navigator.modelContext or WebMCP widgets
    html_features = []
    try:
        response = requests.get(base_url, timeout=15, verify=False)
        if response.status_code == 200:
            html = response.text
            if "navigator.modelContext" in html:
                html_features.append("navigator.modelContext API")
            if "webmcp" in html.lower() or "model context protocol" in html.lower():
                html_features.append("WebMCP/Model Context Protocol references in HTML")
    except requests.RequestException:
        pass

    status = "Found" if found_endpoints or html_features else "Not Found"
    
    return {
        "status": status,
        "endpoints": ", ".join(found_endpoints) if found_endpoints else "None",
        "html_features": ", ".join(html_features) if html_features else "None"
    }

def _check_ai_crawlers(base_url: str) -> Dict[str, Any]:
    """Analyze robots.txt for AI/LLM crawler directives."""
    ai_bots = [
        "GPTBot", "ChatGPT-User", "ClaudeBot", "Claude-Web", 
        "Applebot-Extended", "OAI-SearchBot", "PerplexityBot"
    ]
    
    directives = {bot: "Unknown" for bot in ai_bots}
    
    try:
        robots_url = f"{base_url.rstrip('/')}/robots.txt"
        response = requests.get(robots_url, timeout=10, verify=False)
        if response.status_code == 200:
            content = response.text
            lines = content.splitlines()
            current_agent = None
            
            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                if line.lower().startswith('user-agent:'):
                    agent = line.split(':', 1)[1].strip()
                    if agent in ai_bots:
                        current_agent = agent
                    else:
                        current_agent = None
                        
                elif current_agent and line.lower().startswith('disallow:'):
                    path = line.split(':', 1)[1].strip()
                    if path == '/':
                        directives[current_agent] = "Blocked"
                    elif directives[current_agent] == "Unknown":
                        directives[current_agent] = "Partially Blocked"
                        
                elif current_agent and line.lower().startswith('allow:'):
                    if directives[current_agent] == "Unknown":
                        directives[current_agent] = "Allowed"
                        
            # Mark remaining unknowns as "Allowed (Default)" if robots.txt exists
            for bot in ai_bots:
                if directives[bot] == "Unknown":
                    directives[bot] = "Allowed (Implicit)"
                    
    except requests.RequestException:
        return {"status": "Error checking robots.txt", "bots": {}}

    blocked_count = sum(1 for v in directives.values() if "Blocked" in v)
    total = len(ai_bots)
    status = "Restrictive" if blocked_count > (total / 2) else "Permissive"

    return {
        "status": status,
        "bots": directives
    }

def _calculate_geo_score(results: Dict[str, Any]) -> Dict[str, str]:
    """Calculate the GEO Score based on the findings."""
    score = 0
    max_score = 100
    
    # llms.txt score (40 points max)
    llms = results.get("LLMs Optimization (llms.txt)", {})
    if llms.get("status") == "Found":
        files_count = len(llms.get("files", "").split(","))
        score += min(40, 20 + (files_count * 10))
        
    # WebMCP score (40 points max)
    webmcp = results.get("WebMCP Integration", {})
    if webmcp.get("status") == "Found":
        score += 20
        if webmcp.get("endpoints") != "None":
            score += 10
        if webmcp.get("html_features") != "None":
            score += 10
            
    # AI Crawler Directives score (20 points max)
    crawlers = results.get("AI Crawler Directives", {})
    if crawlers.get("status") == "Permissive":
        score += 20
    elif crawlers.get("status") == "Unknown" or not crawlers.get("bots"):
        score += 10
        
    # Grade
    if score >= 80:
        grade = "A (Excellent)"
    elif score >= 60:
        grade = "B (Good)"
    elif score >= 40:
        grade = "C (Fair)"
    elif score >= 20:
        grade = "D (Poor)"
    else:
        grade = "F (None)"
        
    return {
        "Score": f"{score}/{max_score}",
        "Grade": grade
    }
