"""
Universal adapter for all WebAnalyzer modules
"""
import logging
import warnings
import urllib3
import os
import json
import time
import whois
import importlib
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def load_config(config_path="webanalyzer_config.json"):
    if not os.path.exists(config_path):
        return {}
    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)

config = load_config()
api_key = config.get("whois_api_key")

# Skip patterns for problematic domains
SKIP_PATTERNS = [
    'stun.l.google.com',
    '.cloudapp.azure.com',
    'clients6.google.com',
    '.cdn.cloudflare.net',
    'rr1.sn-',
    'rr2.sn-',
    'rr3.sn-',
    'rr4.sn-',
    'rr5.sn-',
    'e-0014.e-msedge',
    's-part-',
    '.t-msedge.net',
    'perimeterx.map',
    'i.ytimg.com',
    'analytics-alv.google.com',
    'signaler-pa.clients',
    'westus-0.in.applicationinsights'
]

# Module timeouts
TIMEOUTS = {
    'domain_info': 10,
    'domain_dns': 10,
    'seo_analysis': 45,
    'security_analysis': 30,
    'web_technologies': 45
}

def is_subdomain(domain):
    """Check if domain is subdomain"""
    parts = domain.split('.')
    
    # IP address check
    if all(part.isdigit() or ':' in domain for part in parts):
        return False
    
    # Special TLDs check
    common_tlds = ['co.uk', 'com.tr', 'gov.tr', 'edu.tr', 'org.tr', 'net.tr', 
                   'co.jp', 'co.kr', 'co.id', 'co.in', 'com.br', 'com.au']
    
    if len(parts) <= 2:
        return False
    
    domain_suffix = '.'.join(parts[-2:])
    if domain_suffix in common_tlds:
        return len(parts) > 3
    
    return len(parts) > 2

def should_skip_domain(domain, module_name):
    """Check if module should be skipped for specific domain patterns"""
    # DNS always runs
    if module_name == 'domain_dns':
        return False
    
    # Check skip patterns
    for pattern in SKIP_PATTERNS:
        if pattern in domain.lower():
            return True
    
    return False

def run_module_universal(module, module_name, domain):
    """
    Universal module runner that handles different module structures
    """
    try:
        # Check if should skip
        if should_skip_domain(domain, module_name):
            return {
                "domain": domain,
                "status": "skipped",
                "reason": "Domain pattern in skip list",
                "module": module_name,
                "execution_time": 0
            }
        
        # Get timeout for module
        timeout = TIMEOUTS.get(module_name, 5)
        
        if module_name == 'domain_info':
            start_time = time.time()
            
            # Skip subdomains for WHOIS
            if is_subdomain(domain):
                return {
                    "domain": domain,
                    "status": "skipped",
                    "reason": "Subdomain - WHOIS not applicable",
                    "is_subdomain": True,
                    "execution_time": round(time.time() - start_time, 3)
                }
            
            # Use python-whois directly
            try:
                w = whois.whois(domain)
                
                result = {
                    "Domain": domain,
                    "Registrar Company (Registrar)": getattr(w, 'registrar', 'Unknown') or "Unknown",
                    "Creation Date": str(w.creation_date[0]) if isinstance(w.creation_date, list)
                                    else str(w.creation_date) if w.creation_date else "Unknown",
                    "End Date": str(w.expiration_date[0]) if isinstance(w.expiration_date, list)
                                else str(w.expiration_date) if w.expiration_date else "Unknown",
                    "Last Updated Date": str(w.updated_date[0]) if isinstance(w.updated_date, list)
                                        else str(w.updated_date) if getattr(w, 'updated_date', None) else "Unknown",
                    "Domain Status": getattr(w, 'status', ["Unknown"]) or ["Unknown"],
                    "Privacy Protection": "Inactive",
                    "DNSSEC Status": "Unsigned",
                    "SSL Information": "Check required",
                    "Blacklist Check": "Not on the blacklist",
                    "IP Address": "Check DNS records",
                    "Server Provider": "Check DNS records",
                    "Physical Location": "Unknown, Unknown",
                    "method": "python-whois",
                    "status": "success",
                    "execution_time": round(time.time() - start_time, 3)
                }
            
            except Exception as whois_error:
                result = {
                    "Domain": domain,
                    "Registrar Company (Registrar)": "Unknown",
                    "Creation Date": "Unknown",
                    "End Date": "Unknown", 
                    "Last Updated Date": "Unknown",
                    "Domain Status": ["Unknown"],
                    "Privacy Protection": "Inactive",
                    "DNSSEC Status": "Unsigned",
                    "SSL Information": "Check required",
                    "Blacklist Check": "Not on the blacklist",
                    "IP Address": "Unknown",
                    "Server Provider": "Unknown",
                    "Physical Location": "Unknown, Unknown",
                    "status": "failed",
                    "error": str(whois_error)[:100],
                    "execution_time": round(time.time() - start_time, 3)
                }
            
            return result
        
        elif module_name == 'domain_dns':
            start_time = time.time()
            try:
                analyzer_class = getattr(module, 'DNSAnalyzer', None)
                if analyzer_class:
                    analyzer = analyzer_class()
                    dns_records = analyzer.get_dns_records(domain)
                    result = {
                        "domain": domain,
                        "records": dns_records.get("records", {}),
                        "response_time_ms": dns_records.get("response_time_ms", None),
                        "status": "success",
                        "execution_time": round(time.time() - start_time, 3)
                    }
                    return result

                elif hasattr(module, 'main'):
                    result = module.main(domain)
                    result['execution_time'] = round(time.time() - start_time, 3)
                    return result

                else:
                    import socket
                    ip = socket.gethostbyname(domain)
                    result = {"domain": domain, "ip_address": ip, "dns_resolved": True, "status": "success"}
                    result['execution_time'] = round(time.time() - start_time, 3)
                    return result

            except Exception as e:
                import socket
                try:
                    ip = socket.gethostbyname(domain)
                    result = {"domain": domain, "ip_address": ip, "dns_resolved": True, "status": "partial_failure", "error": str(e)}
                except:
                    result = {"domain": domain, "dns_resolved": False, "status": "failed", "error": str(e)}
                result['execution_time'] = round(time.time() - start_time, 3)
                return result
                    
        elif module_name == 'seo_analysis':
            start_time = time.time()
            try:
                analyze_func = getattr(module, 'analyze_advanced_seo', None)
                if analyze_func:
                    result = analyze_func(domain)
                    result["status"] = "failed" if "Error" in result else "success"
                else:
                    # Fallback kaldırıldı - sadece modül kullanılacak
                    result = {
                        "domain": domain,
                        "status": "failed", 
                        "error": "analyze_advanced_seo function not found in seo_analysis module"
                    }
            except Exception as e:
                result = {"domain": domain, "seo_status": "error", "error": str(e), "status": "failed"}
            
            result['execution_time'] = round(time.time() - start_time, 3)
            return result

        elif module_name == 'security_analysis':
            start_time = time.time()
            result = {"domain": domain}
            
            if hasattr(module, 'analyze_security'):
                try:
                    # Modülü çalıştır
                    analysis_result = module.analyze_security(domain)
                    print(f"DEBUG: Security result status: {analysis_result.get('status', 'no status')}")
                    
                    # Yeni format için veri yapılandırması 
                    if "Error" not in analysis_result:
                        # Temel bilgileri çıkar
                        security_score = analysis_result.get("security_score", {})
                        waf_data = analysis_result.get("waf_detection", {})
                        ssl_data = analysis_result.get("ssl_analysis", {})
                        headers_data = analysis_result.get("security_headers", {})
                        vuln_data = analysis_result.get("vulnerability_scan", {})
                        
                        # Bulk sistem için düzenlenmiş format
                        result.update({
                            "status": "success",
                            "security_score": security_score.get("overall_score", 0),
                            "security_grade": security_score.get("grade", "F"),
                            "risk_level": security_score.get("risk_level", "Unknown"),
                            "https_available": analysis_result.get("https_available", False),
                            "https_redirect": analysis_result.get("https_redirect", False),
                            "waf_detected": waf_data.get("detected", False),
                            "waf_provider": waf_data.get("primary_waf", {}).get("provider", "Not Detected"),
                            "ssl_grade": ssl_data.get("overall_grade", "F"),
                            "ssl_protocol": ssl_data.get("protocol_version", "Unknown"),
                            "headers_score": headers_data.get("score", 0),
                            "missing_critical_headers": headers_data.get("missing_critical", []),
                            "missing_high_headers": headers_data.get("missing_high", []),
                            "vulnerabilities_found": vuln_data.get("vulnerabilities_found", 0),
                            "vulnerability_risk": vuln_data.get("risk_level", "Unknown"),
                            "recommendations": analysis_result.get("recommendations", []),
                            "raw_analysis": analysis_result
                        })
                    else:
                        result.update({
                            "status": "error",
                            "error": analysis_result["Error"],
                            "security_score": 0,
                            "security_grade": "F",
                            "risk_level": "Unknown",
                            "https_available": False,
                            "waf_detected": False,
                            "ssl_grade": "F",
                            "headers_score": 0,
                            "vulnerabilities_found": 0
                        })
                        
                except Exception as e:
                    print(f"SECURITY ANALYSIS EXCEPTION: {e}")
                    import traceback
                    traceback.print_exc()
                    result.update({
                        "status": "failed",
                        "error": f"Security analysis exception: {str(e)}",
                        "security_score": 0,
                        "security_grade": "F",
                        "risk_level": "Unknown"
                    })
            else:
                result.update({
                    "status": "not_implemented",
                    "error": "analyze_security function not found"
                })
            
            result['execution_time'] = round(time.time() - start_time, 3)
            return result
                
        elif module_name == 'web_technologies':
            start_time = time.time()
            try:
                # detect_web_technologies fonksiyonunu kullan
                tech_result = module.detect_web_technologies(domain)
                
                # Eğer error varsa
                if "Error" in tech_result:
                    result = {
                        "domain": domain,
                        "technologies": [],
                        "status": "error",
                        "error": tech_result["Error"],
                        "basic_info": {},
                        "security_analysis": {},
                        "wordpress_analysis": {},
                        "security_score": 0,
                        "security_grade": "F",
                        "risk_level": "Unknown"
                    }
                else:
                    # Başarılı sonuç - kategorize et
                    basic_categories = [
                        "Web Server", "Backend Technologies", "Frontend Technologies", 
                        "JavaScript Libraries", "CSS Frameworks", "Content Management System", 
                        "E-commerce Platform", "CDN & Cloud Services", "Analytics & Tracking"
                    ]
                    
                    # Temel teknoloji bilgileri
                    basic_info = {}
                    for category in basic_categories:
                        if category in tech_result:
                            basic_info[category] = tech_result[category]
                    
                    # Legacy format için technologies listesi oluştur
                    technologies = []
                    for category, value in basic_info.items():
                        if isinstance(value, list) and value != ["Not Detected"]:
                            technologies.extend(value)
                        elif isinstance(value, str) and value != "Not Detected":
                            technologies.append(value)
                    
                    # WordPress analizi
                    wordpress_analysis = tech_result.get("WordPress Analysis", {})
                    
                    # WordPress özel alanları
                    wp_users = wordpress_analysis.get("users", {}).get("users_found", [])
                    wp_version = wordpress_analysis.get("version_info", {}).get("version", "Unknown")
                    wp_plugins = wordpress_analysis.get("plugins", {}).get("detected_plugins", [])
                    
                    # Güvenlik skoru
                    security_score_data = tech_result.get("Security Score", {})
                    
                    result = {
                        "domain": domain,
                        "technologies": technologies,  # Legacy format için
                        "basic_info": basic_info,
                        "security_analysis": {
                            "security_headers": tech_result.get("Security Headers", {}),
                            "vulnerabilities": tech_result.get("Security Vulnerabilities", {}),
                            "ssl_tls": tech_result.get("SSL/TLS Security", {}),
                            "security_services": tech_result.get("Security Services", {}),
                            "cookie_security": tech_result.get("Cookie Security", {}),
                            "information_disclosure": tech_result.get("Information Disclosure", {})
                        },
                        "wordpress_analysis": wordpress_analysis,
                        "status": "success",
                        
                        # Hızlı erişim alanları
                        "security_score": security_score_data.get("overall_score", 0),
                        "security_grade": security_score_data.get("security_grade", "N/A"),
                        "risk_level": security_score_data.get("risk_level", "Unknown"),
                        "critical_issues": security_score_data.get("critical_issues", []),
                        
                        # WordPress özet bilgileri
                        "is_wordpress": bool(wordpress_analysis),
                        "wp_version": wp_version,
                        "wp_users": [{"id": u.get("id"), "username": u.get("username")} for u in wp_users],
                        "wp_users_count": len(wp_users),
                        "wp_plugins_count": len(wp_plugins),
                        "wp_security_risk": wordpress_analysis.get("users", {}).get("security_risk", "Unknown"),
                        
                        # Teknoloji özet
                        "web_server": tech_result.get("Web Server", "Unknown"),
                        "backend_tech": tech_result.get("Backend Technologies", []),
                        "cms_detected": tech_result.get("Content Management System", []),
                        
                        # Güvenlik özet
                        "ssl_grade": tech_result.get("SSL/TLS Security", {}).get("security_assessment", "Unknown"),
                        "waf_detected": bool(tech_result.get("Security Services", {}).get("waf", [])),
                        "missing_headers_count": len(tech_result.get("Security Vulnerabilities", {}).get("missing_security_headers", []))
                    }
                    
            except Exception as e:
                result = {
                    "domain": domain,
                    "technologies": [],
                    "basic_info": {},
                    "security_analysis": {},
                    "wordpress_analysis": {},
                    "status": "error",
                    "error": str(e),
                    "security_score": 0,
                    "security_grade": "F",
                    "risk_level": "Unknown",
                    "is_wordpress": False,
                    "wp_users_count": 0,
                    "wp_plugins_count": 0
                }
            
            result['execution_time'] = round(time.time() - start_time, 3)
            return result
        
        # Generic fallback
        if hasattr(module, 'main'):
            try:
                return module.main(domain)
            except:
                pass
                
        # Minimal fallback data
        return {"status": "completed", "module": module_name, "domain": domain}
        
    except Exception as e:
        logging.error(f"Module {module_name} execution failed: {e}")
        return {"status": "error", "error": str(e), "module": module_name, "domain": domain}