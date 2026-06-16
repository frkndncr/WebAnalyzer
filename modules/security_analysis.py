import requests
import ssl
import socket
from urllib.parse import urlparse
from typing import Dict, List, Optional
import warnings
import re
from datetime import datetime
import json

warnings.filterwarnings('ignore', message='Unverified HTTPS request')

def analyze_security(domain: str) -> Dict:
    """
    Perform comprehensive security analysis including WAF detection, security headers,
    HTTPS enforcement, SSL analysis, CORS policy, and vulnerability scanning.
    
    Args:
        domain (str): Target domain
        
    Returns:
        Dict: Comprehensive security analysis results
    """
    try:
        # Normalize domain
        if domain.startswith(('http://', 'https://')):
            parsed = urlparse(domain)
            domain = parsed.netloc
        
        http_url = f"http://{domain}"
        https_url = f"https://{domain}"
        
        # Enhanced headers for better analysis
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache'
        }
        
        # HTTP and HTTPS requests with better error handling
        response_http = None
        response_https = None
        https_redirect = False
        
        try:
            response_http = requests.get(http_url, headers=headers, timeout=30, 
                                       allow_redirects=False, verify=False)
            
            # Check for HTTPS redirect
            if response_http.status_code in [301, 302, 307, 308]:
                location = response_http.headers.get('Location', '')
                if location.startswith('https://'):
                    https_redirect = True
        except requests.exceptions.RequestException:
            pass
        
        try:
            response_https = requests.get(https_url, headers=headers, timeout=30, verify=False)
        except requests.exceptions.RequestException:
            pass
        
        # Choose the best response for analysis
        primary_response = response_https if response_https else response_http
        
        # Comprehensive Security Analysis
        analysis_result = {
            "domain": domain,
            "https_available": response_https is not None,
            "https_redirect": https_redirect,
            "waf_detection": detect_waf(primary_response, domain),
            "security_headers": analyze_security_headers(primary_response),
            "ssl_analysis": analyze_ssl_advanced(domain),
            "cors_policy": analyze_cors_policy(primary_response),
            "cookie_security": analyze_cookie_security_detailed(primary_response),
            "http_methods": detect_http_methods(domain),
            "server_information": analyze_server_info(primary_response),
            "vulnerability_scan": perform_vulnerability_scan(domain, primary_response)
        }
        
        # Calculate security score
        analysis_result["security_score"] = calculate_security_score(analysis_result)
        analysis_result["recommendations"] = generate_security_recommendations(analysis_result)
        
        analysis_result["status"] = "completed"
        
        return analysis_result
        
    except Exception as e:
        return {
            "Error": f"Could not analyze security: {str(e)}",
            "status": "failed"
        }

def detect_waf(response: Optional[requests.Response], domain: str) -> Dict:
    """Enhanced WAF detection with multiple signatures"""
    if not response:
        return {"detected": False, "provider": "Unknown", "confidence": "Low"}
    
    waf_signatures = {
        # Header-based detection
        "cloudflare": {
            "headers": ["cf-ray", "cf-cache-status", "__cfduid"],
            "server": ["cloudflare"],
            "name": "Cloudflare"
        },
        "akamai": {
            "headers": ["akamai-transformed", "akamai-cache-status"],
            "server": ["akamaighost"],
            "name": "Akamai"
        },
        "imperva": {
            "headers": ["x-iinfo", "incap_ses"],
            "server": ["imperva"],
            "name": "Imperva Incapsula"
        },
        "sucuri": {
            "headers": ["x-sucuri-id", "x-sucuri-cache"],
            "server": ["sucuri"],
            "name": "Sucuri"
        },
        "barracuda": {
            "headers": ["barra"],
            "server": ["barracuda"],
            "name": "Barracuda"
        },
        "f5": {
            "headers": ["f5-http-lb", "bigip"],
            "server": ["bigip", "f5"],
            "name": "F5 BIG-IP"
        },
        "aws": {
            "headers": ["x-amz-cf-id", "x-amzn-requestid"],
            "server": ["awselb"],
            "name": "AWS WAF"
        }
    }
    
    detected_wafs = []
    headers_str = str(response.headers).lower()
    server_header = response.headers.get('Server', '').lower()
    
    for waf_key, waf_data in waf_signatures.items():
        confidence = 0
        detection_methods = []
        
        # Check headers
        for header in waf_data.get("headers", []):
            if header in headers_str:
                confidence += 40
                detection_methods.append(f"Header: {header}")
        
        # Check server header
        for server in waf_data.get("server", []):
            if server in server_header:
                confidence += 30
                detection_methods.append(f"Server: {server}")
        
        if confidence > 0:
            detected_wafs.append({
                "provider": waf_data["name"],
                "confidence": "High" if confidence >= 50 else "Medium" if confidence >= 30 else "Low",
                "detection_methods": detection_methods,
                "score": confidence
            })
    
    if detected_wafs:
        # Sort by confidence score and return the best match
        detected_wafs.sort(key=lambda x: x["score"], reverse=True)
        return {
            "detected": True,
            "primary_waf": detected_wafs[0],
            "all_detected": detected_wafs,
            "total_wafs": len(detected_wafs)
        }
    else:
        return {"detected": False, "provider": "Not Detected", "confidence": "N/A"}

def analyze_security_headers(response: Optional[requests.Response]) -> Dict:
    """Comprehensive security headers analysis"""
    if not response:
        return {"error": "No response available for analysis"}
    
    headers_analysis = {}
    
    # Define security headers with their importance
    security_headers_config = {
        "Strict-Transport-Security": "Critical",
        "Content-Security-Policy": "Critical", 
        "X-Frame-Options": "High",
        "X-Content-Type-Options": "Medium",
        "X-XSS-Protection": "Medium",
        "Referrer-Policy": "Medium",
        "Permissions-Policy": "Medium"
    }
    
    for header_name, importance in security_headers_config.items():
        header_value = response.headers.get(header_name)
        
        headers_analysis[header_name] = {
            "present": bool(header_value),
            "value": header_value or "Not Set",
            "importance": importance,
            "security_level": "Good" if header_value else ("Critical" if importance == "Critical" else "Medium")
        }
    
    # Calculate score
    total_score = 0
    max_score = 0
    
    for header_data in headers_analysis.values():
        if header_data["importance"] == "Critical":
            max_score += 30
            if header_data["present"]:
                total_score += 30
        elif header_data["importance"] == "High":
            max_score += 20
            if header_data["present"]:
                total_score += 20
        elif header_data["importance"] == "Medium":
            max_score += 10
            if header_data["present"]:
                total_score += 10
    
    return {
        "headers": headers_analysis,
        "score": round((total_score / max_score) * 100) if max_score > 0 else 0,
        "missing_critical": [name for name, data in headers_analysis.items() 
                           if not data["present"] and data["importance"] == "Critical"],
        "missing_high": [name for name, data in headers_analysis.items() 
                        if not data["present"] and data["importance"] == "High"]
    }

def analyze_ssl_advanced(domain: str) -> Dict:
    """Advanced SSL/TLS analysis"""
    try:
        # Create SSL context
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        # Connect and get certificate info
        with socket.create_connection((domain, 443), timeout=30) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
                
                # Basic certificate analysis
                cert_info = {}
                if cert:
                    subject = dict(x[0] for x in cert.get('subject', []))
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    
                    cert_info = {
                        "subject": subject.get('commonName', 'Unknown'),
                        "issuer": issuer.get('commonName', 'Unknown'),
                        "not_before": cert.get('notBefore', 'Unknown'),
                        "not_after": cert.get('notAfter', 'Unknown'),
                        "serial_number": cert.get('serialNumber', 'Unknown')
                    }
                
                # Cipher analysis
                cipher_strength = "Unknown"
                if cipher:
                    cipher_name = cipher[0]
                    if "AES256" in cipher_name or "CHACHA20" in cipher_name or "TLS_AES_256" in cipher_name:
                        cipher_strength = "Strong"
                    elif "AES128" in cipher_name:
                        cipher_strength = "Medium"
                    elif any(weak in cipher_name for weak in ["DES", "RC4", "NULL"]):
                        cipher_strength = "Weak"
                
                # Overall grade
                grade = "A"
                if version == "TLSv1.3":
                    grade = "A+"
                elif version == "TLSv1.2" and cipher_strength == "Strong":
                    grade = "A"
                elif version == "TLSv1.2":
                    grade = "B"
                elif version in ["TLSv1.1", "TLSv1"]:
                    grade = "C"
                else:
                    grade = "F"
                
                return {
                    "ssl_available": True,
                    "protocol_version": version,
                    "cipher_suite": cipher[0] if cipher else "Unknown",
                    "cipher_strength": cipher_strength,
                    "certificate": cert_info,
                    "overall_grade": grade
                }
                
    except Exception as e:
        return {
            "ssl_available": False,
            "error": str(e),
            "overall_grade": "F"
        }

def analyze_cors_policy(response: Optional[requests.Response]) -> Dict:
    """Analyze CORS policy configuration with dynamic reflection test"""
    if not response:
        return {"error": "No response available"}
    
    cors_headers = {
        "Access-Control-Allow-Origin": response.headers.get("Access-Control-Allow-Origin"),
        "Access-Control-Allow-Methods": response.headers.get("Access-Control-Allow-Methods"),
        "Access-Control-Allow-Headers": response.headers.get("Access-Control-Allow-Headers"),
        "Access-Control-Allow-Credentials": response.headers.get("Access-Control-Allow-Credentials")
    }
    
    issues = []
    
    # 1. Check for overly permissive CORS
    origin_header = cors_headers["Access-Control-Allow-Origin"]
    credentials_header = cors_headers["Access-Control-Allow-Credentials"]
    
    if origin_header == "*":
        if credentials_header and credentials_header.lower() == "true":
            issues.append("Critical: Wildcard origin with credentials allowed")
        else:
            issues.append("Warning: Wildcard origin allows all domains")
            
    # 2. Dynamic reflection test (simulate evil origin)
    try:
        parsed_url = urlparse(response.url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        evil_origin = "https://evil-attacker.local"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'Origin': evil_origin
        }
        test_response = requests.get(base_url, headers=headers, timeout=5, verify=False)
        reflected_origin = test_response.headers.get("Access-Control-Allow-Origin")
        reflected_credentials = test_response.headers.get("Access-Control-Allow-Credentials")
        
        if reflected_origin == evil_origin:
            if reflected_credentials and reflected_credentials.lower() == "true":
                issues.append("Critical: Vulnerable to CORS Origin Reflection with credentials allowed")
            else:
                issues.append("High: Server reflects arbitrary origins in Access-Control-Allow-Origin")
    except Exception:
        pass
    
    return {
        "headers": {k: v or "Not Set" for k, v in cors_headers.items()},
        "configured": any(cors_headers.values()),
        "issues": issues,
        "security_level": "High" if not issues else "Medium" if len(issues) <= 1 else "Low"
    }

def analyze_cookie_security_detailed(response: Optional[requests.Response]) -> Dict:
    """Detailed cookie security analysis checking all cookies individually"""
    if not response:
        return {"error": "No response available"}
    
    # Extract cookies list
    cookies = []
    headers = response.headers
    for header_name, header_value in headers.items():
        if header_name.lower() == 'set-cookie':
            # Support multiple cookies in headers
            cookies.extend([c.strip() for c in header_value.split(',') if c.strip()])
            
    if not cookies:
        return {"cookies_present": False, "analysis": "No cookies detected"}
    
    security_issues = []
    analyzed_cookies = []
    
    # Sensitive cookie names pattern
    sensitive_cookie_pattern = re.compile(r'(session|jwt|auth|token|admin|login|passwd|skey)', re.IGNORECASE)
    
    for cookie in cookies:
        cookie_parts = [part.strip() for part in cookie.split(';')]
        cookie_name_val = cookie_parts[0] if cookie_parts else ""
        cookie_name = cookie_name_val.split('=')[0] if '=' in cookie_name_val else "Unknown"
        
        is_sensitive = bool(sensitive_cookie_pattern.search(cookie_name))
        
        cookie_lower = cookie.lower()
        secure = "secure" in cookie_lower
        httponly = "httponly" in cookie_lower
        samesite = None
        for part in cookie_parts:
            if part.lower().startswith("samesite"):
                samesite = part.split('=')[1] if '=' in part else "True"
                
        cookie_issues = []
        if not secure:
            cookie_issues.append("Missing Secure flag")
        if not httponly:
            cookie_issues.append("Missing HttpOnly flag")
        if not samesite:
            cookie_issues.append("Missing SameSite attribute")
            
        severity = "High" if is_sensitive else "Low"
        for issue in cookie_issues:
            security_issues.append(f"{issue} on {'sensitive ' if is_sensitive else ''}cookie '{cookie_name}' ({severity} severity)")
            
        analyzed_cookies.append({
            "name": cookie_name,
            "is_sensitive": is_sensitive,
            "secure": secure,
            "httponly": httponly,
            "samesite": samesite or "Not Set",
            "issues": cookie_issues
        })
    
    score = max(0, 100 - (len(security_issues) * 15))
    return {
        "cookies_present": True,
        "analyzed_cookies": analyzed_cookies,
        "security_issues": security_issues,
        "security_score": score
    }

def detect_http_methods(domain: str) -> Dict:
    """Detect allowed HTTP methods"""
    try:
        url = f"https://{domain}"
        
        # Try OPTIONS request
        response = requests.options(url, timeout=10, verify=False)
        allowed_methods = response.headers.get('Allow', '').split(',')
        allowed_methods = [method.strip() for method in allowed_methods if method.strip()]
        
        # Check for dangerous methods
        dangerous_methods = ['DELETE', 'PUT', 'PATCH', 'TRACE', 'CONNECT']
        found_dangerous = [method for method in allowed_methods if method.upper() in dangerous_methods]
        
        return {
            "methods_detected": True,
            "allowed_methods": allowed_methods,
            "dangerous_methods": found_dangerous,
            "security_risk": "High" if found_dangerous else "Low"
        }
        
    except Exception as e:
        return {
            "methods_detected": False,
            "error": str(e),
            "security_risk": "Unknown"
        }

def analyze_server_info(response: Optional[requests.Response]) -> Dict:
    """Analyze server information disclosure"""
    if not response:
        return {"error": "No response available"}
    
    server_info = {}
    security_issues = []
    
    # Check various headers for information disclosure
    disclosure_headers = {
        "Server": "Web server version disclosed",
        "X-Powered-By": "Technology stack disclosed"
    }
    
    for header, issue in disclosure_headers.items():
        value = response.headers.get(header)
        if value:
            server_info[header] = value
            security_issues.append(issue)
    
    return {
        "server_headers": server_info,
        "information_disclosure": security_issues,
        "disclosure_count": len(security_issues),
        "security_level": "High" if len(security_issues) > 2 else "Medium" if security_issues else "Good"
    }

def perform_vulnerability_scan(domain: str, response: Optional[requests.Response]) -> Dict:
    """Perform advanced vulnerability scanning including sensitive file probing"""
    vulnerabilities = []
    
    try:
        # 1. Check for HTTPS enforcement
        if response and not response.url.startswith('https://'):
            vulnerabilities.append({
                "type": "Insecure Transport",
                "severity": "High",
                "description": "Site not enforcing HTTPS"
            })
        
        # 2. Check response for database error leaks
        if response:
            response_text = getattr(response, 'text', '')
            error_patterns = [
                (r"fatal error", "PHP Fatal Error"),
                (r"warning.*mysql", "MySQL Warning"),
                (r"error.*sql", "SQL Error")
            ]
            for pattern, description in error_patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    vulnerabilities.append({
                        "type": "Information Disclosure",
                        "severity": "Medium",
                        "description": f"{description} detected in response"
                    })
        
        # 3. Sensitive Files and Endpoints Prober
        sensitive_paths = [
            ".env", ".git/config", "wp-config.php", "config.json", 
            "backup.sql", "db.sql", "phpinfo.php", ".htaccess",
            "config.php.bak", "config.php~"
        ]
        
        # Run concurrent checks for sensitive files
        parsed = urlparse(response.url if response else f"https://{domain}")
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        import concurrent.futures
        def check_path(path):
            try:
                target_url = f"{base_url.rstrip('/')}/{path}"
                headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
                res = requests.get(target_url, headers=headers, timeout=4, verify=False, allow_redirects=False)
                # If we get a 200 and it doesn't look like a standard error landing page
                if res.status_code == 200:
                    content_len = len(res.text)
                    if content_len > 0 and "404" not in res.text and "not found" not in res.text.lower():
                        return {
                            "type": "Exposed Sensitive File",
                            "severity": "High" if path in [".env", ".git/config", "wp-config.php"] else "Medium",
                            "description": f"Exposed sensitive file: {path} (Size: {content_len} bytes)"
                        }
            except Exception:
                pass
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            results = list(executor.map(check_path, sensitive_paths))
            for res in results:
                if res:
                    vulnerabilities.append(res)
        
        return {
            "vulnerabilities_found": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "risk_level": calculate_risk_level(vulnerabilities)
        }
        
    except Exception as e:
        return {
            "scan_error": str(e),
            "vulnerabilities_found": 0,
            "vulnerabilities": []
        }

def calculate_risk_level(vulnerabilities: List[Dict]) -> str:
    """Calculate overall risk level from vulnerabilities"""
    if not vulnerabilities:
        return "Low"
    
    severity_scores = {"High": 3, "Medium": 2, "Low": 1}
    total_score = sum(severity_scores.get(v.get("severity", "Low"), 1) for v in vulnerabilities)
    
    if total_score >= 6:
        return "Critical"
    elif total_score >= 4:
        return "High" 
    elif total_score >= 2:
        return "Medium"
    else:
        return "Low"

def calculate_security_score(analysis: Dict) -> Dict:
    """Calculate comprehensive security score"""
    total_score = 100
    score_breakdown = {}
    
    # Security Headers (40% weight)
    headers_data = analysis.get("security_headers", {})
    headers_score = headers_data.get("score", 0)
    score_breakdown["security_headers"] = headers_score
    total_score -= (100 - headers_score) * 0.4
    
    # SSL/TLS (30% weight)
    ssl_data = analysis.get("ssl_analysis", {})
    ssl_grade = ssl_data.get("overall_grade", "F")
    ssl_score = {"A+": 100, "A": 90, "B": 75, "C": 60, "D": 40, "F": 0}.get(ssl_grade, 0)
    score_breakdown["ssl_tls"] = ssl_score
    total_score -= (100 - ssl_score) * 0.3
    
    # WAF Detection (15% weight)
    waf_data = analysis.get("waf_detection", {})
    waf_score = 100 if waf_data.get("detected", False) else 60
    score_breakdown["waf_protection"] = waf_score
    total_score -= (100 - waf_score) * 0.15
    
    # Vulnerabilities (15% weight)
    vuln_data = analysis.get("vulnerability_scan", {})
    vuln_count = vuln_data.get("vulnerabilities_found", 0)
    vuln_score = max(0, 100 - (vuln_count * 20))
    score_breakdown["vulnerabilities"] = vuln_score
    total_score -= (100 - vuln_score) * 0.15
    
    final_score = max(0, min(100, int(total_score)))
    
    return {
        "overall_score": final_score,
        "grade": get_security_grade(final_score),
        "score_breakdown": score_breakdown,
        "risk_level": get_risk_level_from_score(final_score)
    }

def get_security_grade(score: int) -> str:
    """Convert score to letter grade"""
    if score >= 95:
        return "A+"
    elif score >= 90:
        return "A"
    elif score >= 80:
        return "B"
    elif score >= 70:
        return "C"
    elif score >= 60:
        return "D"
    else:
        return "F"

def get_risk_level_from_score(score: int) -> str:
    """Get risk level from score"""
    if score >= 85:
        return "Low Risk"
    elif score >= 70:
        return "Medium Risk"
    elif score >= 50:
        return "High Risk"
    else:
        return "Critical Risk"

def generate_security_recommendations(analysis: Dict) -> List[str]:
    """Generate security recommendations based on analysis"""
    recommendations = []
    
    # Security headers recommendations
    headers_data = analysis.get("security_headers", {})
    missing_critical = headers_data.get("missing_critical", [])
    missing_high = headers_data.get("missing_high", [])
    
    if missing_critical:
        recommendations.append(f"CRITICAL: Implement missing security headers: {', '.join(missing_critical)}")
    
    if missing_high:
        recommendations.append(f"HIGH: Add security headers: {', '.join(missing_high)}")
    
    # SSL recommendations
    ssl_data = analysis.get("ssl_analysis", {})
    ssl_grade = ssl_data.get("overall_grade", "F")
    if ssl_grade in ["D", "F"]:
        recommendations.append("CRITICAL: Upgrade SSL/TLS configuration")
    elif ssl_grade in ["C"]:
        recommendations.append("MEDIUM: Consider improving SSL/TLS configuration")
    
    # WAF recommendations
    waf_data = analysis.get("waf_detection", {})
    if not waf_data.get("detected", False):
        recommendations.append("MEDIUM: Consider implementing a Web Application Firewall (WAF)")
    
    # HTTPS recommendations
    if not analysis.get("https_available", False):
        recommendations.append("CRITICAL: Enable HTTPS for secure communication")
    elif not analysis.get("https_redirect", False):
        recommendations.append("MEDIUM: Implement automatic HTTP to HTTPS redirect")
    
    return recommendations[:10]

def format_security_report(analysis: Dict) -> str:
    """Format security analysis into readable report"""
    if "Error" in analysis:
        return f"❌ Security Analysis Error: {analysis['Error']}"
    
    report = []
    
    # Header
    domain = analysis.get("domain", "Unknown")
    report.append("=" * 60)
    report.append(f"🛡️  SECURITY ANALYSIS REPORT FOR {domain.upper()}")
    report.append("=" * 60)
    
    # Overall Score
    security_score = analysis.get("security_score", {})
    score = security_score.get("overall_score", 0)
    grade = security_score.get("grade", "F")
    risk_level = security_score.get("risk_level", "Unknown")
    
    report.append(f"\n📊 OVERALL SECURITY ASSESSMENT")
    report.append(f"   Security Score: {score}/100")
    report.append(f"   Security Grade: {grade}")
    report.append(f"   Risk Level: {risk_level}")
    
    # HTTPS Status
    https_available = analysis.get("https_available", False)
    https_redirect = analysis.get("https_redirect", False)
    
    report.append(f"\n🔒 HTTPS STATUS")
    report.append(f"   HTTPS Available: {'✅ Yes' if https_available else '❌ No'}")
    report.append(f"   HTTP to HTTPS Redirect: {'✅ Yes' if https_redirect else '❌ No'}")
    
    # SSL/TLS Analysis
    ssl_data = analysis.get("ssl_analysis", {})
    if ssl_data.get("ssl_available", False):
        report.append(f"\n🔐 SSL/TLS CONFIGURATION")
        report.append(f"   Overall Grade: {ssl_data.get('overall_grade', 'Unknown')}")
        report.append(f"   Protocol Version: {ssl_data.get('protocol_version', 'Unknown')}")
        report.append(f"   Cipher Suite: {ssl_data.get('cipher_suite', 'Unknown')}")
        report.append(f"   Cipher Strength: {ssl_data.get('cipher_strength', 'Unknown')}")
    else:
        report.append(f"\n🔐 SSL/TLS CONFIGURATION")
        report.append(f"   Status: ❌ SSL/TLS Not Available")
    
    # WAF Detection
    waf_data = analysis.get("waf_detection", {})
    report.append(f"\n🛡️  WEB APPLICATION FIREWALL")
    if waf_data.get("detected", False):
        primary_waf = waf_data.get("primary_waf", {})
        provider = primary_waf.get("provider", "Unknown")
        confidence = primary_waf.get("confidence", "Unknown")
        report.append(f"   Status: ✅ Detected")
        report.append(f"   Provider: {provider}")
        report.append(f"   Confidence: {confidence}")
    else:
        report.append(f"   Status: ❌ No WAF Detected")
    
    # Security Headers
    headers_data = analysis.get("security_headers", {})
    if "headers" in headers_data:
        report.append(f"\n🔧 SECURITY HEADERS")
        report.append(f"   Overall Score: {headers_data.get('score', 0)}/100")
        
        for header_name, header_info in headers_data["headers"].items():
            status = "✅" if header_info.get("present", False) else "❌"
            importance = header_info.get("importance", "Unknown")
            report.append(f"   {status} {header_name} ({importance})")
        
        # Missing critical headers
        missing_critical = headers_data.get("missing_critical", [])
        if missing_critical:
            report.append(f"\n   🚨 Missing Critical Headers:")
            for header in missing_critical:
                report.append(f"      • {header}")
    
    # Cookie Security
    cookie_data = analysis.get("cookie_security", {})
    report.append(f"\n🍪 COOKIE SECURITY")
    if cookie_data.get("cookies_present", False):
        cookie_score = cookie_data.get("security_score", 0)
        report.append(f"   Security Score: {cookie_score}/100")
        
        issues = cookie_data.get("security_issues", [])
        if issues:
            report.append(f"   Issues Found:")
            for issue in issues:
                report.append(f"      • {issue}")
        else:
            report.append(f"   Status: ✅ Secure Configuration")
    else:
        report.append(f"   Status: ℹ️  No Cookies Detected")
    
    # Vulnerabilities
    vuln_data = analysis.get("vulnerability_scan", {})
    vuln_count = vuln_data.get("vulnerabilities_found", 0)
    report.append(f"\n🔍 VULNERABILITY SCAN")
    report.append(f"   Vulnerabilities Found: {vuln_count}")
    report.append(f"   Risk Level: {vuln_data.get('risk_level', 'Unknown')}")
    
    if vuln_count > 0:
        vulnerabilities = vuln_data.get("vulnerabilities", [])
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "Unknown")
            description = vuln.get("description", "No description")
            report.append(f"      • {severity}: {description}")
    
    # Server Information
    server_data = analysis.get("server_information", {})
    disclosure_count = server_data.get("disclosure_count", 0)
    report.append(f"\n🖥️  SERVER INFORMATION")
    report.append(f"   Information Disclosure Issues: {disclosure_count}")
    
    if disclosure_count > 0:
        disclosures = server_data.get("information_disclosure", [])
        for disclosure in disclosures:
            report.append(f"      • {disclosure}")
    
    # Recommendations
    recommendations = analysis.get("recommendations", [])
    if recommendations:
        report.append(f"\n💡 SECURITY RECOMMENDATIONS")
        for i, recommendation in enumerate(recommendations, 1):
            report.append(f"   {i}. {recommendation}")
    
    # Footer
    execution_time = analysis.get("execution_time", 0)
    report.append(f"\n" + "=" * 60)
    report.append(f"Analysis completed in {execution_time:.2f} seconds")
    report.append("=" * 60)
    
    return "\n".join(report)

# Main execution - Update to use formatted output
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python security_analyzer.py <domain>")
        print("Example: python security_analyzer.py example.com")
        sys.exit(1)
    
    domain = sys.argv[1]
    print(f"🔍 Analyzing security for {domain}...")
    
    try:
        results = analyze_security(domain)
        
        # Display formatted report
        print("\n" + format_security_report(results))
        
        # Save detailed JSON results
        with open(f"{domain}_security_analysis.json", 'w') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"\n📄 Detailed JSON results saved to {domain}_security_analysis.json")
        
    except KeyboardInterrupt:
        print("\n⏹️  Analysis interrupted by user")
    except Exception as e:
        print(f"❌ Unexpected error: {str(e)}")

"""
DÜZELTMELER:
✅ Optional type hints eklendi
✅ Fazla karmaşık fonksiyonlar sadeleştirildi
✅ Error handling iyileştirildi
✅ Import sorunları düzeltildi
✅ Gereksiz fonksiyonlar kaldırıldı
✅ Daha stabil kod yapısı

TEMEL ÖZELLİKLER:
🛡️ WAF Detection (Cloudflare, Akamai, F5, AWS vb.)
🔒 Security Headers Analysis
🔐 SSL/TLS Analysis
🍪 Cookie Security
📊 Security Scoring (0-100)
🔍 Basic Vulnerability Scanning
⚠️ Risk Assessment
💡 Security Recommendations
"""