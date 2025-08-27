import requests
from OpenSSL import SSL
import socket


def analyze_security(domain):
    """
    Perform advanced security analysis including WAF detection, security headers,
    HTTPS enforcement, SSL analysis, and CORS policy.
    """
    try:
        http_url = f"http://{domain}"
        https_url = f"https://{domain}"

        # HTTP and HTTPS requests
        response_http = requests.get(http_url, timeout=30, allow_redirects=False)
        response_https = None
        try:
            response_https = requests.get(https_url, timeout=30)
        except requests.exceptions.RequestException:
            pass
        
        # WAF Detection
        waf_signatures = {
            "cloudflare": "Cloudflare",
            "akamai": "Akamai",
            "imperva": "Imperva",
            "sucuri": "Sucuri",
            "barracuda": "Barracuda",
            "f5": "F5 BIG-IP",
            "aws": "AWS WAF",
        }
        waf_detected = None
        for signature, name in waf_signatures.items():
            if signature in response_http.headers.get("X-CDN", "").lower():
                waf_detected = name
                break

        # Security Headers
        security_headers = {
            "Strict-Transport-Security": response_https.headers.get("Strict-Transport-Security", "Not Found")
            if response_https
            else "Not Found",
            "Content-Security-Policy": response_http.headers.get("Content-Security-Policy", "Not Found"),
            "X-Frame-Options": response_http.headers.get("X-Frame-Options", "Not Found"),
            "X-XSS-Protection": response_http.headers.get("X-XSS-Protection", "Not Found"),
            "X-Content-Type-Options": response_http.headers.get("X-Content-Type-Options", "Not Found"),
            "Referrer-Policy": response_http.headers.get("Referrer-Policy", "Not Found"),
            "Permissions-Policy": response_http.headers.get("Permissions-Policy", "Not Found"),
        }

        # CORS Policy
        cors_policy = {
            "Access-Control-Allow-Origin": response_http.headers.get("Access-Control-Allow-Origin", "Not Found"),
            "Access-Control-Allow-Methods": response_http.headers.get("Access-Control-Allow-Methods", "Not Found"),
            "Access-Control-Allow-Headers": response_http.headers.get("Access-Control-Allow-Headers", "Not Found"),
        }

        # HTTPS and SSL Analysis
        ssl_info = {}
        try:
            context = SSL.Context(SSL.SSLv23_METHOD)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ssl_sock = SSL.Connection(context, sock)
            ssl_sock.connect((domain, 443))
            ssl_sock.do_handshake()
            cert = ssl_sock.get_peer_certificate()
            ssl_info = {
                "Issuer": cert.get_issuer().commonName,
                "Validity Start": cert.get_notBefore().decode("utf-8"),
                "Validity End": cert.get_notAfter().decode("utf-8"),
                "Version": cert.get_version(),
            }
        except Exception as e:
            ssl_info = {"Error": str(e)}

        return {
            "Web Application Firewall": waf_detected or "Not Detected",
            "Security Headers": security_headers,
            "SSL Info": ssl_info,
            "CORS Policy": cors_policy,
        }
    except requests.exceptions.RequestException as e:
        return {"Error": f"Could not analyze security: {e}"}
