import socket
import ssl
import subprocess
import datetime
import json
import re
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib.request
import urllib.error


def get_domain_info(domain, api_key=None):
    """
    Domain hakkında kapsamlı bilgi toplar - 3. parti API kullanmadan
    """
    domain_info = {}
    
    # Domain temizleme
    domain = clean_domain(domain)
    domain_info["Domain"] = domain
    
    # IP Adresi al (IPv4 ve IPv6)
    ip_info = get_ip_address(domain)
    domain_info["IP Address"] = ip_info.get("ipv4", "Bulunamadı")
    domain_info["IPv6 Address"] = ip_info.get("ipv6", [])
    domain_info["All IPv4"] = ip_info.get("all_ipv4", [])
    
    # Reverse DNS
    if ip_info.get("ipv4"):
        domain_info["Reverse DNS"] = get_reverse_dns(ip_info["ipv4"])
    
    # WHOIS bilgilerini al
    whois_data = get_whois_data(domain)
    domain_info.update(whois_data)
    
    # SSL Sertifika bilgileri
    domain_info["SSL Information"] = get_ssl_certificate_info(domain)
    
    # DNS bilgileri
    dns_info = get_dns_records(domain)
    domain_info["Name Servers"] = dns_info.get("nameservers", "Bulunamadı")
    domain_info["MX Records"] = dns_info.get("mx_records", [])
    domain_info["TXT Records"] = dns_info.get("txt_records", [])
    domain_info["SPF Record"] = dns_info.get("spf", "Yok")
    domain_info["DMARC Record"] = dns_info.get("dmarc", "Yok")
    
    # Port taraması (paralel ve hızlı)
    domain_info["Open Ports"] = check_common_ports(ip_info.get("ipv4", ""))
    
    # HTTP/HTTPS bilgileri
    http_info = check_http_status(domain)
    domain_info["HTTP Status"] = http_info.get("status", "Erişilemedi")
    domain_info["Web Server"] = http_info.get("server", "Unknown")
    domain_info["Response Time (ms)"] = http_info.get("response_time", "N/A")
    
    # Güvenlik kontrolleri
    security_info = check_security(domain)
    domain_info["HTTPS Available"] = security_info.get("https_available", False)
    domain_info["HTTPS Redirect"] = security_info.get("https_redirect", False)
    domain_info["Security Headers"] = security_info.get("headers_count", 0)
    domain_info["Security Score"] = calculate_security_score(domain_info, security_info)
    
    return domain_info


def clean_domain(domain):
    """Domain'i temizle - http/https ve path'leri kaldır"""
    if '://' in domain:
        domain = urlparse(domain).netloc
    if not domain:
        domain = urlparse('http://' + domain).netloc
    domain = domain.replace('www.', '')
    return domain.split('/')[0].split(':')[0]


def get_ip_address(domain):
    """Domain'in IP adreslerini al (IPv4 ve IPv6)"""
    result = {"ipv4": None, "ipv6": [], "all_ipv4": []}
    
    try:
        # IPv4
        result["ipv4"] = socket.gethostbyname(domain)
        # Tüm IPv4 adresleri
        result["all_ipv4"] = socket.gethostbyname_ex(domain)[2]
    except:
        pass
    
    try:
        # IPv6
        ipv6_info = socket.getaddrinfo(domain, None, socket.AF_INET6)
        result["ipv6"] = [addr[4][0] for addr in ipv6_info]
    except:
        pass
    
    return result


def get_reverse_dns(ip_address):
    """Reverse DNS lookup"""
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except:
        return "Bulunamadı"


def get_whois_server(domain):
    """TLD'ye göre WHOIS sunucusunu belirle"""
    tld = domain.split('.')[-1].lower()
    
    whois_servers = {
        'com': 'whois.verisign-grs.com',
        'net': 'whois.verisign-grs.com',
        'org': 'whois.pir.org',
        'info': 'whois.afilias.net',
        'biz': 'whois.biz',
        'us': 'whois.nic.us',
        'uk': 'whois.nic.uk',
        'de': 'whois.denic.de',
        'fr': 'whois.nic.fr',
        'it': 'whois.nic.it',
        'nl': 'whois.domain-registry.nl',
        'eu': 'whois.eu',
        'ru': 'whois.tcinet.ru',
        'cn': 'whois.cnnic.cn',
        'jp': 'whois.jprs.jp',
        'br': 'whois.registro.br',
        'au': 'whois.auda.org.au',
        'ca': 'whois.cira.ca',
        'in': 'whois.registry.in',
        'tr': 'whois.nic.tr',
        'co': 'whois.nic.co',
        'io': 'whois.nic.io',
        'me': 'whois.nic.me',
        'tv': 'whois.nic.tv',
        'cc': 'whois.nic.cc'
    }
    
    return whois_servers.get(tld, 'whois.iana.org')


def query_whois_server(domain, server, port=43, timeout=10):
    """WHOIS sunucusuna doğrudan TCP bağlantısı ile sorgu yap"""
    try:
        # Socket ile WHOIS sunucusuna bağlan
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((server, port))
        
        # Domain sorgusunu gönder
        sock.send(f"{domain}\r\n".encode())
        
        # Yanıtı al
        response = b""
        while True:
            data = sock.recv(4096)
            if not data:
                break
            response += data
        
        sock.close()
        return response.decode('utf-8', errors='ignore')
    
    except socket.timeout:
        return None
    except Exception as e:
        return None


def get_whois_data(domain):
    """Python socket ile WHOIS sorgula - sistem komutu gerektirmez"""
    whois_info = {
        "Registrar Company": "Unknown",
        "Creation Date": "Unknown",
        "Expiry Date": "Unknown",
        "Last Updated": "Unknown",
        "Domain Status": [],
        "Registrant": "Unknown",
        "Privacy Protection": "Unknown"
    }
    
    try:
        # WHOIS sunucusunu belirle
        whois_server = get_whois_server(domain)
        
        # İlk sorgu
        output = query_whois_server(domain, whois_server)
        
        if not output:
            whois_info["Error"] = "WHOIS sunucusuna bağlanılamadı"
            return whois_info
        
        # Bazı TLD'ler yönlendirme yapar (örn: .com -> specific registrar)
        referral_match = re.search(r'Registrar WHOIS Server:\s*(.+)', output, re.IGNORECASE)
        if referral_match:
            referral_server = referral_match.group(1).strip()
            # Protokolü temizle
            referral_server = referral_server.replace('whois://', '').replace('http://', '').replace('https://', '')
            
            # Yönlendirilen sunucudan tekrar sorgula
            referral_output = query_whois_server(domain, referral_server)
            if referral_output:
                output = referral_output
        
        # Registrar
        for pattern in [r"Registrar:\s*(.+)", r"Registrar Name:\s*(.+)", r"Registrar Organization:\s*(.+)"]:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                whois_info["Registrar Company"] = match.group(1).strip()
                break
        
        # Creation Date
        for pattern in [
            r"Creation Date:\s*(.+)",
            r"Created Date:\s*(.+)",
            r"Created:\s*(.+)",
            r"created:\s*(.+)",
            r"Registration Time:\s*(.+)"
        ]:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                whois_info["Creation Date"] = match.group(1).strip().split('\n')[0]
                break
        
        # Expiry Date
        for pattern in [
            r"Registry Expiry Date:\s*(.+)",
            r"Registrar Registration Expiration Date:\s*(.+)",
            r"Expir(?:y|ation) Date:\s*(.+)",
            r"expires:\s*(.+)",
            r"Expiration Time:\s*(.+)"
        ]:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                whois_info["Expiry Date"] = match.group(1).strip().split('\n')[0]
                break
        
        # Updated Date
        for pattern in [
            r"Updated Date:\s*(.+)",
            r"Last Updated:\s*(.+)",
            r"last-update:\s*(.+)",
            r"Modified Date:\s*(.+)"
        ]:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                whois_info["Last Updated"] = match.group(1).strip().split('\n')[0]
                break
        
        # Domain Status
        statuses = re.findall(r"(?:Domain )?Status:\s*(.+)", output, re.IGNORECASE)
        if statuses:
            whois_info["Domain Status"] = [s.strip().split()[0] for s in statuses[:3]]
        else:
            whois_info["Domain Status"] = ["Unknown"]
        
        # Registrant
        for pattern in [
            r"Registrant Name:\s*(.+)",
            r"Registrant:\s*(.+)",
            r"Registrant Organization:\s*(.+)",
            r"Registrant Contact Name:\s*(.+)"
        ]:
            match = re.search(pattern, output, re.IGNORECASE)
            if match:
                value = match.group(1).strip().split('\n')[0]
                if value:
                    whois_info["Registrant"] = value
                    break
        
        # Privacy Protection
        privacy_keywords = ["REDACTED", "Privacy", "GDPR", "Protected", "Proxy", "PRIVATE"]
        if any(keyword.lower() in output.lower() for keyword in privacy_keywords):
            whois_info["Privacy Protection"] = "Active"
        else:
            whois_info["Privacy Protection"] = "Inactive"
        
        # Name Servers (ek bilgi)
        nameservers = re.findall(r"Name Server:\s*(.+)", output, re.IGNORECASE)
        if nameservers:
            whois_info["WHOIS Name Servers"] = [ns.strip().lower() for ns in nameservers[:4]]
            
    except Exception as e:
        whois_info["Error"] = f"WHOIS hatası: {str(e)}"
    
    return whois_info


def get_ssl_certificate_info(domain):
    """SSL sertifika bilgilerini al - iyileştirilmiş"""
    ssl_info = {}
    
    try:
        context = ssl.create_default_context()
        
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                ssl_info["SSL Status"] = "Valid"
                ssl_info["Protocol Version"] = ssock.version()
                ssl_info["Cipher Suite"] = ssock.cipher()[0] if ssock.cipher() else "Unknown"
                
                if cert:
                    # Subject
                    subject = dict(x[0] for x in cert.get('subject', []))
                    ssl_info["Issued To"] = subject.get('commonName', 'Unknown')
                    
                    # Issuer
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    ssl_info["Issuer"] = issuer.get('commonName', 'Unknown')
                    ssl_info["Issuer Organization"] = issuer.get('organizationName', 'Unknown')
                    
                    # Dates
                    not_after = cert.get('notAfter', '')
                    if not_after:
                        expiry_date = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        ssl_info["Expiry Date"] = expiry_date.strftime('%Y-%m-%d')
                        
                        days_left = (expiry_date - datetime.datetime.now()).days
                        ssl_info["Days Until Expiry"] = days_left
                        
                        if expiry_date < datetime.datetime.now():
                            ssl_info["SSL Status"] = "Expired"
                        elif days_left < 30:
                            ssl_info["SSL Status"] = "Expiring Soon"
                    
                    # SAN (Subject Alternative Names)
                    san = cert.get('subjectAltName', [])
                    if san:
                        ssl_info["Alternative Names"] = [name[1] for name in san if name[0] == 'DNS'][:5]
                else:
                    ssl_info["SSL Status"] = "No certificate found"
                    
    except socket.timeout:
        ssl_info["SSL Status"] = "Connection timeout"
    except ConnectionRefusedError:
        ssl_info["SSL Status"] = "HTTPS not available"
    except ssl.SSLError as e:
        ssl_info["SSL Status"] = f"SSL Error: {str(e)}"
    except Exception as e:
        ssl_info["SSL Status"] = f"Error: {str(e)}"
    
    return ssl_info


def get_dns_records(domain):
    """DNS kayıtlarını al - genişletilmiş"""
    dns_info = {
        "nameservers": [],
        "mx_records": [],
        "txt_records": [],
        "spf": None,
        "dmarc": None
    }
    
    # Nameservers
    try:
        result = subprocess.run(
            ["nslookup", "-type=NS", domain],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            nameservers = re.findall(r'nameserver = (.+)', result.stdout)
            dns_info["nameservers"] = [ns.strip('.') for ns in nameservers]
    except:
        pass
    
    # MX Records
    try:
        result = subprocess.run(
            ["nslookup", "-type=MX", domain],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            mx_records = re.findall(r'mail exchanger = \d+ (.+)', result.stdout)
            dns_info["mx_records"] = [mx.strip('.') for mx in mx_records]
    except:
        pass
    
    # TXT Records (SPF, DMARC, vb.)
    try:
        result = subprocess.run(
            ["nslookup", "-type=TXT", domain],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            txt_records = re.findall(r'"([^"]+)"', result.stdout)
            dns_info["txt_records"] = txt_records
            
            # SPF
            for txt in txt_records:
                if txt.startswith('v=spf1'):
                    dns_info["spf"] = txt
                elif txt.startswith('v=DMARC1'):
                    dns_info["dmarc"] = txt
    except:
        pass
    
    # Format output
    if dns_info["nameservers"]:
        dns_info["nameservers"] = ", ".join(dns_info["nameservers"][:3])
    else:
        dns_info["nameservers"] = "Bulunamadı"
    
    return dns_info


def check_common_ports(ip_address):
    """Yaygın portları paralel kontrol et - çok daha hızlı"""
    if not ip_address or ip_address == "Bulunamadı":
        return "IP adresi olmadan port taraması yapılamaz"
    
    common_ports = {
        21: "FTP", 22: "SSH", 25: "SMTP", 80: "HTTP",
        443: "HTTPS", 3306: "MySQL", 5432: "PostgreSQL",
        8080: "HTTP-Alt", 8443: "HTTPS-Alt"
    }
    
    def check_port(port, service):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        try:
            result = sock.connect_ex((ip_address, port))
            if result == 0:
                return f"{port}/{service}"
        except:
            pass
        finally:
            sock.close()
        return None
    
    open_ports = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_port, port, service): port 
                  for port, service in common_ports.items()}
        
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
    
    if open_ports:
        return ", ".join(sorted(open_ports))
    else:
        return "Açık port bulunamadı"


def check_http_status(domain):
    """HTTP durum kodunu ve web sunucu bilgilerini kontrol et"""
    http_info = {"status": "Erişilemedi", "server": "Unknown", "response_time": None}
    
    protocols = ['https://', 'http://']
    
    for protocol in protocols:
        try:
            import time
            url = protocol + domain
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            
            start_time = time.time()
            response = urllib.request.urlopen(req, timeout=5)
            response_time = round((time.time() - start_time) * 1000, 2)
            
            http_info["status"] = f"{response.code} - {protocol.replace('://', '').upper()}"
            http_info["server"] = response.headers.get('Server', 'Unknown')
            http_info["response_time"] = response_time
            
            return http_info
            
        except urllib.error.HTTPError as e:
            http_info["status"] = f"{e.code} - HTTP Error"
            return http_info
        except urllib.error.URLError:
            continue
        except Exception:
            continue
    
    return http_info


def check_security(domain):
    """Güvenlik özelliklerini kontrol et"""
    security = {
        "https_available": False,
        "https_redirect": False,
        "headers_count": 0,
        "security_headers": {}
    }
    
    # HTTPS kontrolü ve security headers
    try:
        req = urllib.request.Request(
            f"https://{domain}",
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        response = urllib.request.urlopen(req, timeout=5)
        security["https_available"] = True
        
        # Security Headers
        important_headers = [
            'Strict-Transport-Security',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'X-XSS-Protection',
            'Content-Security-Policy'
        ]
        
        for header in important_headers:
            value = response.headers.get(header)
            if value:
                security["security_headers"][header] = value
                security["headers_count"] += 1
    except:
        pass
    
    # HTTP -> HTTPS redirect kontrolü
    try:
        req = urllib.request.Request(
            f"http://{domain}",
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        response = urllib.request.urlopen(req, timeout=5)
        if response.url.startswith('https://'):
            security["https_redirect"] = True
    except:
        pass
    
    return security


def calculate_security_score(domain_info, security_info):
    """Basit güvenlik skoru hesapla (0-100)"""
    score = 0
    
    # HTTPS mevcut mu? (+30)
    if security_info.get("https_available"):
        score += 30
    
    # HTTPS redirect var mı? (+10)
    if security_info.get("https_redirect"):
        score += 10
    
    # SSL geçerli mi? (+20)
    ssl_info = domain_info.get("SSL Information", {})
    if ssl_info.get("SSL Status") == "Valid":
        score += 20
    
    # Security headers var mı? (+20)
    score += min(security_info.get("headers_count", 0) * 4, 20)
    
    # SPF kaydı var mı? (+10)
    if domain_info.get("SPF Record") and domain_info["SPF Record"] != "Yok":
        score += 10
    
    # DMARC kaydı var mı? (+10)
    if domain_info.get("DMARC Record") and domain_info["DMARC Record"] != "Yok":
        score += 10
    
    return score


# Eski fonksiyonlarla uyumluluk için
def get_nameservers(domain):
    """Eski API uyumluluğu için"""
    dns_info = get_dns_records(domain)
    return dns_info.get("nameservers", "Bulunamadı")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Kullanım: python domain_analyzer.py <domain>")
        print("Örnek: python domain_analyzer.py google.com")
        sys.exit(1)
    
    print("Domain analizi başlatılıyor...\n")
    
    result = get_domain_info(sys.argv[1])
    
    # Sonuçları güzel formatta göster
    print("=" * 70)
    print(f"DOMAIN ANALİZ RAPORU: {result['Domain']}")
    print("=" * 70)
    
    for key, value in result.items():
        if key == "Domain":
            continue
        
        if isinstance(value, dict):
            print(f"\n{key}:")
            for k, v in value.items():
                print(f"  {k}: {v}")
        elif isinstance(value, list):
            if value:
                print(f"\n{key}:")
                for item in value:
                    print(f"  - {item}")
            else:
                print(f"\n{key}: Yok")
        else:
            print(f"\n{key}: {value}")
    
    print("\n" + "=" * 70)
