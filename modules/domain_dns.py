import dns.resolver
import time
import re
from datetime import datetime
from typing import Dict, List, Union
from collections import defaultdict
import concurrent.futures

class DNSAnalyzer:
    """Ultra-fast DNS analysis tool with minimal overhead"""
    
    def __init__(self, max_history: int = 10):
        self.history = defaultdict(list)
        self.max_history = max_history
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 1.0  # Hızlı timeout
        self.resolver.lifetime = 1.0  # Toplam sorgu süresi limiti

    def get_dns_records(self, domain: str) -> Dict:
        """Fetch DNS records ultra-fast"""
        dns_info = {
            "timestamp": datetime.now().isoformat(),
            "domain": domain,
            "records": self._resolve_all_dns(domain),
            "response_time_ms": self._measure_dns_response_time(domain)
        }
        
        # Add DNS Security Audit
        dns_info["security_audit"] = self.audit_dns_security(domain)

        self._update_history(domain, dns_info)
        return dns_info

    def audit_dns_security(self, domain: str) -> Dict:
        """Perform security audit on domain's SPF, DMARC, DNSSEC and CAA records"""
        score = 100
        issues = []
        
        # 1. SPF Audit
        spf_status = "Missing"
        spf_record = ""
        spf_issues = []
        try:
            txt_records = self.resolver.resolve(domain, "TXT")
            for record in txt_records:
                record_str = str(record).replace('"', '').strip()
                if record_str.startswith("v=spf1"):
                    spf_status = "Found"
                    spf_record = record_str
                    break
        except Exception:
            pass
            
        if spf_status == "Missing":
            score -= 30
            spf_issues.append("SPF record is missing. Attackers can spoof emails from this domain.")
            issues.append("Missing SPF record")
        else:
            if "+all" in spf_record or "?all" in spf_record:
                score -= 20
                spf_issues.append("SPF ends with +all or ?all, allowing any sender to spoof mail.")
                issues.append("Weak SPF policy (+all/?all)")
                
        # 2. DMARC Audit
        dmarc_status = "Missing"
        dmarc_record = ""
        dmarc_issues = []
        try:
            dmarc_txt = self.resolver.resolve(f"_dmarc.{domain}", "TXT")
            for record in dmarc_txt:
                record_str = str(record).replace('"', '').strip()
                if record_str.startswith("v=DMARC1"):
                    dmarc_status = "Found"
                    dmarc_record = record_str
                    break
        except Exception:
            pass
            
        if dmarc_status == "Missing":
            score -= 35
            dmarc_issues.append("DMARC record is missing. No protection against email spoofing.")
            issues.append("Missing DMARC record")
        else:
            policy_match = re.search(r"p=(none|quarantine|reject)", dmarc_record, re.IGNORECASE)
            if policy_match:
                policy = policy_match.group(1).lower()
                if policy == "none":
                    score -= 15
                    dmarc_issues.append("DMARC policy set to 'p=none' (monitoring only, spoofed mail is still delivered).")
                    issues.append("Weak DMARC policy (p=none)")
            else:
                score -= 20
                dmarc_issues.append("DMARC record is misconfigured (no valid p= policy found).")
                issues.append("Misconfigured DMARC policy")
                
        # 3. DNSSEC Check
        dnssec_enabled = False
        try:
            dnskey_records = self.resolver.resolve(domain, "DNSKEY")
            if dnskey_records:
                dnssec_enabled = True
        except Exception:
            pass
            
        if not dnssec_enabled:
            score -= 15
            issues.append("DNSSEC is not enabled")
            
        # 4. CAA Check
        caa_status = "Missing"
        try:
            caa_records = self.resolver.resolve(domain, "CAA")
            if caa_records and len(caa_records) > 0 and str(caa_records[0]) != "No Record":
                caa_status = "Found"
        except Exception:
            pass
            
        if caa_status == "Missing":
            score -= 10
            issues.append("Missing CAA record")
            
        score = max(0, score)
        
        # Calculate grade
        if score >= 90: grade = "A"
        elif score >= 75: grade = "B"
        elif score >= 60: grade = "C"
        elif score >= 45: grade = "D"
        else: grade = "F"
        
        return {
            "score": score,
            "grade": grade,
            "spf": {
                "status": spf_status,
                "record": spf_record,
                "issues": spf_issues
            },
            "dmarc": {
                "status": dmarc_status,
                "record": dmarc_record,
                "issues": dmarc_issues
            },
            "dnssec": {
                "enabled": dnssec_enabled
            },
            "caa": {
                "status": caa_status
            },
            "weaknesses": issues
        }

    def _resolve_all_dns(self, domain: str) -> Dict:
        """Resolve all DNS records concurrently with minimal types"""
        record_types = ["A (IPv4)", "AAAA (IPv6)", "MX (Mail Servers)", 
                        "NS (Name Servers)", "SOA (Authority)"]
        results = {}
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            future_to_type = {executor.submit(self._resolve_dns, domain, rtype.split()[0]): rtype 
                            for rtype in record_types}
            for future in concurrent.futures.as_completed(future_to_type):
                rtype = future_to_type[future]
                try:
                    results[rtype] = future.result()
                except Exception as e:
                    results[rtype] = [f"Error: {str(e)}"]
        return results

    def _resolve_dns(self, domain: str, record_type: str) -> List[str]:
        try:
            answers = self.resolver.resolve(domain, record_type)
            return [str(rdata) for rdata in answers]
        except dns.resolver.NoAnswer:
            return ["No Record"]
        except dns.resolver.NXDOMAIN:
            return ["Invalid Domain"]
        except Exception as e:
            return [f"Error: {str(e)[:50]}..."]

    def _measure_dns_response_time(self, domain: str) -> Union[float, str]:
        try:
            start_time = time.time()
            self.resolver.resolve(domain, "A")
            return round((time.time() - start_time) * 1000, 2)
        except Exception:
            return "N/A"

    def _update_history(self, domain: str, dns_info: Dict) -> None:
        self.history[domain].append(dns_info)
        self.history[domain] = self.history[domain][-self.max_history:]

    def get_domain_history(self, domain: str) -> List[Dict]:
        return self.history.get(domain, [])

    def generate_report(self, domain: str, color: bool = False) -> str:
        """Generate a fast, clean, and beautiful report with security audit"""
        dns_info = self.get_dns_records(domain)
        c = lambda x, y: f"\033[{x}m{y}\033[0m" if color else y  # Renk fonksiyonu
        report = [
            c(96, f"🔍 DNS Report: {domain}"),
            c(90, f"Generated: {dns_info['timestamp']}"),
            c(90, "─" * 40)
        ]

        # DNS Records
        for rtype, records in dns_info["records"].items():
            report.append(c(94, f"{rtype}"))
            for record in records:
                report.append(f"  {record[:70]}{'...' if len(record) > 70 else ''}")

        # Response Time
        report.append("")
        report.append(c(92, f"⏱  Response Time: {dns_info['response_time_ms']} ms"))
        
        # Security Audit Section
        sec = dns_info["security_audit"]
        report.append("")
        report.append(c(95, "🛡️  DNS Security Audit"))
        report.append(c(90, "─" * 40))
        
        grade_color = 92 if sec["grade"] in ["A", "B"] else (93 if sec["grade"] in ["C", "D"] else 91)
        report.append(f"Security Grade: " + c(grade_color, f"{sec['grade']} ({sec['score']}/100)"))
        report.append(f"SPF Status    : {sec['spf']['status']}")
        report.append(f"DMARC Status  : {sec['dmarc']['status']}")
        report.append(f"DNSSEC Enabled: {'Yes' if sec['dnssec']['enabled'] else 'No'}")
        report.append(f"CAA Status    : {sec['caa']['status']}")
        
        if sec["weaknesses"]:
            report.append("")
            report.append(c(91, "⚠️  Security Weaknesses Detected:"))
            for issue in sec["weaknesses"]:
                report.append(f"  - {issue}")

        return "\n".join(report)

def main(domain: str) -> Dict:
    """Main function for main.py compatibility"""
    analyzer = DNSAnalyzer()
    return analyzer.get_dns_records(domain)
