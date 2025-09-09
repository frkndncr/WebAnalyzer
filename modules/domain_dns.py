import dns.resolver
import time
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

        self._update_history(domain, dns_info)
        return dns_info

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
        """Generate a fast, clean, and beautiful report"""
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

        return "\n".join(report)

def main(domain: str) -> Dict:
    """Main function for main.py compatibility"""
    return analyzer.get_dns_records(domain)
