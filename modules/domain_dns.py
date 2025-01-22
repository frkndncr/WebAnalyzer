import dns.resolver
import time

def get_dns_records(domain):
    """
    Queries the DNS records of a domain and returns detailed results.
    """
    dns_info = {}

    # A Records (IPv4)
    dns_info["A Records (IPv4)"] = resolve_dns(domain, "A")

    # AAAA Records (IPv6)
    dns_info["AAAA Records (IPv6)"] = resolve_dns(domain, "AAAA")

    # MX Records (Mail Servers)
    dns_info["MX Records (Mail Servers)"] = resolve_dns(domain, "MX")

    # TXT Records (Verification Details)
    dns_info["TXT Records"] = resolve_dns(domain, "TXT")

    # NS Records (Name Servers)
    dns_info["NS Records (Name Servers)"] = resolve_dns(domain, "NS")

    # DNS response time
    dns_info["Response Time (ms)"] = measure_dns_response_time(domain)

    return dns_info


def resolve_dns(domain, record_type):
    """
    Resolves a specific DNS record type for a given domain.
    """
    try:
        answers = dns.resolver.resolve(domain, record_type)
        return [str(rdata) for rdata in answers]
    except dns.resolver.NoAnswer:
        return ["No Record Found"]
    except dns.resolver.NXDOMAIN:
        return ["Invalid Domain"]
    except Exception as e:
        return [f"Error: {e}"]


def measure_dns_response_time(domain):
    """
    Measures the response time of a DNS query.
    """
    try:
        start_time = time.time()
        dns.resolver.resolve(domain, "A")
        end_time = time.time()
        return round((end_time - start_time) * 1000, 2)
    except Exception:
        return "Could not measure"
