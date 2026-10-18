"""The built-in analysis modules, registered with :mod:`modules.registry`.

Each module imports its implementation lazily, so loading the catalogue is cheap
and a missing optional dependency only affects the one module that needs it
(it fails with an error result instead of stopping the platform).
"""
from modules.registry import ModuleSpec, register


def _domain_information(domain):
    from modules.domain_info import get_domain_info
    return get_domain_info(domain)


def _dns_records(domain):
    from modules.domain_dns import DNSAnalyzer
    return DNSAnalyzer().get_dns_records(domain)


def _seo_analysis(domain):
    from modules.seo_analysis import analyze_advanced_seo
    return analyze_advanced_seo(domain)


def _web_technologies(domain):
    from modules.web_technologies import detect_web_technologies
    return detect_web_technologies(domain)


def _security_analysis(domain):
    from modules.security_analysis import analyze_security
    return analyze_security(domain)


def _advanced_content_scan(domain):
    from modules.advanced_content_scanner import AdvancedContentScanner
    return AdvancedContentScanner(domain).run()


def _contact_spy(domain):
    from modules.contact_spy import GlobalDomainScraper
    return GlobalDomainScraper(domain).crawl()


def _subdomain_discovery(domain):
    from modules.subfinder_tool import run_subfinder
    return run_subfinder(domain)


def _subdomain_takeover(domain):
    from modules.subdomain_takeover import SubdomainTakeover
    from modules.subfinder_tool import run_subfinder
    return SubdomainTakeover(domain).run(run_subfinder(domain))


def _cloudflare_bypass(domain):
    from modules.cloudflare_bypass import CloudflareBypass
    return CloudflareBypass(domain).run()


def _nmap_scan(domain):
    from modules.nmap_zero_day import UltraAdvancedNetworkScanner
    return UltraAdvancedNetworkScanner(domain=domain).run_comprehensive_scan(domain)


def _geo_analysis(domain):
    from modules.geo_analysis import analyze_geo
    return analyze_geo(domain)


def _web_archive_spy(domain):
    from modules.archive_spy import ArchiveSpy
    return ArchiveSpy(domain).run()


def _phishing_protection(domain):
    from modules.phishing_detector import PhishingDetector
    return PhishingDetector(domain).run()


def _ssl_san_association(domain):
    from modules.ssl_association import SSLAssociation
    return SSLAssociation(domain).run()


def _attack_path_planner(domain, results):
    from modules.attack_path_planner import AttackPathPlanner
    return AttackPathPlanner(domain, findings=results).run()


# name, function, description, group, weight, extra options (order is the list position)
_BUILTIN = [
    ("Domain Information", _domain_information, "WHOIS, registrar, dates", "recon", "light", {}),
    ("DNS Records", _dns_records, "A, MX, TXT, CNAME records", "recon", "light", {}),
    ("GEO Analysis", _geo_analysis, "Geolocation & AI directives", "recon", "light", {}),
    ("SEO Analysis", _seo_analysis, "Meta tags, Open Graph", "recon", "medium", {}),
    ("Web Technologies", _web_technologies, "Frameworks, CMS, stack", "recon", "medium", {}),
    ("Contact Spy", _contact_spy, "Emails, phones, socials", "recon", "heavy", {}),
    ("Subdomain Discovery", _subdomain_discovery, "Subdomain enumeration", "recon", "heavy", {}),
    ("Security Analysis", _security_analysis, "Headers, SSL/TLS, WAF", "security", "heavy", {}),
    ("Advanced Content Scan", _advanced_content_scan, "Secrets, JS taint, SSRF", "security", "heavy", {"active": True}),
    ("Web Archive Spy", _web_archive_spy, "Wayback secret scraping", "security", "heavy", {"runs_in_loop": True}),
    ("SSL SAN Association", _ssl_san_association, "Certificate asset mapping", "security", "medium", {"runs_in_loop": True}),
    ("Subdomain Takeover", _subdomain_takeover, "Dangling CNAME checks", "offensive", "heavy", {"active": True}),
    ("CloudFlare Bypass", _cloudflare_bypass, "Origin IP unmasking", "offensive", "heavy", {"active": True}),
    ("Nmap Zero Day Scan", _nmap_scan, "Ports & service scan", "offensive", "heavy", {"active": True}),
    ("Phishing Domain Protection", _phishing_protection, "Typosquat detection", "offensive", "heavy", {"runs_in_loop": True}),
    ("Attack Path Planner", _attack_path_planner, "Exploit chain roadmap", "offensive", "medium",
     {"needs_results": True, "runs_in_loop": True}),
]


def register_builtin_modules():
    """Register the built-in modules (safe to call more than once)."""
    for position, (name, fn, description, group, weight, options) in enumerate(_BUILTIN, start=1):
        register(
            ModuleSpec(name=name, run=fn, description=description, group=group, weight=weight,
                       order=position * 10, **options),
            replace=True,
        )


register_builtin_modules()


# Scan presets by name ("full" is every registered module, including plugins).
PRESETS = {
    "quick": ["Domain Information", "DNS Records", "GEO Analysis"],
    "standard": ["Domain Information", "DNS Records", "GEO Analysis", "SEO Analysis",
                 "Web Technologies", "Security Analysis",
                 # light, passive checks shipped as plugins
                 "Email Security", "DNS Health", "TLS Health", "Cookies & CORS", "HTTP Methods & Redirects",
                 "Privacy & Trackers", "JS Library Vulnerabilities", "Security.txt"],
}
