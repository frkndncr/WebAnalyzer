import logging
import os
import json

logger = logging.getLogger("modules.attack_path_planner")

class AttackPathPlanner:
    def __init__(self, domain, findings=None):
        self.domain = domain
        self.findings = findings
        self.output_dir = os.path.join("logs", self.domain)
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
        self.output_file = os.path.join(self.output_dir, "attack_paths.json")

    async def run(self):
        """Analyzes scan findings and constructs potential attack vector graphs"""
        logger.info(f"Starting Attack Path Exploit Chain Planner for {self.domain}")
        
        # Load other results to aggregate findings
        findings = self.findings
        if not findings:
            results_file = os.path.join(self.output_dir, "results.json")
            findings = {}
            if os.path.exists(results_file):
                try:
                    with open(results_file, "r", encoding="utf-8") as f:
                        findings = json.load(f)
                except Exception as e:
                    logger.error(f"Error loading findings for attack planner: {e}")

        # Construct nodes and edges for the exploit chain graph
        nodes = []
        edges = []
        chains = []

        # Default Entry Node
        nodes.append({
            "id": "entry",
            "label": f"Target: {self.domain}",
            "type": "target",
            "severity": "Info",
            "description": "Initial entry point for external threat actors."
        })

        # Check for DNS/Domain Recon
        dns_data = findings.get("DNS Records", {})
        if dns_data:
            nodes.append({
                "id": "dns_recon",
                "label": "DNS Mapping Discovered",
                "type": "recon",
                "severity": "Info",
                "description": f"Identified {len(dns_data)} DNS records providing infrastructure blueprints."
            })
            edges.append({"from": "entry", "to": "dns_recon", "label": "Passive Recon"})

        # Check for Web Technologies / CMS
        tech_data = findings.get("Web Technologies", {})
        cms_node_id = None
        if isinstance(tech_data, dict):
            # Try to identify CMS
            cms_detected = []
            for tech_name, info in tech_data.items():
                if isinstance(info, dict) and info.get("categories") and "CMS" in info.get("categories", []):
                    cms_detected.append(tech_name)
                elif tech_name.lower() in ["wordpress", "joomla", "drupal", "magento"]:
                    cms_detected.append(tech_name)

            if cms_detected:
                cms_node_id = "cms_recon"
                nodes.append({
                    "id": cms_node_id,
                    "label": f"CMS Detected: {', '.join(cms_detected)}",
                    "type": "technology",
                    "severity": "Info",
                    "description": "Identified CMS framework which dictates potential exploit surfaces."
                })
                edges.append({"from": "entry", "to": cms_node_id, "label": "Fingerprinting"})

        # Check for Subdomains
        subs_data = findings.get("Subdomain Discovery", [])
        if subs_data:
            nodes.append({
                "id": "sub_recon",
                "label": f"Subdomains Found ({len(subs_data)})",
                "type": "recon",
                "severity": "Info",
                "description": "Discovered external host names increasing the total attack surface."
            })
            edges.append({"from": "entry", "to": "sub_recon", "label": "Subdomain Enumeration"})

            # Check Subdomain Takeover Vulnerability
            takeover_data = findings.get("Subdomain Takeover", {})
            vulnerable_subs = []
            if isinstance(takeover_data, dict):
                vulnerable_subs = takeover_data.get("vulnerable_subdomains", takeover_data.get("results", []))
            elif isinstance(takeover_data, list):
                vulnerable_subs = takeover_data

            if vulnerable_subs:
                nodes.append({
                    "id": "sub_takeover",
                    "label": "Subdomain Takeover Risk",
                    "type": "exploit",
                    "severity": "High",
                    "description": f"Vulnerable DNS aliases found in subdomains. Threat actors can hijack domain controls."
                })
                edges.append({"from": "sub_recon", "to": "sub_takeover", "label": "CNAME Hijack"})
                chains.append({
                    "name": "Subdomain Hijacking Path",
                    "steps": ["Subdomain Enumeration", "Identify Dangling CNAMEs", "Register Third-Party Hosting", "Brand Hijack / Phishing Deployment"],
                    "severity": "High",
                    "impact": "Complete control of trusted subdomains to launch spoofing or malware campaigns."
                })

        # Check Port Scanning (Nmap)
        nmap_data = findings.get("Nmap Zero Day Scan", {})
        open_ports = []
        if isinstance(nmap_data, dict):
            open_ports = nmap_data.get("open_ports", nmap_data.get("ports", []))
        if open_ports:
            nodes.append({
                "id": "port_scan",
                "label": f"Active Ports Discovered ({len(open_ports)})",
                "type": "recon",
                "severity": "Info",
                "description": f"Identified active ports: {', '.join([str(p.get('port')) for p in open_ports if isinstance(p, dict)])}."
            })
            edges.append({"from": "entry", "to": "port_scan", "label": "Port Probing"})

            # Look for dangerous open ports
            dangerous_ports = [21, 22, 23, 445, 1433, 3306, 3389]
            detected_danger_ports = [p.get('port') for p in open_ports if isinstance(p, dict) and p.get('port') in dangerous_ports]
            if detected_danger_ports:
                nodes.append({
                    "id": "dangerous_ports",
                    "label": f"Exposed Admin Services: Port {', '.join(map(str, detected_danger_ports))}",
                    "type": "exploit",
                    "severity": "High",
                    "description": "Exposed admin or database service interfaces vulnerable to credential brute-force and remote exploit attacks."
                })
                edges.append({"from": "port_scan", "to": "dangerous_ports", "label": "Service Fingerprinting"})
                
                chains.append({
                    "name": "Management Interface Brute Force",
                    "steps": ["Scan Port Layouts", "Detect Open Admin Services", "Brute-force credentials / Use default logins", "Interactive Remote Console Access"],
                    "severity": "High",
                    "impact": "Unauthorized access to internal systems, databases, or terminal interfaces."
                })

        # Check for Security Vulnerabilities (Security Analysis or ACS)
        sec_data = findings.get("Security Analysis", {})
        acs_data = findings.get("Advanced Content Scan", {})
        
        all_vulns = []
        if isinstance(sec_data, dict):
            all_vulns.extend(sec_data.get("vulnerabilities", []))
        if isinstance(acs_data, dict):
            for key in ["secrets", "js_vulnerabilities", "active_vulnerabilities", "ssrf_vulnerabilities"]:
                all_vulns.extend(acs_data.get(key, []))

        # Check for Exposed Secrets / Credentials
        secrets_found = [v for v in all_vulns if isinstance(v, dict) and any(x in (v.get("type") or v.get("vuln_type") or "").lower() for x in ["secret", "credential", "api_key", "password", "token", "private_key"])]
        if secrets_found:
            nodes.append({
                "id": "leaked_credentials",
                "label": f"Leaked Credentials Found ({len(secrets_found)})",
                "type": "vulnerability",
                "severity": "Critical",
                "description": "Discovered api keys, tokens, or hardcoded server passwords inside public files/scripts."
            })
            edges.append({"from": "entry", "to": "leaked_credentials", "label": "Content Parsing"})
            
            # Pivot from credentials to cloud or API access
            nodes.append({
                "id": "unauthorized_api_access",
                "label": "Third-Party / Cloud Resource Takeover",
                "type": "exploit",
                "severity": "Critical",
                "description": "Leveraging leaked secrets to hijack backend cloud providers, databases, or internal application servers."
            })
            edges.append({"from": "leaked_credentials", "to": "unauthorized_api_access", "label": "Credential Spraying"})
            
            chains.append({
                "name": "Historical Secrets Data Exfiltration",
                "steps": ["Scrape historical web caches", "Detect exposed API tokens or DB connection URLs", "Authenticate to cloud databases / APIs", "Unauthorized database download"],
                "severity": "Critical",
                "impact": "Immediate compromise of proprietary data, sensitive user databases, or cloud accounts."
            })

        # Check for Web Vulnerabilities (XSS, Injection, SSRF, RCE)
        web_vulns = [v for v in all_vulns if isinstance(v, dict) and any(x in (v.get("type") or v.get("vuln_type") or v.get("title") or "").lower() for x in ["xss", "injection", "ssrf", "rce", "cors", "bypass"])]
        if web_vulns:
            nodes.append({
                "id": "web_vuln",
                "label": f"Web Vulnerabilities Found ({len(web_vulns)})",
                "type": "vulnerability",
                "severity": "High",
                "description": f"Identified software flaws: {', '.join(set([v.get('type', v.get('title', 'Vuln')) for v in web_vulns if isinstance(v, dict)]))[:80]}."
            })
            
            # Connect web vulnerabilities to CMS or general entry
            source_id = cms_node_id if cms_node_id else "entry"
            edges.append({"from": source_id, "to": "web_vuln", "label": "Vulnerability Scanner"})

            # Pivot: Remote Code Execution / Server Compromise
            nodes.append({
                "id": "server_compromise",
                "label": "Remote Server Takeover",
                "type": "exploit",
                "severity": "Critical",
                "description": "Abusing identified software flaws to gain remote code execution, pivoting to backend network segments."
            })
            edges.append({"from": "web_vuln", "to": "server_compromise", "label": "Exploit Payload Execution"})

            chains.append({
                "name": "Web Infrastructure Pivot Route",
                "steps": ["Identify outdated components / input fields", "Launch exploitation payloads (SQLi / RCE / SSRF)", "Compromise server user permissions", "Internal environment pivoting"],
                "severity": "Critical",
                "impact": "Complete execution control on backend web hosting servers, facilitating persistent backdoor installations."
            })

        # Add fallback chains if no vulnerabilities are found
        if not chains:
            chains.append({
                "name": "Standard Recon Mapping Path",
                "steps": ["DNS Blueprint Discovery", "Technology Fingerprinting", "Subdomain Mapping", "Surface Area Overview"],
                "severity": "Info",
                "impact": "Gathers intelligence but reveals no immediate compromise routes."
            })

        results = {
            "domain": self.domain,
            "graph": {
                "nodes": nodes,
                "edges": edges
            },
            "exploit_chains": chains
        }

        with open(self.output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2)

        return results
