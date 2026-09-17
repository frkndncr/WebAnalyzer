"""
WebAnalyzer - Executive Security Audit Report Generator
Generates comprehensive, standalone, print-ready HTML/PDF security audit reports
with executive scorecards, vulnerability details, and actionable remediation guidance.
"""

import os
import json
import html
from datetime import datetime
from typing import Dict, List, Any, Optional

# Pre-defined remediation guidance library for common findings
REMEDIATION_DATABASE = {
    "missing_csp": {
        "title": "Missing Content Security Policy (CSP)",
        "remediation": "Deploy a restrictive Content-Security-Policy HTTP header to prevent Cross-Site Scripting (XSS) and data injection attacks.",
        "code": "# Nginx Configuration\nadd_header Content-Security-Policy \"default-src 'self'; script-src 'self' https://trustedscripts.com; object-src 'none'; frame-ancestors 'none';\" always;\n\n# Apache Configuration\nHeader set Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none';\""
    },
    "missing_hsts": {
        "title": "Missing HTTP Strict Transport Security (HSTS)",
        "remediation": "Enforce HTTPS communication across the domain and all subdomains by enabling HSTS with a 1-year duration.",
        "code": "# Nginx Configuration\nadd_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\n\n# Apache Configuration\nHeader always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\""
    },
    "missing_x_frame_options": {
        "title": "Clickjacking Protection Missing (X-Frame-Options)",
        "remediation": "Prevent clickjacking attacks by forbidding external domains from embedding your application in iframes.",
        "code": "# Nginx Configuration\nadd_header X-Frame-Options \"DENY\" always;\n\n# Apache Configuration\nHeader always set X-Frame-Options \"DENY\""
    },
    "missing_x_content_type_options": {
        "title": "MIME-Sniffing Protection Missing",
        "remediation": "Disable MIME type sniffing to prevent malicious file uploads from executing in the victim's browser.",
        "code": "# Nginx Configuration\nadd_header X-Content-Type-Options \"nosniff\" always;\n\n# Apache Configuration\nHeader always set X-Content-Type-Options \"nosniff\""
    },
    "subdomain_takeover": {
        "title": "Subdomain Takeover Risk",
        "remediation": "Immediate Action Required: Delete the dangling DNS CNAME or NS record pointing to an unallocated third-party cloud provider, or reclaim the cloud resource before an attacker does.",
        "code": "# DNS Command: Remove the dangling CNAME record from your DNS registrar\n# E.g. Remove: sub.example.com CNAME attacker-bucket.s3.amazonaws.com"
    },
    "open_port": {
        "title": "Exposed Network Port",
        "remediation": "Close unnecessary public ports or restrict access using a network firewall (UFW, iptables, AWS Security Groups).",
        "code": "# Linux UFW Firewall\nsudo ufw deny <PORT>/tcp\nsudo ufw reload"
    },
    "cloudflare_bypass": {
        "title": "Direct Origin IP Exposed (WAF Bypass)",
        "remediation": "Configure your origin web server firewall to only accept HTTP/HTTPS traffic originating from Cloudflare IP ranges, rejecting all direct connections.",
        "code": "# Nginx: Restrict access to Cloudflare IP ranges\nset_real_ip_from 173.245.48.0/20;\n# Drop all other direct requests"
    },
    "default": {
        "title": "Security Finding",
        "remediation": "Review the affected component against standard security hardening best practices (OWASP Top 10, CIS Benchmarks).",
        "code": ""
    }
}


def _get_remediation(vuln_type: str, desc: str) -> Dict[str, str]:
    """Resolves actionable remediation guidance based on vulnerability type or description"""
    v_lower = (vuln_type + " " + desc).lower()
    if "csp" in v_lower or "content security policy" in v_lower:
        return REMEDIATION_DATABASE["missing_csp"]
    elif "hsts" in v_lower or "strict-transport-security" in v_lower:
        return REMEDIATION_DATABASE["missing_hsts"]
    elif "frame-options" in v_lower or "clickjacking" in v_lower:
        return REMEDIATION_DATABASE["missing_x_frame_options"]
    elif "content-type" in v_lower or "nosniff" in v_lower:
        return REMEDIATION_DATABASE["missing_x_content_type_options"]
    elif "takeover" in v_lower:
        return REMEDIATION_DATABASE["subdomain_takeover"]
    elif "cloudflare" in v_lower or "direct ip" in v_lower:
        return REMEDIATION_DATABASE["cloudflare_bypass"]
    elif "port" in v_lower:
        return REMEDIATION_DATABASE["open_port"]
    return REMEDIATION_DATABASE["default"]


def generate_executive_report(domain: str, data: Dict[str, Any]) -> str:
    """
    Compiles full scan results into a responsive, standalone,
    print-ready executive HTML security audit report.
    """
    clean_domain = domain.replace("http://", "").replace("https://", "").split("/")[0]
    scan_date = datetime.now().strftime("%B %d, %Y - %H:%M:%S UTC")
    
    # ── 1. Calculate Scorecard Metrics ──
    vulnerabilities = []
    
    # Extract from Security Analysis module
    sec = data.get("Security Analysis", {})
    if isinstance(sec, dict):
        for v in sec.get("vulnerabilities", []):
            if isinstance(v, dict):
                vulnerabilities.append({
                    "title": v.get("title") or v.get("type", "Security Finding"),
                    "severity": (v.get("severity") or "Medium").capitalize(),
                    "description": v.get("description", "Potential security misconfiguration detected."),
                    "source": "Security Analysis"
                })
    
    # Extract from Subdomain Takeover module
    sub_takeovers = data.get("Subdomain Takeover", [])
    if isinstance(sub_takeovers, list):
        for st in sub_takeovers:
            if isinstance(st, dict) and st.get("vulnerable"):
                vulnerabilities.append({
                    "title": f"Subdomain Takeover Risk on {st.get('subdomain', clean_domain)}",
                    "severity": "High",
                    "description": f"Dangling pointer to {st.get('service', 'Unknown Service')}. External takeover possible.",
                    "source": "Subdomain Takeover"
                })
                
    # Extract from Advanced Content Scanner
    acs = data.get("Advanced Content Scan", {})
    if isinstance(acs, dict):
        for vuln in acs.get("findings", []) or acs.get("vulnerabilities", []):
            if isinstance(vuln, dict):
                vulnerabilities.append({
                    "title": vuln.get("type") or vuln.get("title", "Content Finding"),
                    "severity": (vuln.get("severity") or "Low").capitalize(),
                    "description": vuln.get("description", ""),
                    "source": "Advanced Content Scanner"
                })
                
    # Extract Cloudflare Bypass findings
    cf = data.get("Cloudflare Bypass", {})
    if isinstance(cf, dict) and cf.get("bypassed"):
        vulnerabilities.append({
            "title": "Cloudflare WAF Bypassed - Origin IP Exposed",
            "severity": "High",
            "description": f"Direct origin IP identified: {cf.get('real_ip', 'Unknown')}. Attackers can bypass WAF defenses directly.",
            "source": "Cloudflare Bypass"
        })

    # Count by severity
    crit_count = sum(1 for v in vulnerabilities if v["severity"] == "Critical")
    high_count = sum(1 for v in vulnerabilities if v["severity"] == "High")
    med_count = sum(1 for v in vulnerabilities if v["severity"] == "Medium")
    low_count = sum(1 for v in vulnerabilities if v["severity"] in ["Low", "Info"])
    total_vulns = len(vulnerabilities)
    
    # Calculate Security Grade & Risk Score (0 - 100)
    raw_score = 100 - (crit_count * 25 + high_count * 15 + med_count * 8 + low_count * 2)
    security_score = max(0, min(100, raw_score))
    
    if security_score >= 90:
        grade = "A+"
        grade_color = "#10b981"
        grade_badge = "Excellent Security Posture"
    elif security_score >= 80:
        grade = "A"
        grade_color = "#059669"
        grade_badge = "Good Security Posture"
    elif security_score >= 65:
        grade = "B"
        grade_color = "#3b82f6"
        grade_badge = "Moderate Risk Detected"
    elif security_score >= 50:
        grade = "C"
        grade_color = "#f59e0b"
        grade_badge = "Significant Vulnerabilities Found"
    elif security_score >= 30:
        grade = "D"
        grade_color = "#f97316"
        grade_badge = "High Attack Surface Exposure"
    else:
        grade = "F"
        grade_color = "#ef4444"
        grade_badge = "Critical Security Compromise Risks"

    # ── 2. Extract Network & Recon Assets ──
    subdomains = data.get("Subdomain Discovery", [])
    if isinstance(subdomains, dict):
        subdomains = subdomains.get("subdomains", [])
    elif not isinstance(subdomains, list):
        subdomains = []
        
    dns_data = data.get("DNS Records", {})
    domain_info = data.get("Domain Information", {})
    web_tech = data.get("Web Technologies", {})
    if isinstance(web_tech, dict) and "technologies" in web_tech:
        web_tech = web_tech.get("technologies", {})
        
    ports_data = data.get("Nmap Zero Day Scan", {})
    open_ports = []
    if isinstance(ports_data, dict):
        port_scan = ports_data.get("port_scan", {})
        if isinstance(port_scan, dict):
            open_ports = port_scan.get("open_ports", [])

    # ── 3. Build HTML Output ──
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebAnalyzer Audit Report - {html.escape(clean_domain)}</title>
    <style>
        :root {{
            --primary: #0f172a;
            --secondary: #1e293b;
            --accent: #0284c7;
            --text: #0f172a;
            --text-muted: #64748b;
            --bg: #f8fafc;
            --card-bg: #ffffff;
            --border: #e2e8f0;
            --danger: #ef4444;
            --warning: #f59e0b;
            --info: #3b82f6;
            --success: #10b981;
        }}
        
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            line-height: 1.6;
            padding-bottom: 60px;
        }}
        
        /* Top Navigation / Action Bar */
        .top-bar {{
            background: #090d16;
            color: #fff;
            padding: 14px 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: sticky;
            top: 0;
            z-index: 100;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }}
        .top-bar .brand {{
            font-weight: 800;
            font-size: 1.15rem;
            letter-spacing: 0.5px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .top-bar .brand span {{ color: #38bdf8; }}
        .btn {{
            background: #0284c7;
            color: #fff;
            border: none;
            padding: 8px 18px;
            border-radius: 6px;
            font-weight: 600;
            cursor: pointer;
            font-size: 0.85rem;
            transition: 0.2s all;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }}
        .btn:hover {{ background: #0369a1; transform: translateY(-1px); }}
        
        /* Main Container */
        .container {{
            max-width: 1080px;
            margin: 30px auto;
            padding: 0 20px;
        }}
        
        /* Header Hero Card */
        .hero-card {{
            background: #ffffff;
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 25px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.04);
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 20px;
        }}
        .hero-info h1 {{
            font-size: 2rem;
            color: #0f172a;
            margin-bottom: 6px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .hero-info p {{ color: var(--text-muted); font-size: 0.9rem; }}
        
        /* Score Grade Badge */
        .grade-card {{
            display: flex;
            align-items: center;
            gap: 16px;
            background: #f8fafc;
            border: 1px solid var(--border);
            padding: 16px 24px;
            border-radius: 10px;
        }}
        .grade-circle {{
            width: 68px;
            height: 68px;
            border-radius: 50%;
            background: {grade_color};
            color: #ffffff;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 2rem;
            font-weight: 900;
            box-shadow: 0 4px 14px {grade_color}40;
        }}
        .grade-text .title {{ font-size: 0.75rem; text-transform: uppercase; color: var(--text-muted); font-weight: 700; }}
        .grade-text .score {{ font-size: 1.25rem; font-weight: 800; color: #0f172a; }}
        .grade-text .badge {{ font-size: 0.75rem; color: {grade_color}; font-weight: 600; }}
        
        /* Metrics Grid */
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }}
        .metric-box {{
            background: #ffffff;
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 18px;
            box-shadow: 0 1px 4px rgba(0,0,0,0.02);
            text-align: center;
        }}
        .metric-box .label {{ font-size: 0.75rem; text-transform: uppercase; color: var(--text-muted); font-weight: 700; margin-bottom: 4px; }}
        .metric-box .val {{ font-size: 1.8rem; font-weight: 800; color: #0f172a; }}
        
        /* Severity Pills */
        .badge-crit {{ background: #fee2e2; color: #991b1b; border: 1px solid #f87171; }}
        .badge-high {{ background: #ffedd5; color: #9a3412; border: 1px solid #fb923c; }}
        .badge-med {{ background: #fef3c7; color: #92400e; border: 1px solid #fcd34d; }}
        .badge-low {{ background: #dbeafe; color: #1e40af; border: 1px solid #93c5fd; }}
        .pill {{ padding: 3px 10px; border-radius: 9999px; font-size: 0.75rem; font-weight: 700; display: inline-block; }}
        
        /* Section Card */
        .section-card {{
            background: #ffffff;
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 26px;
            margin-bottom: 25px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.03);
        }}
        .section-card h2 {{
            font-size: 1.25rem;
            color: #0f172a;
            margin-bottom: 16px;
            padding-bottom: 12px;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        /* Vulnerability Items */
        .vuln-card {{
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 18px;
            margin-bottom: 15px;
            background: #fafafa;
        }}
        .vuln-card.Critical {{ border-left: 5px solid var(--danger); }}
        .vuln-card.High {{ border-left: 5px solid var(--warning); }}
        .vuln-card.Medium {{ border-left: 5px solid #facc15; }}
        .vuln-card.Low {{ border-left: 5px solid var(--info); }}
        
        .vuln-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
        }}
        .vuln-header h3 {{ font-size: 1.05rem; font-weight: 700; color: #0f172a; }}
        .vuln-desc {{ font-size: 0.88rem; color: #334155; margin-bottom: 12px; }}
        
        /* Remediation Box */
        .remediation-box {{
            background: #f1f5f9;
            border-radius: 6px;
            padding: 12px 16px;
            font-size: 0.85rem;
            border-left: 4px solid #0284c7;
        }}
        .remediation-box .rem-title {{ font-weight: 700; color: #0369a1; margin-bottom: 4px; display: flex; align-items: center; gap: 6px; }}
        .code-snippet {{
            background: #0f172a;
            color: #e2e8f0;
            padding: 10px 14px;
            border-radius: 6px;
            font-family: monospace;
            font-size: 0.8rem;
            margin-top: 8px;
            overflow-x: auto;
            white-space: pre-wrap;
        }}
        
        /* Table Styles */
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 0.88rem; }}
        th, td {{ padding: 10px 14px; text-align: left; border-bottom: 1px solid var(--border); }}
        th {{ background: #f8fafc; color: var(--text-muted); font-weight: 700; font-size: 0.78rem; text-transform: uppercase; }}
        tr:hover td {{ background: #f8fafc; }}
        
        /* Footer */
        .report-footer {{
            text-align: center;
            color: var(--text-muted);
            font-size: 0.8rem;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid var(--border);
        }}
        
        /* Print Styles */
        @media print {{
            .top-bar {{ display: none !important; }}
            body {{ background: #ffffff !important; padding: 0 !important; color: #000 !important; }}
            .container {{ max-width: 100% !important; margin: 0 !important; padding: 0 !important; }}
            .section-card, .hero-card {{ box-shadow: none !important; border: 1px solid #ddd !important; break-inside: avoid; }}
            .btn {{ display: none !important; }}
        }}
    </style>
</head>
<body>

    <!-- Top Action Bar -->
    <div class="top-bar">
        <div class="brand">
            🛡️ <span>WebAnalyzer</span> Security Audit
        </div>
        <div>
            <button class="btn" onclick="window.print()">🖨️ Save as PDF / Print</button>
        </div>
    </div>

    <div class="container">
        <!-- Hero Header -->
        <div class="hero-card">
            <div class="hero-info">
                <h1>🌐 {html.escape(clean_domain)}</h1>
                <p><strong>Generated by:</strong> WebAnalyzer Enterprise Platform (v3.6.4)</p>
                <p><strong>Audit Timestamp:</strong> {scan_date}</p>
                <p><strong>Scope:</strong> Automated 16-Module Deep Security Reconnaissance</p>
            </div>
            
            <!-- Security Grade Card -->
            <div class="grade-card">
                <div class="grade-circle">{grade}</div>
                <div class="grade-text">
                    <div class="title">Security Grade</div>
                    <div class="score">{security_score}/100</div>
                    <div class="badge">{grade_badge}</div>
                </div>
            </div>
        </div>

        <!-- Metrics Overview Grid -->
        <div class="metrics-grid">
            <div class="metric-box">
                <div class="label">Total Findings</div>
                <div class="val">{total_vulns}</div>
            </div>
            <div class="metric-box">
                <div class="label">Critical / High</div>
                <div class="val" style="color: var(--danger);">{crit_count + high_count}</div>
            </div>
            <div class="metric-box">
                <div class="label">Subdomains Discovered</div>
                <div class="val">{len(subdomains)}</div>
            </div>
            <div class="metric-box">
                <div class="label">Open Ports Identified</div>
                <div class="val">{len(open_ports)}</div>
            </div>
        </div>

        <!-- Vulnerabilities & Remediation Guidance -->
        <div class="section-card">
            <h2>🚨 Detected Vulnerabilities & Actionable Remediation Guidance</h2>
"""
    
    if vulnerabilities:
        for v in vulnerabilities:
            sev = v["severity"]
            badge_class = "badge-crit" if sev == "Critical" else "badge-high" if sev == "High" else "badge-med" if sev == "Medium" else "badge-low"
            rem = _get_remediation(v["title"], v["description"])
            
            html_content += f"""
            <div class="vuln-card {sev}">
                <div class="vuln-header">
                    <h3>{html.escape(v['title'])}</h3>
                    <span class="pill {badge_class}">{sev}</span>
                </div>
                <div class="vuln-desc">{html.escape(v['description'])}</div>
                
                <div class="remediation-box">
                    <div class="rem-title">💡 How to Fix (Remediation Guidance):</div>
                    <p>{html.escape(rem['remediation'])}</p>
            """
            if rem.get("code"):
                html_content += f"""
                    <div class="code-snippet">{html.escape(rem['code'])}</div>
                """
            html_content += """
                </div>
            </div>
            """
    else:
        html_content += """
            <p style="color: var(--success); font-weight: 600; padding: 15px;">
                ✅ No critical or high vulnerabilities detected on the scanned target.
            </p>
        """

    # ── 4. Network & Asset Reconnaissance ──
    html_content += """
        </div>

        <!-- Network & Surface Reconnaissance -->
        <div class="section-card">
            <h2>📡 Attack Surface & Asset Reconnaissance</h2>
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                <div>
                    <h3 style="font-size: 0.95rem; margin-bottom: 8px; color: var(--text-muted); text-transform: uppercase;">Domain Credentials</h3>
                    <table>
                        <tr><th>Registrar</th><td>""" + html.escape(str(domain_info.get("registrar", "Not Publicly Disclosed"))) + """</td></tr>
                        <tr><th>Creation Date</th><td>""" + html.escape(str(domain_info.get("creation_date", "Unknown"))) + """</td></tr>
                        <tr><th>Expiration Date</th><td>""" + html.escape(str(domain_info.get("expiration_date", "Unknown"))) + """</td></tr>
                        <tr><th>DNSSEC</th><td>""" + html.escape(str(dns_data.get("DNSSEC", "Disabled / Not Configured"))) + """</td></tr>
                    </table>
                </div>
                <div>
                    <h3 style="font-size: 0.95rem; margin-bottom: 8px; color: var(--text-muted); text-transform: uppercase;">Exposed Ports</h3>
    """
    
    if open_ports:
        html_content += "<table><tr><th>Port</th><th>Status</th></tr>"
        for p in open_ports:
            html_content += f"<tr><td><strong>TCP {p}</strong></td><td><span class='pill badge-med'>OPEN</span></td></tr>"
        html_content += "</table>"
    else:
        html_content += "<p style='font-size: 0.85rem; color: var(--text-muted); margin-top: 10px;'>No exposed standard ports discovered or firewall filtered.</p>"
        
    html_content += """
                </div>
            </div>
    """

    # Subdomains listing
    if subdomains:
        html_content += """
            <div style="margin-top: 20px;">
                <h3 style="font-size: 0.95rem; margin-bottom: 8px; color: var(--text-muted); text-transform: uppercase;">Discovered Subdomains (""" + str(len(subdomains)) + """)</h3>
                <div style="display: flex; flex-wrap: wrap; gap: 6px; max-height: 180px; overflow-y: auto; padding: 10px; background: #f8fafc; border-radius: 6px; border: 1px solid var(--border);">
        """
        for s in subdomains[:60]:
            html_content += f"<span style='font-family: monospace; font-size: 0.75rem; background: #fff; padding: 3px 8px; border-radius: 4px; border: 1px solid #cbd5e1;'>{html.escape(str(s))}</span>"
        if len(subdomains) > 60:
            html_content += f"<span style='font-size: 0.75rem; color: var(--text-muted);'>+{len(subdomains)-60} more</span>"
        html_content += "</div></div>"

    # Technologies
    if web_tech:
        html_content += """
            <div style="margin-top: 20px;">
                <h3 style="font-size: 0.95rem; margin-bottom: 8px; color: var(--text-muted); text-transform: uppercase;">Identified Technology Stack</h3>
                <div style="display: flex; flex-wrap: wrap; gap: 8px;">
        """
        for k, v in web_tech.items():
            html_content += f"<span style='font-size: 0.8rem; background: #e0f2fe; color: #0369a1; padding: 4px 10px; border-radius: 6px; font-weight: 600;'>{html.escape(str(k))}: {html.escape(str(v))}</span>"
        html_content += "</div></div>"

    # Footer
    html_content += f"""
        </div>

        <div class="report-footer">
            <p><strong>Confidentiality Notice:</strong> This audit report was automatically generated by WebAnalyzer for authorized security assessment purposes.</p>
            <p style="margin-top: 4px;">WebAnalyzer © {datetime.now().year} Furkan Dinçer. Open-Source Domain Intelligence &amp; Reconnaissance Platform.</p>
        </div>
    </div>
</body>
</html>
"""
    return html_content


def save_html_report(domain: str, data: Dict[str, Any], output_path: Optional[str] = None) -> str:
    """Generates and writes the executive HTML report to disk"""
    report_html = generate_executive_report(domain, data)
    if not output_path:
        clean_domain = domain.replace("http://", "").replace("https://", "").split("/")[0]
        output_dir = os.path.join("logs", clean_domain)
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, "report.html")
    
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report_html)
    return output_path
