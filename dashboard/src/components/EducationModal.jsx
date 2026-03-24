import React from 'react';

const MODULE_DESCRIPTIONS = {
  "Domain Information": "Queries the WHOIS registry directly via raw socket connections on Port 43 and executes DNS reconnaissance to identify server providers, registrars, and physical data locations. A foundational step in mapping the target's attack surface without triggering WAF warnings.",
  "DNS Records": "Iterates dynamically through DNS servers to dump A, AAAA, MX, NS, and TXT records. Specifically looks for forgotten or misconfigured records that might leak internal IP ranges or point to decommissioned mail servers, setting the stage for deeper routing exploitation.",
  "SEO Analysis": "Scrapes the semantic HTML skeleton of the page searching for trackers, Webmaster Tools fingerprints, and hidden sitemaps. By reading sitemap.xml and robots.txt directives, it finds endpoints the developer explicitly wanted to hide from web crawlers.",
  "Web Technologies": "Performs an advanced regex-based fingerprinting of the DOM, script sources, and HTTP headers against a massive library of technology signatures. Determines specific frameworks (React/Vue), CMS versions (WordPress), and even specific WAF providers in the network boundary.",
  "Security Analysis": "Evaluates defensive HTTP Headers (CSP, HSTS, X-Frame-Options) and scans cookie configuration flags (Secure, HttpOnly). Lack of these exact headers often directly highlights the application's susceptibility to Clickjacking and Cross-Site Scripting (XSS).",
  "Advanced Content Scan": "Executes malicious payloads directly into standard parameters and evaluates the result via JavaScript AST (Abstract Syntax Tree) taint-flow logic. Maps Source-to-Sink vectors iteratively to confirm severe DOM-based vulnerabilities or highly sensitive API endpoints.",
  "Contact Spy": "Scrapes digital footprints traversing the target's web structure. Employs regex to mass-extract Phone numbers, Email addresses, and Social Media handles. Perfect for subsequent social engineering payloads or discovering hidden employee logic interfaces.",
  "Subdomain Discovery": "Interfaces with 'subfinder', a Go-based passive DNS mapper that silently queries multiple global intelligence APIs (like Shodan, Censys, VirusTotal) to aggregate all publicly historical associated subdomains without ever contacting the target directly.",
  "Subdomain Takeover": "Pings the previously identified subdomains to analyze CNAME assignments. If a subdomain points to a third-party service (like GitHub Pages or AWS S3) that does not exist, an attacker can silently register the service and 'take over' that legitimate subdomain name.",
  "CloudFlare Bypass": "Hunts for the True Origin Server behind a Cloudflare reverse proxy. Analyzes historical IP changes via database dumps, enumerates direct-access subdomains (like mail. or ftp.), and matches original SSL certificate Common Names directly to raw Shodan IP spaces.",
  "Nmap Zero Day Scan": "Utilizes raw system-level packets using Nmap to scan open TCP ports. Matches the exact service versions running on those isolated ports against the NVD (National Vulnerability Database) to automatically map instances of globally known Zero-Day exploits.",
  "GEO Analysis": "Scans emerging AI endpoints. Specifically looking into `llms.txt`, `robots.txt` blocking instructions for `GPTBot`, and searching for WebMCP contexts. Understands how large language models autonomously gather data from this target."
};

const EducationModal = ({ isOpen, onClose, moduleName }) => {
  if (!isOpen) return null;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={e => e.stopPropagation()}>
        <button className="modal-close" onClick={onClose}>×</button>
        <h2 style={{ marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span style={{ fontSize: '1.5rem' }}>🎓</span> 
          How it Works: {moduleName}
        </h2>
        
        <div style={{ background: 'var(--panel-bg)', padding: '1.5rem', borderRadius: '8px', borderLeft: '4px solid var(--accent-purple)' }}>
          <p style={{ color: 'var(--text-primary)', lineHeight: '1.8', fontSize: '1rem' }}>
            {MODULE_DESCRIPTIONS[moduleName] || "This module performs advanced reconnaissance and active identification against the target domain based on unique execution heuristics."}
          </p>
        </div>
        
        <div style={{ marginTop: '1.5rem', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
          <p>This technical execution context has been provided for educational purposes by WebAnalyzer.</p>
        </div>
      </div>
    </div>
  );
};

export default EducationModal;
