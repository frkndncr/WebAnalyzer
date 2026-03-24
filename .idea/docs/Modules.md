# WebAnalyzer Modules

This document describes all individual scanning modules encapsulated within the `modules/` directory. Each module corresponds to a specific analysis feature and functions independently.

## Lightweight Modules

### 1. Domain & DNS Information (`domain_info.py`, `domain_dns.py`)
- **Purpose:** Collect base-level insights related to the domain's existence and routing parameters.
- **Capabilities:** Performs WHOIS lookups natively via raw socket connections on port 43. Analyzes basic DNS records (A, AAAA, MX, NS, TXT). Scans for open common ports (80, 443, 8080) and parses HTTP Headers for server identification.
- **Concurrency:** Uses `ThreadPoolExecutor` to speed up DNS record queries.

### 2. Generative Engine Optimization (`geo_analysis.py`)
- **Purpose:** Analyzes how modern Large Language Models and AI engines perceive the target.
- **Capabilities:** Scans for `.well-known/llms.txt`, probes for WebMCP endpoint structures, and investigates `robots.txt` directives specifically targeting AI crawlers (like GPTBot, ClaudeBot, Applebot).

### 3. Subfinder Wrapper (`subfinder_tool.py`)
- **Purpose:** Performs rapid passive subdomain enumeration.
- **Capabilities:** Serves as a Python wrapper around the `subfinder` Go binary. Executes system-level commands securely and parses the STDOUT output to discover subdomains mapped to the primary domain.

## Mediumweight Modules

### 4. SEO & Performance Analysis (`seo_analysis.py`)
- **Purpose:** Deep dive into the Search Engine Optimization and frontend performance matrix.
- **Capabilities:** Scrapes Meta tags, semantic HTML tags (H1-H6), OpenGraph/Twitter Cards for social media display. Validates keyword density and identifies broken links on the main page. Detects the presence of `sitemap.xml`, `robots.txt`, and Google Analytics trackers.

### 5. Web Technologies Identifier (`web_technologies.py`)
- **Purpose:** Fingerprints the entire technology stack (Frontend + Backend) running on the target.
- **Capabilities:** Through advanced regex rules applied on DOM, script sources, and HTTP headers, it maps frameworks (React, Vue, Django, Laravel), CMS (WordPress, Magento), CSS frameworks, CDNs, Analytics platforms, and associated security ramifications for recognized versions. Includes dedicated WordPress deep-scanning.

### 6. Security Analysis (`security_analysis.py`)
- **Purpose:** Basic application-layer security posture assessment.
- **Capabilities:** Identifies missing HTTP Security Headers (HSTS, CSP, X-Frame-Options). Checks SSL/TLS configurations, cookie security flags (Secure, HttpOnly, SameSite), open CORS policies, and potential Web Application Firewall (WAF) presence.

## Heavyweight / Active Security Modules

### 7. Advanced Content Scanner (`advanced_content_scanner.py`)
- **Purpose:** Heavy active L1-L5 security scanning methodology. Built as a "Nirvana Edition".
- **Capabilities:** 
  - **L1-L2:** Crawls maps, hunts for JSON blobs. Actively fuzzes parameters for SQLi, XSS, SSTI, Path Traversal, and CRLF vulnerabilities using pre-defined payloads.
  - **L3 (Taint Flow):** Maps variables through Javascript AST logic via regex heuristics to find DOM-based XSS and Open Redirect vulnerabilities from Source -> Sink execution.
  - **L4-L5:** Scans for high-entropy hardcoded secrets, Auth Bypass techniques, and attempts to find hidden debug endpoints (`/actuator`, `/.env`).

### 8. API Security Hunter (`api_security_scanner.py`)
- **Purpose:** Specialized bug bounty grade scanner focusing specifically on Application Programming Interfaces.
- **Capabilities:** Intelligently discerns valid endpoints from standard HTML 404 pages using complex structural heuristics (JSON formats, response behaviors). Fuzzes inputs for BOLA/IDOR, parameter pollution, SSRF, and command injections specifically mapped to API behavior structures like GraphQL or REST.

### 9. Cloudflare Bypass (`cloudflare_bypass.py`)
- **Purpose:** Unmasks the true origin IP of targets hidden behind Cloudflare reverse proxies.
- **Capabilities:** Uses historical DNS databases (ViewDNS, SecurityTrails), Shodan lookups, subdomains pointing outside CF, Mail server headers, and direct IP brute forcing via SSL certificate common names (CN) matching to find origin leaks.

### 10. Contact Spy (`contact_spy.py`)
- **Purpose:** Generates comprehensive OSINT regarding the human and corporate elements behind the domain.
- **Capabilities:** Crawls the domain explicitly searching for regex matches of Emails, Phone Numbers, and Social Media profiles (Facebook, LinkedIn, Twitter, GitHub), validating their formats for active use mapping.

### 11. Nmap Zero-Day Scanner (`nmap_zero_day.py`)
- **Purpose:** Correlates open ports and services with active CVE databases.
- **Capabilities:** Re-executes `nmap` logic natively via `python-nmap` to discover exact service versions running on detected open ports. Automatically requests known vulnerability datasets (like NVD or Vulners) to map discovered running versions against actively exploited CVE architectures.

### 12. Subdomain Takeover (`subdomain_takeover.py`)
- **Purpose:** Probes subdomains to discover abandoned third-party services still attached to CNAME records.
- **Capabilities:** Compares HTTP error messages off dangling CNAME targets against a mapping table of over 40 distinct services (AWS S3, GitHub Pages, Heroku, Azure App Service). Determines the risk difficulty (Easy vs Hard) to claim the subdomain.
