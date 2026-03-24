# WebAnalyzer Features

WebAnalyzer bridges the gap between passive OSINT enumeration and aggressive active vulnerability exploitation. Its features are crafted for security researchers, penetration testers, and bug bounty hunters.

## 1. Modular Execution Pipeline
Unlike monolithic tools, WebAnalyzer allows users to explicitly toggle which segments of analysis they want to execute.
- **Selective Modules:** A rich terminal UI lets users toggle modules with Space/Enter. 
- **Time efficiency:** Unwanted heavy scans (like exhaustive API fuzzing) can be skipped if the goal is purely passive OSINT.
- **Pacing Control:** Dynamic pacing adjusts timeouts based on module 'weight' (e.g., waiting 5-10 seconds after a medium module, and 10-20 seconds after an aggressive fuzzer) to minimize WAF triggers and account suspensions.

## 2. Advanced Evasion Techniques
To operate successfully against modern targets protected by WAFs (Cloudflare, Akamai, AWS WAF), WebAnalyzer incorporates:
- **Session Rotation:** Transparently cycles User-Agent strings. Every new module initiates a fresh `requests.Session`.
- **Intelligent Proxies:** Native hooks to support rotating proxy infrastructures seamlessly.
- **Adaptive Rate Limiting:** If HTTP 429 Too Many Requests are hit, the tool automatically enforces exponential backoffs, resets the IP/Proxy connection, and retries gracefully without destroying the current module's execution state.
- **WAF Detection:** Proactively identifies the protective layer over the target, altering testing behavior and adjusting parsing rules.

## 3. High-Confidence API and Secrets Discovery
WebAnalyzer integrates logic built from bug bounty methodology natively into the code:
- **Heuristic API Detection:** Differentiates real JSON/XML API endpoints from misconfigured webservers returning HTML inside 404 status codes. It scores valid endpoints via headers, server stacks, and response structure.
- **Taint Analysis in JS:** Analyzes minified JavaScript to trace instances where `.search`, `.hash`, or `.referrer` dynamically inputs into sinks like `.innerHTML` or `eval()`, pointing directly to DOM XSS.
- **Entropy Secret Hunting:** Uses Shannon Entropy coupled with a robust Pattern Registry to locate leaked AWS Keys, Stripe Secrets, JWT tokens, and OAuth identifiers within code blocks.

## 4. Origin IP Unmasking
Finding origin IPs behind Cloudflare is notoriously difficult. WebAnalyzer automates the whole kill-chain:
- **Historical Records:** Scrapes historical DNS records to find the IP associated with the domain before it moved to CloudFlare.
- **Subdomain Leakage:** Discovers subdomains (`mail.x.com`, `ftp.x.com`, `direct.x.com`) that often bypass proxy rules and hit the origin infrastructure directly.
- **SSL Certificate Mapping:** Validates IPs by checking if the SSL certificate served directly by the IP has the target domain present in its SAN (Subject Alternative Names).

## 5. Comprehensive Reporting & Output
- **Continuous Saving:** Scan states are parsed and dynamically serialized.
- **JSON Blobs:** Saves structured, parsable data for each module directly into `logs/<domain_name>/results.json`, permitting integration into CI/CD pipelines, dashboards, or external graphing engines.
- **Terminal UI:** Utilizes `Rich` rendering to provide beautiful inline summaries, progress bars, and color-coded risk assessment scoring.
