# Changelog

## [3.9.0] - 2026-10-18

### Changed
- **The score now reflects every module.** It used to come from Security Analysis alone, so an exposed `.env`, a takeover or a missing DMARC policy changed nothing. Findings from other modules now take points off (capped per module and in total); see `docs/SCORING.md`. Python and the dashboard compute it identically.
- **Advanced Content Scan: fewer false positives.** Exposed-file checks now require the file's real content and ignore catch-all pages and 401/403 answers; pattern hits inside library code (jQuery, WordPress core, ...) are skipped; `eval(` and `__proto__` alone are low severity, not high.
- **Phishing Domain Protection:** skips IP addresses, looks up IDN homoglyphs as punycode, and rates a look-alike by what it can do (own registrations are info, mail-capable or login-themed ones are high).
- **Subdomain Takeover:** severity follows the module's confidence when none is given.

### Added
- **11 new modules** (28 in total), each one file under `modules/plugins/`: **Email Security** (SPF, DKIM, DMARC, MTA-STS), **TLS Health**, **DNS Health**, **Cookies & CORS**, **HTTP Methods & Redirects**, **Privacy & Trackers** (KVKK/GDPR signals), **JS Library Vulnerabilities** (OSV), **Asset Inventory** (ASN, certificate-transparency names), and three intrusive ones that need a verified domain on the public demo: **Exposed Files**, **Cloud Storage**, **DNS Zone Transfer**.
- The `standard` preset now includes the light passive checks.
- `utils/webprobe.py`: shared, safe request helpers (no cross-site redirects, size and time limits).

## [3.8.0] - 2026-10-16

### Added
- **Client report**: `webanalyzer scan -f html` and `/api/report/<domain>` now produce a cover page, executive summary, findings with IDs, CWE and OWASP Top 10 references, remediation and a module appendix, styled to print as PDF. It is built from the same data as the dashboard, so the numbers match.
- **Change detection**: `webanalyzer diff old.json new.json` and `scan --baseline` (fail only on new findings; new subdomains and ports are listed).
- Slack and generic webhook notifications next to Telegram, with the client IP and browser in each scan message.
- Docker image published to ghcr.io on release, `docs/DOCKER.md`, a `.dockerignore`; the compose file no longer exposes MySQL on every interface.
- Dashboard refresh: hero, score ring, severity bars, a phone-friendly menu.

## [3.7.3] - 2026-10-12

### Changed
- The GitHub Action is named `WebAnalyzer Security Scan` (the plain name is taken on the Marketplace). No code changes.

## [3.7.2] - 2026-10-12

### Changed
- The GitHub Action is now named `WebAnalyzer` (was `WebAnalyzer scan`). No code changes.

## [3.7.1] - 2026-10-12

### Added
- Modules and plugins can report findings by returning `{"findings": [...]}`; they are counted in the Overview, Findings tab, SARIF and `--fail-on`. The Security.txt plugin uses it. See docs/WRITING_A_MODULE.md.
- `docs/RELEASING.md` and a test guarding the GitHub Action metadata.

### Changed
- The Action description now fits the GitHub Marketplace limit; documented examples pin `@v3.7.0`.

## [3.7.0] - 2026-10-12

A large release: a real command line and GitHub Action, a plugin system, a safer
public demo, and a rebuilt dashboard. (Versions 3.6.3 - 3.6.5 were not recorded
in this file.)

### Added
- **Command line**: `webanalyzer scan | modules | verify | version`. Output as
  `text`, `json`, `jsonl`, **SARIF 2.1.0** (GitHub Code Scanning) or `markdown`;
  `--fail-on` makes a scan gate a pipeline (exit codes 0/1/2/3), `--passive`
  never runs intrusive modules, `--timeout`, `--list`, stdin and `-c` for
  parallel domains. The interactive mode and the older `-u/-l/-m` flags still work.
- **GitHub Action** (`uses: frkndncr/WebAnalyzer@...`): scans, writes SARIF, adds
  a Markdown job summary, optionally uploads to Code Scanning and enforces a
  severity gate. See `docs/CI.md`.
- **Module registry and plugins**: a module is one function in one file. Drop it
  into `modules/plugins/` (or a directory in `WEBANALYZER_PLUGIN_DIRS`) and it
  appears in the API, the dashboard and the CLI. See `docs/WRITING_A_MODULE.md`.
  Ships with a `Security.txt` (RFC 9116) check as a reference plugin.
- **Domain ownership verification** for the public demo: in `DEMO_MODE` the
  intrusive modules (Nmap, active content tests, takeover and origin probing)
  only run on domains whose owner has published a DNS TXT record. New
  `GET /api/verify/<domain>` and `GET /api/modules`.
- Dashboard: Threat Intelligence (MITRE ATT&CK), Network Map and Attack Path
  pages; a Results page with Summary / Findings / Modules tabs; shareable URLs
  (`#/results/example.com`); a "Database offline" banner; privacy, KVKK/GDPR,
  terms and cookie pages; SEO metadata.
- `/api/system-health` reports the database state and `demo_mode`.
- Test suites: ~370 backend tests and a Vitest suite for the dashboard.

### Changed
- The dashboard was rebuilt from scratch with a lighter design and a smaller
  bundle (about 460 KB to 250 KB); the module list now comes from the API.
- The database pool defaults to 5 connections (was 20), the connect timeout to
  10 s, and a failed connection is not retried for 20 s, so a database outage no
  longer freezes the whole API. Blocking database calls run in worker threads.
- One definition of a "finding" is used by the API, the CLI and the dashboard, so
  counts agree everywhere (missing security headers, information disclosure,
  dangerous HTTP methods, CORS issues, exposed endpoints, ... are included).
- The version number lives in `utils/version.py` and `pyproject.toml` reads it.

### Fixed
- **Security:** `GET /api/network-map/<domain>` and `GET /api/threat-intel/<domain>`
  started full scans and bypassed the demo's SSRF block and rate limit. Reads no
  longer start scans.
- Attack Path Planner never received the other modules' findings (a name
  mismatch), so every domain got the same generic path.
- The XSS "safe context" check treated reflected payloads as safe when no quote
  character was involved, hiding real findings.
- `is_json_response` raised on whitespace-only bodies.
- Overview numbers: the domain count was always 1, per-scan finding counts were
  always 0, scans stored as `https://x/` and `x` were listed twice.
- Modules that outlived `--timeout` kept the process alive.
- Network Map listed nested objects as technologies.

### Security notes
- Public instances should set `DEMO_MODE=true`; see the README.

## [3.6.2] - 2026-06-25

### Fixed
- Synced console banner and monitor terminal output versions to `v3.6.2`.
- Fixed dashboard SettingsPage and Sidebar footer versioning mismatches.
- Verified and finalized production React assets compilation.

## [3.6.1] - 2026-06-24

### Added
- Integrated `curl_cffi` for JA3 TLS fingerprinting evasion and `httpx` HTTP/2 support.
- Built Tor Control SOCKS5 proxy rotation using raw socket connection signals.
- Configured dynamic cookie persistence and automated Cloudflare anti-bot retry loops.

## [3.5.0] - 2026-06-17

### Added
- Integrated Web Archive Spy module for hunting historical leaked secrets.
- Integrated Attack Path Planner module with graphical exploit chains.
- Integrated Phishing Domain Protection for discovering typosquatted/spoofed hostnames.
- Integrated SSL SAN Association mapping module to discover certificate-linked hostnames.

## [3.4.0] - 2026-06-16

### Added
- Rewrote the frontend using React & Vite to deliver the Elite Cyber Security Command Center Dashboard v2.0.
- Wired real-time Web sockets and API endpoints for Threat Intelligence, Network Topology, and Settings modules.
- Added dynamic interactive finding filters based on Critical/High/Medium/Low vulnerabilities.
- Added collapsible section limits in result views to improve dashboard readability.

## [3.3.0] - 2026-06-16

### Added
- Database schema alignment in `database/schema.sql` to support new ENUM states (`interrupted`, `timeout`, `skipped`, `partial`), missing statistics constraints, and custom timestamp audit columns.

### Enhanced
- Defer Connection Pool Creation (Lazy Load) in `database/db_manager.py` to allow CLI and API imports to load seamlessly when MySQL is offline.
- Scale Connection Pool Size to 20 by default (from 3) to prevent worker connection starvation during massive bulk operations.
- Thread-safe lazy initialization for Database connection pool using `threading.Lock`.
- Bulk processor concurrency optimizations in `bulk/processor.py`:
  - Moved the `ThreadPoolExecutor` allocation outside retry loops in `safe_run_module` to prevent thread churn.
  - Handled `TimeoutError` using non-blocking executor shutdowns (`wait=False`) to avoid worker blockages.
  - Swapped `domain_cache` to `collections.OrderedDict` to allow O(1) FIFO cache cleanup.
  - Proactive garbage collection (`gc.collect()`) at the end of each batch process to stabilize memory usage.

## [3.2.0] - 2026-06-16

### Added
- Passive OSINT subdomain discovery engine in `modules/subfinder_tool.py` checking crt.sh (Certificate Transparency), HackerTarget, and AlienVault OTX (completely free and keyless) as a fallback when the `subfinder` Go binary is missing.

### Removed
- Removed all `whois_api_key` and other API key configs, CLI settings, configuration loaders/savers, warning prompts, and documentation to deliver a fully decentralized, zero-config, keyless operation.

## [3.1.0] - 2026-06-16

### Added
- DNS Security Audit checking SPF records, DMARC policies, DNSSEC status, and CAA policies in `modules/domain_dns.py`.
- Dynamic CORS Origin Reflection vulnerability test in `modules/security_analysis.py`.
- Individual cookie analysis checking `Secure`, `HttpOnly`, and `SameSite` flags.
- Concurrent sensitive files and endpoints prober in `modules/security_analysis.py` checking for exposed `.env`, `.git/config`, `wp-config.php`, backups, etc.
- CLI argument parsing interface, multi-target inputs, JSON stdout mode, and pipeline support in `main.py`.

### Enhanced
- Cloudflare bypass module (`modules/cloudflare_bypass.py`) with dual-port verification (ports 80 & 443) and Host-header validation.

## [3.0.0] - 2025-09-09

### Added
- Enterprise bulk processing system with MySQL database
- Job queue management with progress tracking
- Module-specific retry mechanisms (3x for security, 4x for web tech)
- Vulnerability and technology detection with database storage
- Advanced domain pre-validation system
- Real-time performance monitoring and resource optimization
- Enhanced anti-bot detection handling for protected sites

### Enhanced
- SEO analysis module with 403 error handling
- Security analysis with comprehensive reporting
- Database schema with optimized indexing
- Documentation with professional formatting

### Technical
- MySQL connection pooling for enterprise scalability
- Worker pool architecture supporting 1-50 concurrent processes
- Checkpoint recovery system for large-scale operations
- Module execution framework improvements