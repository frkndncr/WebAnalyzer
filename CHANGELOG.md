# Changelog

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