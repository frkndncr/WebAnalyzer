# Changelog

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