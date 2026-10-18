/**
 * Turns the raw per-module scan results into the things the Results page shows:
 * one flat list of findings, severity counts, grouped findings, the headline
 * facts and the score breakdown. Pure functions only (no React), unit tested in
 * findings.test.js.
 */
import { severityClass, extractScore } from './analysis';

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

const RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
export const severityRank = (sev) => RANK[severityClass(sev)] ?? 5;

const list = (v) => (Array.isArray(v) ? v : []);
const isObj = (v) => v && typeof v === 'object' && !Array.isArray(v);
const text = (v) => (v == null ? '' : typeof v === 'string' ? v : JSON.stringify(v));

function locationOf(f) {
  if (f.location) return text(f.location);      // plugins may state the location outright
  const url = f.source_url || f.url || f.endpoint || f.target || '';
  return url && f.line ? `${url}:${f.line}` : url;
}

/** Normalise one raw finding object (plus optional overrides) to our shape. */
function make(module, f, over = {}) {
  const raw = isObj(f) ? f : {};
  return {
    severity: severityClass(over.severity || raw.severity || raw.risk_level || 'medium'),
    title: over.title ?? raw.type ?? raw.title ?? raw.name ?? raw.vuln_type ?? 'Finding',
    module,
    description: text(over.description ?? raw.description ?? raw.detail ?? ''),
    location: over.location ?? locationOf(raw),
    evidence: text(over.evidence ?? raw.evidence ?? raw.matched_code ?? raw.value ?? ''),
    recommendation: text(over.recommendation ?? raw.recommendation ?? raw.remediation ?? ''),
    confidence: raw.confidence ?? null,
  };
}

// Modules with dedicated extraction below. Every other module (notably plugins) can
// report findings itself by returning { findings: [{ title, severity, ... }] }.
const DEDICATED = new Set([
  'Security Analysis', 'Advanced Content Scan', 'Subdomain Takeover',
  'Phishing Domain Protection', 'Web Archive Spy', 'CloudFlare Bypass',
]);

const HEADER_SEVERITY = { critical: 'critical', high: 'high', medium: 'medium' };

const TAKEOVER_BY_CONFIDENCE = { high: 'high', medium: 'medium', low: 'low' };

function securityFindings(sec) {
  const out = [];
  const M = 'Security Analysis';

  const scan = isObj(sec.vulnerability_scan) ? sec.vulnerability_scan.vulnerabilities : null;
  for (const v of [...list(scan), ...list(sec.vulnerabilities)]) {
    if (isObj(v)) out.push(make(M, v));
  }

  const headers = isObj(sec.security_headers) ? sec.security_headers.headers : null;
  if (isObj(headers)) {
    for (const [name, h] of Object.entries(headers)) {
      if (isObj(h) && h.present === false) {
        const level = String(h.importance || h.security_level || '').toLowerCase();
        out.push(make(M, {}, {
          severity: HEADER_SEVERITY[level] || 'low',
          title: `Missing security header: ${name}`,
          description: `The ${name} response header is not set.`,
          recommendation: `Add the ${name} header to your server responses.`,
        }));
      }
    }
  }

  for (const note of list(sec.server_information?.information_disclosure)) {
    out.push(make(M, {}, { severity: 'low', title: 'Information disclosure', description: text(note) }));
  }
  for (const m of list(sec.http_methods?.dangerous_methods)) {
    out.push(make(M, {}, {
      severity: 'high', title: `Dangerous HTTP method enabled: ${text(m)}`,
      recommendation: 'Disable HTTP methods that are not required.',
    }));
  }
  for (const issue of list(sec.cors_policy?.issues)) {
    const msg = isObj(issue) ? (issue.issue || issue.description || text(issue)) : text(issue);
    out.push(make(M, {}, { severity: 'medium', title: 'CORS misconfiguration', description: msg }));
  }
  if (sec.ssl_analysis?.ssl_available === false) {
    out.push(make(M, {}, {
      severity: 'high', title: 'TLS is not available',
      description: 'The target does not serve a valid HTTPS/TLS endpoint.',
      recommendation: 'Enable HTTPS with a valid certificate.',
    }));
  }
  return out;
}

const ACS_LISTS = [
  ['secrets', 'high', 'Exposed secret'],
  ['js_vulnerabilities', 'medium', 'JavaScript issue'],
  ['active_vulnerabilities', 'high', 'Active vulnerability'],
  ['ssrf_vulnerabilities', 'high', 'SSRF'],
];

function contentScanFindings(acs) {
  const out = [];
  const M = 'Advanced Content Scan';
  for (const [key, severity, fallback] of ACS_LISTS) {
    for (const f of list(acs[key])) {
      if (isObj(f)) out.push(make(M, f, { severity: f.severity || severity, title: f.type ?? f.vuln_type ?? f.name ?? fallback }));
    }
  }
  for (const e of list(acs.exposed_endpoints)) {
    if (!isObj(e)) continue;
    out.push(make(M, e, {
      title: `${e.endpoint_type || 'Endpoint'} exposed`,
      location: e.url || '',
      description: e.status_code ? `Responds with HTTP ${e.status_code}.` : '',
    }));
  }
  return out;
}

/** Flatten findings from every module into one list (each gets a stable id). */
export function extractFindings(results) {
  if (!isObj(results)) return [];
  const out = [];

  if (isObj(results['Security Analysis'])) out.push(...securityFindings(results['Security Analysis']));
  if (isObj(results['Advanced Content Scan'])) out.push(...contentScanFindings(results['Advanced Content Scan']));

  const takeover = results['Subdomain Takeover'];
  if (isObj(takeover)) {
    for (const t of [...list(takeover.vulnerable_subdomains), ...list(takeover.vulnerabilities)]) {
      const name = isObj(t) ? (t.subdomain || t.domain || t.host) : t;
      // No explicit severity: follow the module's own confidence (mirrors utils/result_analysis.py).
      const byConfidence = isObj(t) ? TAKEOVER_BY_CONFIDENCE[String(t.confidence || '').toLowerCase()] : undefined;
      out.push(make('Subdomain Takeover', isObj(t) ? t : {}, {
        severity: isObj(t) ? (t.severity || byConfidence || 'high') : 'high',
        title: `Subdomain takeover: ${text(name)}`,
        description: isObj(t) ? (t.description || t.service || '') : '',
      }));
    }
  }

  const phishing = results['Phishing Domain Protection'];
  if (isObj(phishing)) {
    for (const d of list(phishing.phishing_domains)) {
      if (!isObj(d)) continue;
      const ips = list(d.ips).join(', ');
      out.push(make('Phishing Domain Protection', d, {
        severity: d.severity || 'medium',
        title: `Look-alike domain: ${d.domain}`,
        description: `${d.status || 'Active'} look-alike${ips ? ` resolving to ${ips}` : ''}.`,
        recommendation: 'Monitor or take down look-alike domains that could be used for phishing.',
      }));
    }
  }

  const archive = results['Web Archive Spy'];
  if (isObj(archive)) {
    for (const s of list(archive.secrets)) {
      out.push(make('Web Archive Spy', isObj(s) ? s : {}, {
        severity: isObj(s) ? (s.severity || 'high') : 'high',
        title: `Historical secret: ${isObj(s) ? (s.type || s.secret_type || 'secret') : 'secret'}`,
        location: isObj(s) ? (s.url || s.source || '') : '',
        recommendation: 'Rotate the credential and remove it from public archives.',
      }));
    }
  }

  const cf = results['CloudFlare Bypass'];
  if (isObj(cf) && cf.cloudflare_protected) {
    const exposed = list(cf.real_ips).filter((r) => isObj(r) && r.source && r.source !== 'direct_dns');
    if (exposed.length) {
      out.push(make('CloudFlare Bypass', {}, {
        severity: 'high',
        title: 'Origin IP exposed behind CloudFlare',
        description: `Possible origin address(es): ${exposed.map((r) => r.ip).join(', ')}.`,
        recommendation: 'Restrict the origin to CloudFlare IP ranges so it cannot be reached directly.',
      }));
    }
  }

  for (const [name, data] of Object.entries(results)) {
    if (DEDICATED.has(name) || !isObj(data)) continue;
    for (const f of list(data.findings)) {
      if (isObj(f) && (f.title || f.type)) out.push(make(name, f, { severity: f.severity || 'info' }));
    }
  }

  return out.map((f, i) => ({ ...f, id: i }));
}

export function countBySeverity(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
  return counts;
}

/** Apply the severity chip and the search box. */
export function filterFindings(findings, { severity = 'all', query = '' } = {}) {
  const q = query.trim().toLowerCase();
  return findings.filter((f) => {
    if (severity !== 'all' && f.severity !== severity) return false;
    if (!q) return true;
    return [f.title, f.description, f.location, f.module].some((v) => String(v || '').toLowerCase().includes(q));
  });
}

/** Group identical issues so e.g. 16 "DOM XSS" hits show as one row with a count. */
export function groupFindings(findings) {
  const map = new Map();
  for (const f of findings) {
    const key = `${f.severity}|${f.module}|${f.title}`;
    if (!map.has(key)) map.set(key, { key, severity: f.severity, module: f.module, title: f.title, items: [] });
    map.get(key).items.push(f);
  }
  return [...map.values()].sort((a, b) =>
    severityRank(a.severity) - severityRank(b.severity)
    || b.items.length - a.items.length
    || a.title.localeCompare(b.title));
}

/** "CRITICAL: do X" strings -> { severity, text }, most severe first. */
export function parseRecommendations(items) {
  return list(items)
    .map((r) => {
      const s = text(r);
      const m = s.match(/^\s*(CRITICAL|HIGH|MEDIUM|LOW|INFO)\s*:\s*(.*)$/i);
      return m ? { severity: severityClass(m[1]), text: m[2] } : { severity: 'info', text: s };
    })
    .sort((a, b) => severityRank(a.severity) - severityRank(b.severity));
}

// Mirrors utils/result_analysis.py (posture_score): points taken off the Security Analysis
// score for findings from the other modules. Keep the two in step.
const PENALTY_PER_FINDING = { critical: 12, high: 7, medium: 3, low: 1, info: 0 };
const MODULE_PENALTY_CAP = 15;
const TOTAL_PENALTY_CAP = 40;

export function gradeFor(score) {
  for (const [floor, grade] of [[95, 'A+'], [90, 'A'], [80, 'B'], [70, 'C'], [60, 'D']]) {
    if (score >= floor) return grade;
  }
  return 'F';
}

/** { score, grade, base, penalty }: the Security Analysis score minus findings from the other modules. */
export function postureScore(results) {
  const { score: base, grade } = extractScore(results?.['Security Analysis']?.security_score);
  if (base == null) return { score: null, grade, base: null, penalty: 0 };
  const perModule = {};
  for (const f of extractFindings(results)) {
    if (f.module !== 'Security Analysis') perModule[f.module] = (perModule[f.module] || 0) + PENALTY_PER_FINDING[f.severity];
  }
  const penalty = Math.min(TOTAL_PENALTY_CAP,
    Object.values(perModule).reduce((sum, points) => sum + Math.min(MODULE_PENALTY_CAP, points), 0));
  if (penalty === 0) return { score: base, grade, base, penalty: 0 };
  const score = Math.max(0, base - penalty);
  return { score, grade: gradeFor(score), base, penalty };
}

const BREAKDOWN_LABELS = {
  security_headers: 'Security headers',
  ssl_tls: 'SSL / TLS',
  waf_protection: 'WAF protection',
  vulnerabilities: 'Vulnerabilities',
};

/** The four sub-scores behind the headline security score. */
export function scoreBreakdown(results) {
  const b = results?.['Security Analysis']?.security_score?.score_breakdown;
  if (!isObj(b)) return [];
  return Object.entries(b)
    .filter(([, v]) => typeof v === 'number')
    .map(([key, value]) => ({ key, label: BREAKDOWN_LABELS[key] || key, value }));
}

export function daysUntil(dateStr, now = Date.now()) {
  const t = Date.parse(dateStr);
  if (Number.isNaN(t)) return null;
  return Math.round((t - now) / 86400000);
}

const NOT_DETECTED = new Set(['', 'not detected', 'unknown', 'not found', 'none']);
const present = (v) => v != null && !NOT_DETECTED.has(String(v).trim().toLowerCase());

const TECH_KEYS = [
  'Web Server', 'Backend Technologies', 'Frontend Technologies', 'JavaScript Libraries', 'CSS Frameworks',
  'Content Management System', 'E-commerce Platform', 'CDN & Cloud Services', 'Analytics & Tracking',
];

/** Distinct detected technologies. Only the technology categories are read:
 *  the same payload also carries nested objects (security headers, scores, ...)
 *  that are not technologies, and non-string values are ignored. */
export function listTechnologies(tech) {
  if (!isObj(tech)) return [];
  const seen = new Set();
  for (const key of TECH_KEYS) {
    for (const v of (Array.isArray(tech[key]) ? tech[key] : [tech[key]])) {
      if ((typeof v === 'string' || typeof v === 'number') && present(v)) seen.add(String(v));
    }
  }
  return [...seen];
}

export const countTechnologies = (tech) => listTechnologies(tech).length;

/** Headline facts for the Summary tab: [{ label, value, tone? }]. */
export function extractFacts(results, now = Date.now()) {
  if (!isObj(results)) return [];
  const facts = [];
  const add = (label, value, tone) => { if (value !== null && value !== undefined && value !== '') facts.push({ label, value: String(value), tone }); };

  const info = isObj(results['Domain Information']) ? results['Domain Information'] : {};
  const sec = isObj(results['Security Analysis']) ? results['Security Analysis'] : {};
  const tech = isObj(results['Web Technologies']) ? results['Web Technologies'] : {};

  if (present(info['IP Address'])) add('IP address', info['IP Address']);
  if (present(info['Registrar Company'])) add('Registrar', info['Registrar Company']);

  if (present(info['Expiry Date'])) {
    const days = daysUntil(info['Expiry Date'], now);
    const when = String(info['Expiry Date']).slice(0, 10);
    add('Domain expires', days == null ? when : `${when} (${days} days)`, days != null && days < 30 ? 'high' : days != null && days < 90 ? 'medium' : undefined);
  }

  const ssl = isObj(sec.ssl_analysis) ? sec.ssl_analysis : {};
  const sslInfo = isObj(info['SSL Information']) ? info['SSL Information'] : {};
  const proto = ssl.protocol_version || sslInfo['Protocol Version'];
  if (present(proto)) add('TLS', ssl.overall_grade ? `${proto} · grade ${ssl.overall_grade}` : proto);
  const certDays = sslInfo['Days Until Expiry'];
  if (typeof certDays === 'number') add('Certificate expires', `in ${certDays} days`, certDays < 15 ? 'critical' : certDays < 30 ? 'high' : undefined);

  const server = [tech['Web Server'], info['Web Server'], sec.server_information?.server_headers?.Server].find(present);
  if (server) add('Web server', server);

  const waf = sec.waf_detection;
  if (isObj(waf)) {
    add('WAF', waf.detected ? (waf.primary_waf?.provider || waf.provider || 'Detected') : 'None detected', waf.detected ? undefined : 'medium');
  }

  const techCount = countTechnologies(tech);
  if (techCount) add('Technologies', `${techCount} detected`);

  const subs = results['Subdomain Discovery'];
  if (Array.isArray(subs)) add('Subdomains', subs.length);

  const nmapPorts = results['Nmap Zero Day Scan']?.port_scan?.open_ports;
  if (Array.isArray(nmapPorts)) add('Open ports', nmapPorts.length ? nmapPorts.join(', ') : 'none');
  else if (present(info['Open Ports'])) add('Open ports', info['Open Ports']);

  const lookalikes = results['Phishing Domain Protection']?.total_active_phishing_domains;
  if (typeof lookalikes === 'number') add('Look-alike domains', lookalikes, lookalikes > 0 ? 'high' : undefined);

  const contact = results['Contact Spy']?.summary;
  if (isObj(contact)) add('Contacts found', (contact.total_emails || 0) + (contact.total_phones || 0));

  return facts;
}

/** 'error' when the module reported a failure, 'empty' when it returned nothing. */
export function moduleStatus(data) {
  if (isObj(data) && data.error) return 'error';
  const empty = data == null || data === ''
    || (Array.isArray(data) && data.length === 0)
    || (isObj(data) && Object.keys(data).length === 0);
  return empty ? 'empty' : 'ok';
}

/** Plain-text export of grouped findings, for pasting into a ticket or report. */
export function findingsToText(domain, groups) {
  const lines = [`Findings for ${domain}`, ''];
  for (const g of groups) {
    lines.push(`[${g.severity.toUpperCase()}] ${g.title} (${g.module})${g.items.length > 1 ? ` x${g.items.length}` : ''}`);
    const first = g.items[0];
    if (first.description) lines.push(`  ${first.description}`);
    for (const it of g.items.slice(0, 10)) if (it.location) lines.push(`  - ${it.location}`);
    if (first.recommendation) lines.push(`  Fix: ${first.recommendation}`);
    lines.push('');
  }
  return lines.join('\n').trim();
}
