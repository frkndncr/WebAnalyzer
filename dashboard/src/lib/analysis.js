/**
 * Pure, framework-free helpers for the dashboard: the module catalogue, score
 * extraction, severity normalisation and small formatters. Unit tested in
 * analysis.test.js.
 */

/* The 16 analysis modules. `name` must match the backend's module keys exactly
 * (they are sent verbatim in POST /api/scan). */
export const MODULES = [
  { name: 'Domain Information', desc: 'WHOIS, registrar, dates', tier: 'low', group: 'recon' },
  { name: 'DNS Records', desc: 'A, MX, TXT, CNAME records', tier: 'low', group: 'recon' },
  { name: 'GEO Analysis', desc: 'Geolocation & AI directives', tier: 'low', group: 'recon' },
  { name: 'SEO Analysis', desc: 'Meta tags, Open Graph', tier: 'low', group: 'recon' },
  { name: 'Web Technologies', desc: 'Frameworks, CMS, stack', tier: 'low', group: 'recon' },
  { name: 'Contact Spy', desc: 'Emails, phones, socials', tier: 'medium', group: 'recon' },
  { name: 'Subdomain Discovery', desc: 'Subdomain enumeration', tier: 'medium', group: 'recon' },
  { name: 'Security Analysis', desc: 'Headers, SSL/TLS, WAF', tier: 'medium', group: 'security' },
  { name: 'Advanced Content Scan', desc: 'Secrets, JS taint, SSRF', tier: 'medium', group: 'security' },
  { name: 'Web Archive Spy', desc: 'Wayback secret scraping', tier: 'medium', group: 'security' },
  { name: 'SSL SAN Association', desc: 'Certificate asset mapping', tier: 'medium', group: 'security' },
  { name: 'Subdomain Takeover', desc: 'Dangling CNAME checks', tier: 'high', group: 'offensive' },
  { name: 'CloudFlare Bypass', desc: 'Origin IP unmasking', tier: 'high', group: 'offensive' },
  { name: 'Nmap Zero Day Scan', desc: 'Ports & service scan', tier: 'high', group: 'offensive' },
  { name: 'Phishing Domain Protection', desc: 'Typosquat detection', tier: 'high', group: 'offensive' },
  { name: 'Attack Path Planner', desc: 'Exploit chain roadmap', tier: 'high', group: 'offensive' },
];

export const PRESETS = {
  quick: ['Domain Information', 'DNS Records', 'GEO Analysis'],
  standard: ['Domain Information', 'DNS Records', 'GEO Analysis', 'SEO Analysis', 'Web Technologies', 'Security Analysis'],
  full: MODULES.map((m) => m.name),
};

/** Normalise any score shape (int, "50/100", {overall_score|score|Score}) to
 *  { score:number|null, grade:string|null }. */
export function extractScore(raw) {
  if (raw == null) return { score: null, grade: null };
  if (typeof raw === 'number') return { score: raw, grade: null };
  if (typeof raw === 'string') {
    const m = raw.match(/(\d+)/);
    return { score: m ? parseInt(m[1], 10) : null, grade: null };
  }
  if (typeof raw === 'object') {
    let s = raw.overall_score ?? raw.score ?? raw.Score ?? null;
    if (typeof s === 'string') { const m2 = s.match(/(\d+)/); s = m2 ? parseInt(m2[1], 10) : null; }
    const g = raw.grade ?? raw.Grade ?? raw.security_grade ?? null;
    return { score: s, grade: g };
  }
  return { score: null, grade: null };
}

/** A 0–100 score to a severity class + color token. Higher score = safer. */
export function scoreSeverity(score) {
  if (score == null) return 'info';
  if (score >= 85) return 'ok';
  if (score >= 60) return 'medium';
  if (score >= 40) return 'high';
  return 'critical';
}

/** Normalise an arbitrary severity string to one of our class names. */
export function severityClass(sev) {
  const s = String(sev || '').toLowerCase();
  if (s.startsWith('crit')) return 'critical';
  if (s.startsWith('high')) return 'high';
  if (s.startsWith('med')) return 'medium';
  if (s.startsWith('low')) return 'low';
  return 'info';
}

/** Compact "time ago" from an ISO date string. */
export function timeAgo(iso) {
  if (!iso) return '';
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return '';
  const secs = Math.max(0, (Date.now() - then) / 1000);
  const units = [[31536000, 'y'], [2592000, 'mo'], [86400, 'd'], [3600, 'h'], [60, 'm']];
  for (const [size, label] of units) {
    if (secs >= size) return `${Math.floor(secs / size)}${label} ago`;
  }
  return 'just now';
}

/** Strip scheme/path to a bare host for display and scan submission. */
export function cleanDomain(raw) {
  return String(raw || '')
    .trim()
    .replace(/^https?:\/\//i, '')
    .replace(/\/.*$/, '')
    .toLowerCase();
}

/* Scans stored before the backend was translated still contain a few Turkish
 * status values; show them in English. */
const LEGACY_TEXT = {
  'Bulunamadı': 'Not found',
  'Erişilemedi': 'Unreachable',
  'Açık port bulunamadı': 'No open ports found',
  'IP adresi olmadan port taraması yapılamaz': 'Port scan is not possible without an IP address',
  'WHOIS sunucusuna bağlanılamadı': 'Could not connect to the WHOIS server',
};

export function localize(value) {
  if (typeof value !== 'string') return value;
  if (LEGACY_TEXT[value]) return LEGACY_TEXT[value];
  return value.startsWith('WHOIS hatası:') ? value.replace('WHOIS hatası:', 'WHOIS error:') : value;
}
