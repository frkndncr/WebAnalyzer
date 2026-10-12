/**
 * Pure, framework-free helpers for the dashboard: the module catalogue, score
 * extraction, severity normalisation and small formatters. Unit tested in
 * analysis.test.js.
 */

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

/** True when a threat-intel / network-map payload has finished data to render. */
export const isReady = (payload) => Boolean(payload && payload.has_data && !payload.is_scanning);

const DB_REASONS = {
  too_many_connections: 'the database has reached its connection limit',
  pool_exhausted: 'all database connections are busy',
  cannot_connect: 'the database server cannot be reached',
  unknown_host: 'the database host name cannot be resolved',
  access_denied: 'the database rejected the credentials',
  unknown_database: 'the configured database does not exist',
  host_blocked: 'the database blocked this server',
  connection_lost: 'the database connection was lost',
  timeout: 'the database connection timed out',
};

/** null when the database is fine (or unknown); otherwise { reason, retryIn }. */
export function dbProblem(health) {
  const db = health?.database;
  if (!db || db.connected !== false) return null;
  return { reason: DB_REASONS[db.error] || 'the database is unavailable', retryIn: db.retry_in || 0 };
}
