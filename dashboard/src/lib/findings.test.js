import { describe, it, expect } from 'vitest';
import {
  extractFindings, countBySeverity, filterFindings, groupFindings,
  parseRecommendations, scoreBreakdown, extractFacts, daysUntil, countTechnologies, listTechnologies, postureScore, gradeFor,
} from './findings';

const sample = {
  'Security Analysis': {
    security_score: { overall_score: 54, grade: 'F', score_breakdown: { security_headers: 0, ssl_tls: 100, waf_protection: 60, vulnerabilities: 100 } },
    security_headers: { headers: {
      'Strict-Transport-Security': { present: false, importance: 'Critical' },
      'X-Frame-Options': { present: false, importance: 'High' },
      'X-Content-Type-Options': { present: true, importance: 'Medium' },
    } },
    vulnerability_scan: { vulnerabilities: [{ type: 'Open Redirect', severity: 'High', description: 'Redirects anywhere' }] },
    server_information: { information_disclosure: ['Web server version disclosed'], server_headers: { Server: 'LiteSpeed' } },
    http_methods: { dangerous_methods: ['TRACE'] },
    cors_policy: { issues: ['Wildcard origin'] },
    ssl_analysis: { ssl_available: true, protocol_version: 'TLSv1.3', overall_grade: 'A+' },
    waf_detection: { detected: false },
  },
  'Advanced Content Scan': {
    js_vulnerabilities: [
      { type: 'DOM XSS', severity: 'High', source_url: 'https://x.com/a.js', line: 2, matched_code: 'innerHTML', recommendation: 'Sanitise' },
      { type: 'DOM XSS', severity: 'High', source_url: 'https://x.com/b.js', line: 9 },
    ],
    secrets: [],
    exposed_endpoints: [{ endpoint_type: 'Robots File', url: 'https://x.com/robots.txt', status_code: 200, severity: 'Info' }],
  },
  'Phishing Domain Protection': {
    total_active_phishing_domains: 1,
    phishing_domains: [{ domain: 'x-c0m.com', ips: ['1.2.3.4'], status: 'Active', severity: 'High' }],
  },
  'Domain Information': {
    'IP Address': '1.1.1.1', 'Registrar Company': 'Acme Registrar', 'Expiry Date': '2027-01-01T00:00:00Z',
    'SSL Information': { 'Protocol Version': 'TLSv1.3', 'Days Until Expiry': 10 },
  },
  'Web Technologies': { 'Web Server': 'Cloudflare', 'Backend Technologies': ['PHP'], 'Frontend Technologies': ['Vue.js', 'jQuery'], 'CSS Frameworks': 'Not Detected' },
  'Subdomain Discovery': ['a.x.com', 'b.x.com'],
  'Nmap Zero Day Scan': { port_scan: { open_ports: [80, 443] } },
  'Contact Spy': { summary: { total_emails: 1, total_phones: 2 } },
};

describe('extractFindings', () => {
  const findings = extractFindings(sample);
  const titles = findings.map((f) => f.title);

  it('collects findings from every module', () => {
    expect(titles).toContain('Open Redirect');
    expect(titles).toContain('DOM XSS');
    expect(titles).toContain('Missing security header: Strict-Transport-Security');
    expect(titles).toContain('Dangerous HTTP method enabled: TRACE');
    expect(titles).toContain('CORS misconfiguration');
    expect(titles).toContain('Look-alike domain: x-c0m.com');
    expect(titles).toContain('Robots File exposed');
  });

  it('does not report headers that are present', () => {
    expect(titles.join('|')).not.toContain('X-Content-Type-Options');
  });

  it('maps header importance to severity', () => {
    expect(findings.find((f) => f.title.includes('Strict-Transport')).severity).toBe('critical');
    expect(findings.find((f) => f.title.includes('X-Frame')).severity).toBe('high');
  });

  it('keeps location, evidence and recommendation', () => {
    const xss = findings.find((f) => f.title === 'DOM XSS');
    expect(xss.location).toBe('https://x.com/a.js:2');
    expect(xss.evidence).toBe('innerHTML');
    expect(xss.recommendation).toBe('Sanitise');
  });

  it('assigns unique ids', () => {
    expect(new Set(findings.map((f) => f.id)).size).toBe(findings.length);
  });

  it('is safe on empty or malformed input', () => {
    expect(extractFindings(null)).toEqual([]);
    expect(extractFindings({})).toEqual([]);
    expect(extractFindings({ 'Security Analysis': 'oops', 'Advanced Content Scan': [] })).toEqual([]);
  });

  it('reports exposed origin IPs only when CloudFlare is in front', () => {
    const exposed = extractFindings({ 'CloudFlare Bypass': { cloudflare_protected: true, real_ips: [{ ip: '9.9.9.9', source: 'history' }] } });
    expect(exposed[0].title).toContain('Origin IP exposed');
    const direct = extractFindings({ 'CloudFlare Bypass': { cloudflare_protected: false, real_ips: [{ ip: '9.9.9.9', source: 'direct_dns' }] } });
    expect(direct).toEqual([]);
  });
});

describe('counting, filtering and grouping', () => {
  const findings = extractFindings(sample);

  it('counts by severity', () => {
    const c = countBySeverity(findings);
    expect(c.critical).toBe(1);
    expect(c.high).toBeGreaterThanOrEqual(4);
    expect(Object.values(c).reduce((a, b) => a + b, 0)).toBe(findings.length);
  });

  it('filters by severity and by search text', () => {
    expect(filterFindings(findings, { severity: 'critical' })).toHaveLength(1);
    expect(filterFindings(findings, { query: 'dom xss' })).toHaveLength(2);
    expect(filterFindings(findings, { severity: 'low', query: 'dom xss' })).toHaveLength(0);
    expect(filterFindings(findings, {})).toHaveLength(findings.length);
  });

  it('groups identical issues and orders by severity', () => {
    const groups = groupFindings(findings);
    const xss = groups.find((g) => g.title === 'DOM XSS');
    expect(xss.items).toHaveLength(2);
    expect(groups[0].severity).toBe('critical');
  });
});

describe('parseRecommendations', () => {
  it('splits the severity prefix and sorts most severe first', () => {
    const out = parseRecommendations(['MEDIUM: add a WAF', 'CRITICAL: fix headers', 'plain advice']);
    expect(out[0]).toEqual({ severity: 'critical', text: 'fix headers' });
    expect(out[1]).toEqual({ severity: 'medium', text: 'add a WAF' });
    expect(out[2]).toEqual({ severity: 'info', text: 'plain advice' });
  });
  it('handles non-arrays', () => {
    expect(parseRecommendations(undefined)).toEqual([]);
  });
});

describe('scoreBreakdown', () => {
  it('labels the four sub-scores', () => {
    const b = scoreBreakdown(sample);
    expect(b).toHaveLength(4);
    expect(b[0]).toEqual({ key: 'security_headers', label: 'Security headers', value: 0 });
  });
  it('returns [] when absent', () => {
    expect(scoreBreakdown({})).toEqual([]);
  });
});

describe('extractFacts', () => {
  const now = Date.parse('2026-10-11T00:00:00Z');
  const facts = extractFacts(sample, now);
  const get = (label) => facts.find((f) => f.label === label);

  it('extracts the headline facts', () => {
    expect(get('IP address').value).toBe('1.1.1.1');
    expect(get('Registrar').value).toBe('Acme Registrar');
    expect(get('Web server').value).toBe('Cloudflare');
    expect(get('Subdomains').value).toBe('2');
    expect(get('Open ports').value).toBe('80, 443');
    expect(get('Contacts found').value).toBe('3');
    expect(get('Technologies').value).toBe('4 detected'); // Cloudflare, PHP, Vue.js, jQuery
  });

  it('flags a short certificate lifetime and a missing WAF', () => {
    expect(get('Certificate expires').tone).toBe('critical');
    expect(get('WAF').value).toBe('None detected');
    expect(get('Look-alike domains').tone).toBe('high');
  });

  it('computes days until domain expiry', () => {
    expect(get('Domain expires').value).toContain('2027-01-01');
    expect(get('Domain expires').value).toContain('days');
  });

  it('is empty for nothing', () => {
    expect(extractFacts(null)).toEqual([]);
  });
});

describe('daysUntil / countTechnologies', () => {
  it('daysUntil handles valid and invalid dates', () => {
    const now = Date.parse('2026-01-01T00:00:00Z');
    expect(daysUntil('2026-01-11T00:00:00Z', now)).toBe(10);
    expect(daysUntil('garbage', now)).toBeNull();
  });
  it('countTechnologies ignores "Not Detected" and dedupes', () => {
    expect(countTechnologies({ 'Backend Technologies': ['PHP', 'PHP'], 'CSS Frameworks': 'Not Detected', 'Frontend Technologies': ['Vue.js'] })).toBe(2);
    expect(countTechnologies(null)).toBe(0);
  });
});

import { moduleStatus, findingsToText } from './findings';
import { localize } from './analysis';

describe('moduleStatus', () => {
  it('classifies module output', () => {
    expect(moduleStatus({ error: 'boom' })).toBe('error');
    expect(moduleStatus(null)).toBe('empty');
    expect(moduleStatus([])).toBe('empty');
    expect(moduleStatus({})).toBe('empty');
    expect(moduleStatus({ a: 1 })).toBe('ok');
    expect(moduleStatus(['x'])).toBe('ok');
  });
});

describe('findingsToText', () => {
  it('renders grouped findings as plain text', () => {
    const groups = groupFindings(extractFindings(sample));
    const out = findingsToText('x.com', groups);
    expect(out.startsWith('Findings for x.com')).toBe(true);
    expect(out).toContain('[CRITICAL] Missing security header: Strict-Transport-Security');
    expect(out).toContain('DOM XSS (Advanced Content Scan) x2');
    expect(out).toContain('- https://x.com/a.js:2');
  });
});

describe('localize', () => {
  it('translates legacy Turkish values and leaves everything else alone', () => {
    expect(localize('Bulunamadı')).toBe('Not found');
    expect(localize('WHOIS hatası: timeout')).toBe('WHOIS error: timeout');
    expect(localize('hello')).toBe('hello');
    expect(localize(5)).toBe(5);
  });
});

describe('listTechnologies', () => {
  const payload = {
    'Web Server': 'Hcdn', 'Backend Technologies': ['Not Detected'], 'Frontend Technologies': ['Vue.js'],
    'JavaScript Libraries': ['jQuery'], 'CSS Frameworks': ['Bootstrap', 'Tailwind CSS'],
    'Security Headers': { 'Content-Security-Policy': { present: true } },
    'Security Score': { overall_score: 77 },
    'Technology Security Analysis': { overall_risk: 'Medium' },
  };
  it('lists real technologies and ignores nested objects and "Not Detected"', () => {
    expect(listTechnologies(payload)).toEqual(['Hcdn', 'Vue.js', 'jQuery', 'Bootstrap', 'Tailwind CSS']);
  });
  it('never produces "[object Object]"', () => {
    expect(listTechnologies({ 'Backend Technologies': [{ a: 1 }, 'PHP'] })).toEqual(['PHP']);
  });
  it('count and list always agree', () => {
    expect(countTechnologies(payload)).toBe(listTechnologies(payload).length);
  });
  it('handles junk input', () => {
    expect(listTechnologies(null)).toEqual([]);
    expect(listTechnologies('x')).toEqual([]);
  });
});

describe('findings reported by plugins', () => {
  const plugin = {
    'My Plugin': {
      findings: [
        { title: 'Open admin panel', severity: 'High', description: 'Reachable without login', location: 'https://x.org/admin', recommendation: 'Restrict access' },
        { type: 'Old library', severity: 'low' },
        { title: 'Needs a look' },
      ],
    },
  };

  it('counts them with their severity, defaulting to info', () => {
    const c = countBySeverity(extractFindings(plugin));
    expect([c.high, c.low, c.info]).toEqual([1, 1, 1]);
  });

  it('attributes them to the plugin and keeps the details', () => {
    const admin = extractFindings(plugin).find((f) => f.title === 'Open admin panel');
    expect(admin.module).toBe('My Plugin');
    expect(admin.location).toBe('https://x.org/admin');
    expect(admin.recommendation).toBe('Restrict access');
  });

  it('accepts `type` as the title', () => {
    expect(extractFindings(plugin).map((f) => f.title)).toContain('Old library');
  });

  it('ignores malformed entries', () => {
    expect(extractFindings({ P: { findings: ['x', null, { severity: 'high' }, { title: '' }, 5] } })).toEqual([]);
    expect(extractFindings({ P: { findings: 'nope' } })).toEqual([]);
  });

  it('does not double count modules that already have dedicated handling', () => {
    const res = { 'Security Analysis': { findings: [{ title: 'X', severity: 'high' }], vulnerability_scan: { vulnerabilities: [{ type: 'Real', severity: 'high' }] } } };
    expect(extractFindings(res).map((f) => f.title)).toEqual(['Real']);
  });
});



describe('posture score', () => {
  const base = (score, grade, extra = {}) => ({ 'Security Analysis': { security_score: { overall_score: score, grade } }, ...extra });
  const plugin = (...sevs) => ({ findings: sevs.map((severity, i) => ({ title: `issue ${i}`, severity })) });

  it('keeps the module score and grade when nothing else was found', () => {
    expect(postureScore(base(83, 'B'))).toEqual({ score: 83, grade: 'B', base: 83, penalty: 0 });
  });

  it('subtracts findings from the other modules and re-grades', () => {
    expect(postureScore(base(90, 'A', { 'Email Security': plugin('high', 'medium') })))
      .toEqual({ score: 80, grade: 'B', base: 90, penalty: 10 });
  });

  it('never counts Security Analysis findings again, and info costs nothing', () => {
    const res = base(90, 'A', { 'Security.txt': plugin('info', 'info') });
    res['Security Analysis'].vulnerability_scan = { vulnerabilities: [{ type: 'X', severity: 'Critical' }] };
    expect(postureScore(res).penalty).toBe(0);
  });

  it('caps one module at 15 and all modules at 40', () => {
    expect(postureScore(base(100, 'A+', { 'Exposed Files': plugin(...Array(10).fill('critical')) })).penalty).toBe(15);
    const many = Object.fromEntries(Array.from({ length: 6 }, (_, i) => [`M${i}`, plugin('critical', 'critical')]));
    expect(postureScore(base(100, 'A+', many)).penalty).toBe(40);
    expect(postureScore(base(10, 'F', many)).score).toBe(0);
  });

  it('has no score without Security Analysis', () => {
    expect(postureScore({ 'Email Security': plugin('high') })).toEqual({ score: null, grade: null, base: null, penalty: 0 });
  });

  it('uses the same grade bands as the backend', () => {
    expect([100, 95, 94, 90, 89, 80, 79, 70, 69, 60, 59, 0].map(gradeFor))
      .toEqual(['A+', 'A+', 'A', 'A', 'B', 'B', 'C', 'C', 'D', 'D', 'F', 'F']);
  });
});

describe('takeover severity', () => {
  it('follows the confidence when no severity is given', () => {
    const found = extractFindings({ 'Subdomain Takeover': { vulnerable_subdomains: [
      { subdomain: 'a.x.org', confidence: 'High' }, { subdomain: 'b.x.org', confidence: 'Medium' },
      { subdomain: 'c.x.org', confidence: 'Low' }, { subdomain: 'd.x.org' },
      { subdomain: 'e.x.org', confidence: 'Low', severity: 'Critical' },
    ] } });
    expect(Object.fromEntries(found.map((f) => [f.title, f.severity]))).toEqual({
      'Subdomain takeover: a.x.org': 'high', 'Subdomain takeover: b.x.org': 'medium', 'Subdomain takeover: c.x.org': 'low',
      'Subdomain takeover: d.x.org': 'high', 'Subdomain takeover: e.x.org': 'critical',
    });
  });
});