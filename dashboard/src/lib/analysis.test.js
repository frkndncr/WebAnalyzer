import { describe, it, expect } from 'vitest';
import { extractScore, scoreSeverity, severityClass, cleanDomain, timeAgo, isReady, dbProblem, MODULES, PRESETS } from './analysis';

describe('extractScore', () => {
  it('handles a plain integer', () => {
    expect(extractScore(68)).toEqual({ score: 68, grade: null });
  });
  it('parses a "50/100" string', () => {
    expect(extractScore('50/100')).toEqual({ score: 50, grade: null });
  });
  it('reads overall_score + grade objects', () => {
    expect(extractScore({ overall_score: 77, grade: 'C' })).toEqual({ score: 77, grade: 'C' });
  });
  it('reads {Score, Grade} objects', () => {
    expect(extractScore({ Score: '50/100', Grade: 'D' })).toEqual({ score: 50, grade: 'D' });
  });
  it('returns nulls for null/undefined', () => {
    expect(extractScore(null)).toEqual({ score: null, grade: null });
    expect(extractScore(undefined)).toEqual({ score: null, grade: null });
  });
});

describe('scoreSeverity', () => {
  it('maps bands', () => {
    expect(scoreSeverity(95)).toBe('ok');
    expect(scoreSeverity(70)).toBe('medium');
    expect(scoreSeverity(45)).toBe('high');
    expect(scoreSeverity(10)).toBe('critical');
    expect(scoreSeverity(null)).toBe('info');
  });
});

describe('severityClass', () => {
  it('normalises common labels', () => {
    expect(severityClass('Critical')).toBe('critical');
    expect(severityClass('HIGH')).toBe('high');
    expect(severityClass('medium')).toBe('medium');
    expect(severityClass('Low')).toBe('low');
    expect(severityClass('whatever')).toBe('info');
    expect(severityClass(undefined)).toBe('info');
  });
});

describe('cleanDomain', () => {
  it('strips scheme and path', () => {
    expect(cleanDomain('https://Example.com/login?x=1')).toBe('example.com');
    expect(cleanDomain('  EXAMPLE.com  ')).toBe('example.com');
  });
});

describe('timeAgo', () => {
  it('returns empty for falsy/invalid', () => {
    expect(timeAgo('')).toBe('');
    expect(timeAgo('not-a-date')).toBe('');
  });
  it('formats a past date', () => {
    const d = new Date(Date.now() - 3 * 3600 * 1000).toISOString();
    expect(timeAgo(d)).toBe('3h ago');
  });
});

describe('catalogue', () => {
  it('exposes 16 modules and presets that reference real module names', () => {
    expect(MODULES).toHaveLength(16);
    const names = new Set(MODULES.map((m) => m.name));
    for (const preset of Object.values(PRESETS)) {
      for (const n of preset) expect(names.has(n)).toBe(true);
    }
  });
});

describe('isReady', () => {
  it('needs data and no scan in flight', () => {
    expect(isReady({ has_data: true, is_scanning: false })).toBe(true);
    expect(isReady({ has_data: true, is_scanning: true })).toBe(false);
    expect(isReady({ has_data: false, is_scanning: false })).toBe(false);
    expect(isReady(null)).toBe(false);
  });
});

describe('dbProblem', () => {
  it('is null while the database is fine or the status is unknown', () => {
    expect(dbProblem(null)).toBeNull();
    expect(dbProblem({ api_status: 'online' })).toBeNull();
    expect(dbProblem({ database: { connected: true, error: null } })).toBeNull();
  });
  it('explains a known failure and carries the retry hint', () => {
    expect(dbProblem({ database: { connected: false, error: 'too_many_connections', retry_in: 12 } }))
      .toEqual({ reason: 'the database has reached its connection limit', retryIn: 12 });
  });
  it('falls back to a generic reason for unknown errors', () => {
    expect(dbProblem({ database: { connected: false, error: 'weird' } }).reason).toBe('the database is unavailable');
  });
});
