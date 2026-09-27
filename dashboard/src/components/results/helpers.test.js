import { describe, it, expect } from 'vitest';
import { extractScore, safeText, categorizeModule } from './helpers';

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

describe('safeText', () => {
  it('passes through primitives', () => {
    expect(safeText('x')).toBe('x');
    expect(safeText(5)).toBe('5');
    expect(safeText(true)).toBe('true');
  });

  it('returns empty string for null/undefined', () => {
    expect(safeText(null)).toBe('');
    expect(safeText(undefined)).toBe('');
  });

  it('prefers display-friendly object fields', () => {
    expect(safeText({ provider: 'AWS' })).toBe('AWS');
    expect(safeText({ name: 'nginx' })).toBe('nginx');
  });

  it('falls back to JSON for arbitrary objects', () => {
    expect(safeText({ a: 1 })).toBe('{"a":1}');
  });
});

describe('categorizeModule', () => {
  it('flags errors', () => {
    expect(categorizeModule('m', { error: 'boom' })).toContain('errors');
  });

  it('flags vulnerabilities', () => {
    expect(categorizeModule('m', { vulnerabilities: [1] })).toContain('vulnerabilities');
  });

  it('flags an array of findings with severity', () => {
    expect(categorizeModule('m', [{ severity: 'high' }])).toContain('vulnerabilities');
  });

  it('defaults to information', () => {
    expect(categorizeModule('m', { foo: 1 })).toEqual(['information']);
  });
});
