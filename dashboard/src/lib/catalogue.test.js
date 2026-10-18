import { describe, it, expect } from 'vitest';
import { buildCatalogue, DEFAULT_CATALOGUE } from './catalogue';

const payload = {
  modules: [
    { name: 'DNS Records', description: 'records', group: 'recon', weight: 'light', active: false },
    { name: 'Nmap Zero Day Scan', description: 'ports', group: 'offensive', weight: 'heavy', active: true },
    { name: 'My Plugin', description: 'from a PR', group: 'security', weight: 'light', active: false },
  ],
  presets: { quick: ['DNS Records', 'Gone Module'], standard: ['DNS Records', 'My Plugin'], full: ['ignored'] },
};

describe('buildCatalogue', () => {
  it('exposes a module added on the backend with no frontend change', () => {
    const c = buildCatalogue(payload);
    expect(c.names).toContain('My Plugin');
    expect(c.byName['My Plugin'].description).toBe('from a PR');
  });

  it('derives the active modules and the full preset from the modules themselves', () => {
    const c = buildCatalogue(payload);
    expect(c.activeNames).toEqual(['Nmap Zero Day Scan']);
    expect(c.presets.full).toEqual(['DNS Records', 'Nmap Zero Day Scan', 'My Plugin']);
  });

  it('drops preset entries that no longer exist', () => {
    expect(buildCatalogue(payload).presets.quick).toEqual(['DNS Records']);
  });

  it('keeps the backend order', () => {
    expect(buildCatalogue(payload).names).toEqual(['DNS Records', 'Nmap Zero Day Scan', 'My Plugin']);
  });

  it('fills in defaults for missing fields', () => {
    const c = buildCatalogue({ modules: [{ name: 'Bare' }], presets: {} });
    expect(c.byName.Bare).toEqual({ name: 'Bare', description: '', group: 'recon', weight: 'medium', active: false });
    expect(c.presets.standard).toEqual([]);
  });

  it.each([null, undefined, {}, { modules: [] }, { modules: 'x' }, { modules: [{ nope: 1 }] }])(
    'falls back to the bundled snapshot for %j', (bad) => {
      expect(buildCatalogue(bad).names).toEqual(DEFAULT_CATALOGUE.names);
    });
});

describe('bundled snapshot', () => {
  it('contains the built-in modules, the shipped plugin and the intrusive flags', () => {
    expect(DEFAULT_CATALOGUE.names).toHaveLength(28);
    expect(DEFAULT_CATALOGUE.names).toContain('Security.txt');
    expect(DEFAULT_CATALOGUE.names).toContain('Email Security');
    expect([...DEFAULT_CATALOGUE.activeNames].sort()).toEqual(
      ['Advanced Content Scan', 'Cloud Storage', 'CloudFlare Bypass', 'DNS Zone Transfer', 'Exposed Files',
        'Nmap Zero Day Scan', 'Subdomain Takeover']);
  });

  it('has presets that only reference real modules', () => {
    for (const list of Object.values(DEFAULT_CATALOGUE.presets)) {
      for (const n of list) expect(DEFAULT_CATALOGUE.byName[n]).toBeDefined();
    }
    expect(DEFAULT_CATALOGUE.presets.full).toHaveLength(28);
  });
});
