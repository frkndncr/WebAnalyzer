/**
 * The module catalogue (which analysis modules exist, which are intrusive, the
 * scan presets). The live list comes from GET /api/modules, so a module added on
 * the backend appears here with no frontend change; catalogue.default.json is a
 * snapshot of the backend's registry (kept in sync by a backend test) used until
 * the API answers or when it is unreachable.
 */
import DEFAULT_PAYLOAD from './catalogue.default.json';

/** Normalise an API payload into everything the UI needs. Invalid input falls back to the snapshot. */
export function buildCatalogue(payload) {
  const valid = payload && Array.isArray(payload.modules) && payload.modules.length > 0
    && payload.modules.every((m) => m && typeof m.name === 'string' && m.name);
  const source = valid ? payload : DEFAULT_PAYLOAD;

  const modules = source.modules.map((m) => ({
    name: m.name,
    description: m.description || '',
    group: m.group || 'recon',
    weight: m.weight || 'medium',
    active: Boolean(m.active),
  }));
  const names = modules.map((m) => m.name);
  const known = new Set(names);
  const only = (list) => (Array.isArray(list) ? list : []).filter((n) => known.has(n));

  return {
    modules,
    names,
    byName: Object.fromEntries(modules.map((m) => [m.name, m])),
    activeNames: modules.filter((m) => m.active).map((m) => m.name),
    presets: {
      quick: only(source.presets?.quick),
      standard: only(source.presets?.standard),
      full: names,
    },
  };
}

export const DEFAULT_CATALOGUE = buildCatalogue(null);
