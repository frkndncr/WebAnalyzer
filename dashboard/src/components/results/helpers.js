/**
 * Pure helpers shared across the results renderers. Kept free of JSX so they
 * can be unit tested and imported without pulling in React components.
 */

/* Universal score extractor — handles every backend score format:
 *   - integer: 68
 *   - string: "50/100"
 *   - object: {Score: "50/100", Percentage: "50.0%", Grade: "D"}
 *   - object: {overall_score: 77, grade: "C", ...}
 */
export const extractScore = (raw) => {
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
};

/* Converts any non-primitive to a readable string so React never crashes
 * trying to render an object as a child. */
export const safeText = (val) => {
  if (val == null) return '';
  if (typeof val === 'string' || typeof val === 'number' || typeof val === 'boolean') return String(val);
  if (typeof val === 'object') {
    // Try common display-friendly fields first
    if (val.provider) return String(val.provider);
    if (val.status) return String(val.status);
    if (val.name) return String(val.name);
    if (val.Score) return String(val.Score);
    if (val.value) return String(val.value);
    return JSON.stringify(val);
  }
  return String(val);
};

/* Classify a module's result into 'information' / 'vulnerabilities' / 'errors'. */
export const categorizeModule = (moduleName, moduleData) => {
  const categories = [];
  if (moduleData && typeof moduleData === 'object') {
    if (moduleData.error) {
      categories.push('errors');
    }
    if (moduleData.vulnerabilities || moduleData.vulnerable_subdomains || moduleData.security_issues ||
      (Array.isArray(moduleData) && moduleData.some(v => v && v.severity))) {
      categories.push('vulnerabilities');
    }
  }
  if (categories.length === 0) categories.push('information');
  return categories;
};
