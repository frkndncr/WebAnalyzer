/**
 * Dynamic API endpoint resolver for WebAnalyzer React Panel.
 * Resolves the backend host automatically based on the current hostname,
 * or falls back to VITE_API_URL if configured.
 */
export const getApiUrl = (path) => {
  const apiBase = import.meta.env.VITE_API_URL || `${window.location.protocol}//${window.location.hostname}:8000`;
  return `${apiBase}${path}`;
};
