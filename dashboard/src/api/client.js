/**
 * Central API client for the WebAnalyzer dashboard.
 *
 * Every component used to inline its own `fetch(getApiUrl(...))` call with
 * ad-hoc error handling and no request cancellation. This module centralises
 * base-URL resolution, JSON parsing, timeouts and error typing so call sites
 * become a single line and can pass an AbortController signal for clean
 * cancellation on unmount.
 */
import { getApiUrl } from '../config';

/** Error thrown for any non-ok HTTP response or network/timeout failure. */
export class ApiError extends Error {
  constructor(message, { status = null, url = null, cause = null } = {}) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.url = url;
    this.cause = cause;
  }
}

const DEFAULT_TIMEOUT_MS = 30000;

/**
 * Combine an optional caller signal with an internal timeout so a request is
 * aborted either when the caller unmounts or when the timeout elapses.
 */
function buildSignal(externalSignal, timeoutMs) {
  const controller = new AbortController();
  const timer = timeoutMs
    ? setTimeout(() => controller.abort(new ApiError('Request timed out', {})), timeoutMs)
    : null;

  if (externalSignal) {
    if (externalSignal.aborted) {
      controller.abort(externalSignal.reason);
    } else {
      externalSignal.addEventListener('abort', () => controller.abort(externalSignal.reason), { once: true });
    }
  }

  return { signal: controller.signal, cleanup: () => timer && clearTimeout(timer) };
}

/**
 * Perform a request against the backend.
 * @param {string} path  API path beginning with '/', e.g. '/api/stats'.
 * @param {object} [options]
 * @param {string} [options.method='GET']
 * @param {*}      [options.body]     Object (JSON-encoded) or string.
 * @param {object} [options.headers]
 * @param {AbortSignal} [options.signal]
 * @param {number} [options.timeout=30000]  Milliseconds; pass 0 to disable.
 * @returns {Promise<*>} Parsed JSON, or text when the response is not JSON.
 */
export async function apiRequest(path, { method = 'GET', body, headers, signal, timeout = DEFAULT_TIMEOUT_MS, ...rest } = {}) {
  const url = getApiUrl(path);
  const { signal: combinedSignal, cleanup } = buildSignal(signal, timeout);

  const options = {
    method,
    signal: combinedSignal,
    headers: { ...(body != null ? { 'Content-Type': 'application/json' } : {}), ...headers },
    ...rest,
  };
  if (body != null) {
    options.body = typeof body === 'string' ? body : JSON.stringify(body);
  }

  let response;
  try {
    response = await fetch(url, options);
  } catch (err) {
    // Propagate cancellation untouched so callers can ignore it silently.
    if (err?.name === 'AbortError' || err instanceof ApiError) throw err;
    throw new ApiError(`Network error while requesting ${path}`, { url, cause: err });
  } finally {
    cleanup();
  }

  if (!response.ok) {
    throw new ApiError(`Request to ${path} failed (${response.status})`, { status: response.status, url });
  }

  const contentType = response.headers.get('content-type') || '';
  return contentType.includes('application/json') ? response.json() : response.text();
}

/** Convenience helper for GET requests. */
export const apiGet = (path, options) => apiRequest(path, { ...options, method: 'GET' });

/** Convenience helper for POST requests with a JSON body. */
export const apiPost = (path, body, options) => apiRequest(path, { ...options, method: 'POST', body });
