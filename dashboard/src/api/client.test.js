import { describe, it, expect, vi, afterEach } from 'vitest';
import { apiGet, apiPost, ApiError } from './client';

const jsonResponse = (body, { ok = true, status = 200 } = {}) => ({
  ok,
  status,
  headers: { get: () => 'application/json' },
  json: async () => body,
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('api client', () => {
  it('apiGet returns parsed JSON', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue(jsonResponse({ hello: 'world' }));
    await expect(apiGet('/api/x')).resolves.toEqual({ hello: 'world' });
  });

  it('throws ApiError with the status on a non-ok response', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue(jsonResponse(null, { ok: false, status: 404 }));
    await expect(apiGet('/api/missing')).rejects.toMatchObject({ name: 'ApiError', status: 404 });
  });

  it('apiPost sends a JSON body and content-type', async () => {
    const fetchMock = vi.fn().mockResolvedValue(jsonResponse({}));
    globalThis.fetch = fetchMock;
    await apiPost('/api/scan', { domain: 'example.com' });
    const [, opts] = fetchMock.mock.calls[0];
    expect(opts.method).toBe('POST');
    expect(opts.headers['Content-Type']).toBe('application/json');
    expect(JSON.parse(opts.body)).toEqual({ domain: 'example.com' });
  });

  it('wraps a network failure in ApiError', async () => {
    globalThis.fetch = vi.fn().mockRejectedValue(new TypeError('network down'));
    await expect(apiGet('/api/x')).rejects.toBeInstanceOf(ApiError);
  });

  it('returns text when the response is not JSON', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      headers: { get: () => 'text/plain' },
      text: async () => 'plain body',
    });
    await expect(apiGet('/api/x')).resolves.toBe('plain body');
  });
});
