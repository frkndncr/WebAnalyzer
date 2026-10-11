/**
 * Reusable data-fetching hook built on the central API client.
 *
 * It owns an AbortController so the in-flight request is cancelled when the
 * component unmounts, preventing "state update on an unmounted component"
 * warnings and wasted network traffic.
 */
import { useEffect, useRef, useState } from 'react';
import { apiRequest } from '../api/client';

/**
 * Run `fn(signal)` immediately and then every `intervalMs`. The in-flight call
 * is aborted on unmount, and the latest `fn` is always used without restarting
 * the interval.
 *
 * @param {(signal: AbortSignal) => Promise<void>} fn
 * @param {number} intervalMs
 * @param {Array} [deps]  Restart the interval when these change.
 */
export function usePolling(fn, intervalMs, deps = []) {
  const savedFn = useRef(fn);

  // Keep the ref pointing at the latest callback without touching it during
  // render (react-compiler forbids mutating refs in the render phase).
  useEffect(() => {
    savedFn.current = fn;
  }, [fn]);

  useEffect(() => {
    let cancelled = false;
    let controller = new AbortController();

    const tick = async () => {
      controller = new AbortController();
      try {
        await savedFn.current(controller.signal);
      } catch (err) {
        if (!cancelled && err?.name !== 'AbortError') {
          console.warn('Polling request failed', err);
        }
      }
    };

    tick();
    const id = setInterval(tick, intervalMs);

    return () => {
      cancelled = true;
      clearInterval(id);
      controller.abort();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [intervalMs, ...deps]);
}

/**
 * Fetch `path` and keep polling every 3s while the response says a scan is
 * still running (`is_scanning === true`). Returns { data, loading, error }.
 * Pass a falsy path to stay idle. `reload()` fetches again (e.g. after a scan
 * has been started) and resumes polling.
 */
export function useResource(path) {
  const [nonce, setNonce] = useState(0);
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(Boolean(path));
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!path) return undefined;  // idle; initial state already reflects "no data"
    let stop = false;
    let timer;
    const controller = new AbortController();

    const tick = async (first) => {
      if (first) { setLoading(true); setError(null); }
      try {
        const d = await apiRequest(path, { signal: controller.signal });
        if (stop) return;
        setData(d);
        setError(null);
        setLoading(false);
        if (!d || d.is_scanning !== true) { stop = true; clearInterval(timer); }
      } catch (err) {
        if (controller.signal.aborted) return;
        setLoading(false);
        setData(null);
        setError(err);
        clearInterval(timer);
      }
    };

    tick(true);
    timer = setInterval(() => tick(false), 3000);
    return () => { stop = true; clearInterval(timer); controller.abort(); };
  }, [path, nonce]);

  return { data, loading, error, reload: () => setNonce((n) => n + 1) };
}
