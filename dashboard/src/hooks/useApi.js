/**
 * Reusable data-fetching hook built on the central API client.
 *
 * It owns an AbortController so the in-flight request is cancelled when the
 * component unmounts, preventing "state update on an unmounted component"
 * warnings and wasted network traffic.
 */
import { useEffect, useRef } from 'react';

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
