/**
 * Citation integrity tool — reachability (spec-v8 §19, Step 139).
 *
 * The **network** half of the integrity check: confirm a citation URL
 * still resolves (HTTP 200/3xx) so a moved or 404'd source is caught.
 * This path touches the network and is therefore **scheduled/on-demand
 * only**, never per-commit (network is flaky — the same deferral v7 used
 * for Stryker). It is build/CI-only and never imported by `src/`.
 */

export type ReachVerdict = {
  url: string;
  ok: boolean;
  /** HTTP status, or 0 when the request failed before a response. */
  status: number;
  reason?: string;
};

export type FetchLike = (
  url: string,
  init: { method: string; redirect: "manual" | "follow"; signal: AbortSignal },
) => Promise<{ status: number }>;

/**
 * Probe a single URL with a bounded request. A timeout here is acceptable
 * (unlike the shipped engine) precisely because this is build-only tooling
 * — it never runs in the deterministic in-tab path, so the no-clock rule
 * does not apply.
 */
export async function checkReachable(
  url: string,
  opts: { fetchImpl?: FetchLike; timeoutMs?: number } = {},
): Promise<ReachVerdict> {
  const fetchImpl = (opts.fetchImpl ?? (globalThis.fetch as unknown as FetchLike)) as FetchLike;
  const timeoutMs = opts.timeoutMs ?? 10_000;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    // HEAD first (cheap); many static hosts answer it. Follow redirects so
    // a 301→200 chain counts as reachable.
    const res = await fetchImpl(url, {
      method: "HEAD",
      redirect: "follow",
      signal: controller.signal,
    });
    const ok = res.status >= 200 && res.status < 400;
    return { url, ok, status: res.status, reason: ok ? undefined : `HTTP ${res.status}` };
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    return { url, ok: false, status: 0, reason };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Probe many URLs with a small concurrency cap so a sweep is courteous to
 * the source hosts. Deterministic in *output order* (results map 1:1 to
 * the input order); request scheduling is concurrent.
 */
export async function checkAllReachable(
  urls: string[],
  opts: { fetchImpl?: FetchLike; timeoutMs?: number; concurrency?: number } = {},
): Promise<ReachVerdict[]> {
  const concurrency = opts.concurrency ?? 6;
  const results: ReachVerdict[] = new Array(urls.length);
  let next = 0;
  async function worker(): Promise<void> {
    while (next < urls.length) {
      const i = next++;
      results[i] = await checkReachable(urls[i]!, opts);
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, urls.length) }, () => worker()));
  return results;
}
