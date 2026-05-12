/**
 * Rate-limited, retrying HTTP client used by every DKB fetcher.
 *
 * - One client instance per source, configured with that source's
 *   `rate_limit_rps`. The client serializes outgoing requests through
 *   a token-bucket style delay so EDGAR's 10-RPS rule is respected
 *   even if a single fetcher does thousands of requests.
 * - Exponential backoff on 5xx and network errors. 4xx is returned
 *   without retry — bad URLs are a config error, not a transient.
 * - Every request carries the source-declared User-Agent. EDGAR
 *   rejects unidentified clients; this is enforced at the type level
 *   by requiring the UA at construction.
 *
 * The cache is consulted by the *fetcher*, not the client: clients
 * are dumb network pumps. Fetchers read from the cache first and only
 * fall through to {@link RateLimitedHttp} on a miss.
 */

import type { HttpClient } from "./types.js";

export type RateLimitedHttpOptions = {
  rate_limit_rps: number;
  user_agent: string;
  /** Pluggable fetch — tests inject a fake. Defaults to global `fetch`. */
  fetchImpl?: typeof fetch;
  /** Sleeper — tests inject a no-op. Defaults to setTimeout-based delay. */
  sleep?: (ms: number) => Promise<void>;
  /** Retry attempts on 5xx/network. */
  max_retries?: number;
};

const DEFAULT_RETRIES = 4;

export class RateLimitedHttp implements HttpClient {
  private readonly minSpacingMs: number;
  private readonly fetchImpl: typeof fetch;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly maxRetries: number;
  private nextEarliestMs = 0;

  constructor(private readonly opts: RateLimitedHttpOptions) {
    this.minSpacingMs = Math.max(1, Math.ceil(1000 / opts.rate_limit_rps));
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.sleep = opts.sleep ?? defaultSleep;
    this.maxRetries = opts.max_retries ?? DEFAULT_RETRIES;
  }

  async getBytes(url: string, init?: { headers?: Record<string, string> }): Promise<Uint8Array> {
    const headers: Record<string, string> = {
      "User-Agent": this.opts.user_agent,
      ...(init?.headers ?? {}),
    };

    let attempt = 0;
    let lastError: unknown;
    while (attempt <= this.maxRetries) {
      await this.throttle();
      let res: Response;
      try {
        res = await this.fetchImpl(url, { headers });
      } catch (err) {
        // Network-level error (DNS, abort, TLS). Retry.
        lastError = err;
        attempt++;
        if (attempt > this.maxRetries) break;
        await this.backoff(attempt);
        continue;
      }
      if (res.status >= 500) {
        attempt++;
        lastError = new Error(`HTTP ${res.status} ${res.statusText} for ${url}`);
        if (attempt > this.maxRetries) break;
        await this.backoff(attempt);
        continue;
      }
      if (!res.ok) {
        // 4xx — bad URL / auth / etc. Don't retry.
        throw new Error(`HTTP ${res.status} ${res.statusText} for ${url}`);
      }
      return new Uint8Array(await res.arrayBuffer());
    }
    throw lastError instanceof Error
      ? lastError
      : new Error(`fetch failed for ${url} after ${this.maxRetries + 1} attempts`);
  }

  async getText(url: string, init?: { headers?: Record<string, string> }): Promise<string> {
    const bytes = await this.getBytes(url, init);
    return new TextDecoder().decode(bytes);
  }

  async getJson<T = unknown>(url: string, init?: { headers?: Record<string, string> }): Promise<T> {
    return JSON.parse(await this.getText(url, init)) as T;
  }

  private async throttle(): Promise<void> {
    const now = Date.now();
    const wait = this.nextEarliestMs - now;
    if (wait > 0) await this.sleep(wait);
    this.nextEarliestMs = Math.max(now, this.nextEarliestMs) + this.minSpacingMs;
  }

  private async backoff(attempt: number): Promise<void> {
    // 250ms, 500ms, 1s, 2s, 4s. Deterministic; no jitter — the cache
    // means a retry storm is bounded and the GitHub Action timeout
    // backstops anything else.
    const delay = 250 * 2 ** (attempt - 1);
    await this.sleep(delay);
  }
}

function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
