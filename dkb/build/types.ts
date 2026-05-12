/**
 * Shared types for the DKB build pipeline (spec §15, build step 10).
 *
 * Each source declared in `dkb/build/sources.yaml` is dispatched to a
 * named fetcher under `dkb/build/fetchers/`. A fetcher is a pure
 * function from a {@link FetchContext} (HTTP client + cache + dated
 * "now") to a {@link FetcherResult} of typed DKB records.
 *
 * Determinism: fetchers must produce identical records on identical
 * cached responses. Network IO is therefore separated from parsing —
 * the parser path is pure and tested with fixture strings; the
 * fetcher merely orchestrates the HTTP calls.
 */

import type { SourceCitation } from "../../src/dkb/types.js";

export type FetchMethod = "http" | "github-clone" | "huggingface-download";

export type ParserId =
  | "edgar"
  | "uscode"
  | "ecfr"
  | "govinfo"
  | "commonpaper"
  | "cuad"
  | "ledgar"
  | "ulc";

export type SourceDeclaration = {
  id: string;
  name: string;
  url: string;
  fetch_method: FetchMethod;
  parser: ParserId;
  license: string;
  license_url: string;
  rate_limit_rps: number;
  user_agent: string;
  notes?: string;
};

export type SourcesFile = {
  sources: SourceDeclaration[];
};

export type FetcherResult = {
  source_id: string;
  retrieved_at: string;
  /** Raw bytes fetched, count only — for logging / regression. */
  bytes_fetched: number;
  /** Records the fetcher produced after parsing. Shape depends on parser. */
  records: ParsedRecord[];
  /** Optional shared citation prototype to copy into each emitted record. */
  citation_prototype?: SourceCitation;
};

/**
 * Discriminated union covering every record shape a fetcher can emit.
 * The build orchestrator routes each variant to the matching DKB
 * collection (clauses, statutes, jurisdictions, classifier corpus,
 * etc.).
 */
export type ParsedRecord =
  | { kind: "clause"; data: ClauseRecord }
  | { kind: "statute"; data: StatuteRecord }
  | { kind: "classifier-example"; data: ClassifierExample };

export type ClauseRecord = {
  id: string;
  category: string;
  text: string;
  position: "restrictive" | "balanced" | "permissive";
  deal_types: string[];
  source: SourceCitation;
};

export type StatuteRecord = {
  id: string;
  citation: string;
  canonical_url: string;
  jurisdiction: string;
  excerpt: string;
  retrieved_at: string;
};

export type ClassifierExample = {
  /** Stable id derived from corpus + record offset. */
  id: string;
  category: string;
  text: string;
};

export interface Cache {
  /** Return the cached payload for a key, or undefined if not cached. */
  get(key: string): Promise<Uint8Array | undefined>;
  /** Store the payload under a key. */
  set(key: string, value: Uint8Array): Promise<void>;
  /** Compute the deterministic cache key for a URL + optional namespace. */
  keyFor(sourceId: string, url: string): string;
}

export interface HttpClient {
  /** Issue a GET, respecting the per-instance rate limit. Bytes returned raw. */
  getBytes(url: string, init?: { headers?: Record<string, string> }): Promise<Uint8Array>;
  /** Convenience wrapper that decodes the body as UTF-8 text. */
  getText(url: string, init?: { headers?: Record<string, string> }): Promise<string>;
  /** Convenience wrapper that parses the body as JSON. */
  getJson<T = unknown>(url: string, init?: { headers?: Record<string, string> }): Promise<T>;
}

export interface FetchContext {
  source: SourceDeclaration;
  http: HttpClient;
  cache: Cache;
  /**
   * Deterministic clock. The pipeline injects an ISO-8601 string so
   * `retrieved_at` values reproduce across re-runs of the same build.
   */
  nowIso: string;
}

/** Fetcher contract: `(ctx) => FetcherResult`. Must be referentially transparent given the cache. */
export type Fetcher = (ctx: FetchContext) => Promise<FetcherResult>;
