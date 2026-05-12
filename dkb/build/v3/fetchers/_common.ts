/**
 * v3 fetcher framework — shared helpers (spec-v3.md §§5–9 / Step 21–22).
 *
 * Each v3 fetcher is a pure function `(ctx) => V3FetcherResult`. The
 * input `ctx` carries a deterministic `nowIso`, an `HttpClient` for
 * live fetches, and a "source reader" that reads from vendored
 * snapshot fixtures when offline mode is on (the default for CI and
 * for tests). The output is a list of v3 DKB nodes — typically
 * `statutory_clause_requirement` or `regulator_model_form` — already
 * carrying `cites: PinnedCitation[]` so the Step-20 staleness gate
 * can validate them.
 *
 * Determinism: live fetches are conditionally bypassed when a
 * snapshot is present, and `content_hash_at_pin` is recomputed each
 * build from the normalized snapshot text. The Step-20 gate compares
 * the recomputed hash against the pinned hash and surfaces drift.
 */

import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

import type { PinnedCitation, V3DkbNode } from "../../../../src/dkb/v3/types.js";
import type { HttpClient } from "../../types.js";
import { normalizeForHash, sha256Hex } from "../staleness.js";

export type V3SourceId = string;

export type V3SourceReader = {
  /** Read the snapshot text for a URL from disk (offline). Throws if absent in strict mode. */
  read(url: string): string | undefined;
};

export type V3FetchContext = {
  source_id: V3SourceId;
  nowIso: string;
  /** Optional live HTTP client. When omitted, fetchers must use the reader only. */
  http?: HttpClient;
  reader: V3SourceReader;
  /** Repo-root absolute path so fetchers can reference vendored documents. */
  repoRoot: string;
};

export type V3FetcherResult = {
  source_id: V3SourceId;
  nodes: V3DkbNode[];
};

export type V3Fetcher = (ctx: V3FetchContext) => Promise<V3FetcherResult>;

export const urlKey = (url: string): string => createHash("sha256").update(url).digest("hex");

/**
 * Filesystem-backed snapshot reader. Resolves
 * `dkb/fixtures/v3/snapshots/{sha256(url)}.txt` from `repoRoot`.
 */
export function createFsReader(repoRoot: string): V3SourceReader {
  const dir = join(repoRoot, "dkb", "fixtures", "v3", "snapshots");
  return {
    read(url: string): string | undefined {
      const path = join(dir, `${urlKey(url)}.txt`);
      return existsSync(path) ? readFileSync(path, "utf8") : undefined;
    },
  };
}

export type PinOptions = {
  authority: string;
  citation: string;
  source_url: string;
  fetched_at: string;
  /** Pre-normalized text to hash. */
  text: string;
};

export function pin({ authority, citation, source_url, fetched_at, text }: PinOptions): PinnedCitation {
  return {
    authority,
    citation,
    source_url,
    content_hash_at_pin: sha256Hex(text),
    fetched_at,
  };
}

export { normalizeForHash, sha256Hex };
