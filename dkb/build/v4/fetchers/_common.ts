/**
 * v4 fetcher framework — shared helpers (spec-v4.md §13 / Step 60).
 *
 * v4 reuses the v3 DKB schema (spec-v4.md §12), so each v4 fetcher is
 * still a pure function `(ctx) => V4FetcherResult` emitting `V3DkbNode`
 * values. The only thing v4-specific is the snapshots directory:
 * `dkb/fixtures/v4/snapshots/{sha256(source_url)}.txt`. The Step-20
 * staleness gate then runs unchanged on v4 nodes.
 */

import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

import type { HttpClient } from "../../types.js";
import { normalizeForHash, sha256Hex } from "../../v3/staleness.js";
import {
  pin,
  type V3FetchContext,
  type V3Fetcher,
  type V3FetcherResult,
  type V3SourceReader,
} from "../../v3/fetchers/_common.js";

export type V4SourceId = string;
export type V4SourceReader = V3SourceReader;
export type V4FetchContext = V3FetchContext;
export type V4Fetcher = V3Fetcher;
export type V4FetcherResult = V3FetcherResult;

export const urlKey = (url: string): string =>
  createHash("sha256").update(url).digest("hex");

/**
 * Filesystem-backed snapshot reader. Resolves
 * `dkb/fixtures/v4/snapshots/{sha256(url)}.txt` from `repoRoot`.
 */
export function createV4FsReader(repoRoot: string): V4SourceReader {
  const dir = join(repoRoot, "dkb", "fixtures", "v4", "snapshots");
  return {
    read(url: string): string | undefined {
      const path = join(dir, `${urlKey(url)}.txt`);
      return existsSync(path) ? readFileSync(path, "utf8") : undefined;
    },
  };
}

export { pin, normalizeForHash, sha256Hex };
export type { HttpClient };
