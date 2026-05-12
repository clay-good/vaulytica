#!/usr/bin/env tsx
/**
 * CLI entry point for individual fetchers.
 *
 *   npm run dkb:fetch -- commonpaper
 *
 * Reads `sources.yaml`, finds the requested source by id, builds a
 * RateLimitedHttp client + FilesystemCache for it, and runs the
 * matching fetcher. Writes the result envelope to
 * `dkb/build/cache/{source_id}/result.json` for inspection.
 *
 * The CLI is the substrate the Step 11 orchestrator builds on; it is
 * also the path the spec calls out (`pnpm tsx
 * dkb/build/fetchers/commonpaper.ts`) for ad-hoc development.
 */

import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { loadSourcesYaml } from "./sources.js";
import { FilesystemCache, defaultCacheRoot } from "./cache.js";
import { RateLimitedHttp } from "./http.js";
import { FETCHERS } from "./fetchers/index.js";

async function main(): Promise<void> {
  const sourceId = process.argv[2];
  if (!sourceId) {
    process.stderr.write("usage: tsx dkb/build/run-fetcher.ts <source-id>\n");
    process.exit(2);
  }
  const file = await loadSourcesYaml();
  const source = file.sources.find((s) => s.id === sourceId);
  if (!source) {
    process.stderr.write(`unknown source: ${sourceId}\n`);
    process.exit(2);
  }
  const http = new RateLimitedHttp({
    rate_limit_rps: source.rate_limit_rps,
    user_agent: source.user_agent,
  });
  const cache = new FilesystemCache(defaultCacheRoot());
  const fetcher = FETCHERS[source.parser];
  const result = await fetcher({
    source,
    http,
    cache,
    nowIso: new Date().toISOString(),
  });
  const outDir = join(defaultCacheRoot(), source.id);
  await mkdir(outDir, { recursive: true });
  await writeFile(join(outDir, "result.json"), JSON.stringify(result, null, 2));
  process.stdout.write(
    `${source.id}: ${result.records.length} records, ${result.bytes_fetched} bytes fetched\n`,
  );
}

void main().catch((err) => {
  process.stderr.write(`${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
  process.exit(1);
});
