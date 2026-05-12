#!/usr/bin/env tsx
/**
 * Top-level DKB build orchestrator (spec §15, build step 11).
 *
 * Pipeline:
 *   1. Read `sources.yaml`
 *   2. Run every fetcher (with cache)
 *   3. Reconcile taxonomies + train classifier vocab
 *   4. Load hand-authored classifier patterns
 *   5. Assemble candidate DKB artifacts
 *   6. Validate every artifact against its Zod schema
 *   7. Compute file SHA-256 hashes + write manifest
 *   8. Write to `dkb/dist/{version}/`
 *   9. Optionally run the regression check against
 *      `tests/fixtures/contracts/` (Step 16 fixtures)
 *
 * Determinism: a fixed `nowIso` is threaded through every fetcher so
 * re-runs from cache produce byte-identical artifacts.
 *
 * The script supports `--dry-run` to skip the disk write (used by the
 * GitHub Action when running the regression check on PRs).
 */

import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import type {
  ClassifierPatternEntry,
  ClassifierVocabEntry,
  ClauseLibraryEntry,
  DkbManifest,
  SourceCitation,
  StatutoryIndexEntry,
} from "../../src/dkb/types.js";
import {
  ClassifierPatternSchema,
  ClassifierVocabSchema,
  ClauseLibrarySchema,
  DkbManifestSchema,
  StatutorySchema,
} from "../../src/dkb/schema.js";
import { FETCHERS } from "./fetchers/index.js";
import { FilesystemCache, defaultCacheRoot } from "./cache.js";
import { RateLimitedHttp } from "./http.js";
import { loadSourcesYaml } from "./sources.js";
import {
  buildAliasMap,
  loadStopwords,
  loadTaxonomy,
  trainTfIdf,
  reconcileCategory,
  type ClassifierExample,
} from "./classifiers/index.js";
import { PATTERNS } from "./classifiers/patterns.js";
import type { ParsedRecord } from "./types.js";

export type BuildOptions = {
  /** Output root. Defaults to `dkb/dist/`. */
  out_root?: string;
  /** Override the version. Defaults to `v{YYYY-MM-DD}-{shortCommit}` or `v{YYYY-MM-DD}-local`. */
  version?: string;
  /** When true, skip the disk write — useful for PR regression checks. */
  dry_run?: boolean;
  /** Deterministic clock. Defaults to `new Date().toISOString()`. */
  now_iso?: string;
  /** Optional explicit commit hash. */
  commit_hash?: string;
};

export type BuildResult = {
  version: string;
  manifest: DkbManifest;
  vocab: ClassifierVocabEntry[];
  patterns: ClassifierPatternEntry[];
  clauses: ClauseLibraryEntry[];
  statutes: StatutoryIndexEntry[];
};

export async function runBuild(opts: BuildOptions = {}): Promise<BuildResult> {
  const nowIso = opts.now_iso ?? new Date().toISOString();
  const version = opts.version ?? defaultVersion(nowIso, opts.commit_hash);

  const sources = await loadSourcesYaml();
  const stopwords = await loadStopwords();
  const taxonomy = await loadTaxonomy();
  const aliasMap = buildAliasMap(taxonomy);

  // --- 2. Fetch every source ---
  const allRecords: ParsedRecord[] = [];
  for (const source of sources.sources) {
    const http = new RateLimitedHttp({
      rate_limit_rps: source.rate_limit_rps,
      user_agent: source.user_agent,
    });
    const cache = new FilesystemCache(defaultCacheRoot());
    const fetcher = FETCHERS[source.parser];
    try {
      const result = await fetcher({ source, http, cache, nowIso });
      allRecords.push(...result.records);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      process.stderr.write(`warn: fetcher ${source.id} failed: ${msg}\n`);
    }
  }

  // --- 3. Train classifier vocab ---
  const examples: ClassifierExample[] = allRecords
    .filter((r) => r.kind === "classifier-example")
    .map((r) => ({
      category: reconcileCategory((r.data as { category: string }).category, aliasMap),
      text: (r.data as { text: string }).text,
    }));
  const vocab = trainTfIdf(examples, { stopwords });

  // --- 4. Patterns ---
  const patterns: ClassifierPatternEntry[] = [...PATTERNS];

  // --- 5. Assemble clause library + statutes from typed records ---
  const clauses: ClauseLibraryEntry[] = allRecords
    .filter((r) => r.kind === "clause")
    .map((r) => {
      const c = r.data as {
        id: string;
        category: string;
        text: string;
        position: "restrictive" | "balanced" | "permissive";
        deal_types: string[];
        source: SourceCitation;
      };
      return {
        id: c.id,
        version: "1.0.0",
        category: reconcileCategory(c.category, aliasMap),
        position: c.position,
        normalized_text: c.text,
        deal_types: c.deal_types,
        side: "neutral",
        source: c.source,
      };
    });

  const statutes: StatutoryIndexEntry[] = allRecords
    .filter((r) => r.kind === "statute")
    .map((r) => r.data as StatutoryIndexEntry);

  // --- 6. Validate ---
  ClassifierVocabSchema.parse(vocab);
  ClassifierPatternSchema.parse(patterns);
  ClauseLibrarySchema.parse(clauses);
  StatutorySchema.parse(statutes);

  // --- 7. Manifest ---
  const files = {
    clauses: makeFileRef("dkb-clauses.json", clauses),
    jurisdictions: makeFileRef("dkb-jurisdictions.json", []), // hand-authored in starter; build pass-through
    definitions: makeFileRef("dkb-definitions.json", []),
    dark_patterns: makeFileRef("dkb-dark-patterns.json", []),
    statutes: makeFileRef("dkb-statutes.json", statutes),
    classifier_vocab: makeFileRef("dkb-classifier-vocab.json", vocab),
    classifier_patterns: makeFileRef("dkb-classifier-patterns.json", patterns),
  };

  const manifestSources = collectSourceCitations(allRecords);
  const manifest: DkbManifest = {
    version,
    schema_version: "1.0.0",
    built_at: nowIso,
    files,
    sources: manifestSources,
  };

  DkbManifestSchema.parse(manifest);

  // --- 8. Write artifacts ---
  if (!opts.dry_run) {
    const outRoot = opts.out_root ?? join(process.cwd(), "dkb", "dist");
    const outDir = join(outRoot, version);
    await mkdir(outDir, { recursive: true });
    await writeJsonFile(join(outDir, "dkb-manifest.json"), manifest);
    await writeJsonFile(join(outDir, "dkb-clauses.json"), clauses);
    await writeJsonFile(join(outDir, "dkb-statutes.json"), statutes);
    await writeJsonFile(join(outDir, "dkb-classifier-vocab.json"), vocab);
    await writeJsonFile(join(outDir, "dkb-classifier-patterns.json"), patterns);
    // Hand-authored files (jurisdictions/definitions/dark_patterns) pass
    // through from the starter directory if present, so the orchestrator
    // never silently overwrites curated content with empties.
    await passThroughStarter(outDir);
  }

  return { version, manifest, vocab, patterns, clauses, statutes };
}

// ---------------------------------------------------------------------------

function defaultVersion(nowIso: string, commit?: string): string {
  const date = nowIso.slice(0, 10);
  const sha = commit?.slice(0, 7) ?? "local";
  return `v${date}-${sha}`;
}

function makeFileRef(filename: string, contents: unknown[]) {
  const json = stableJson(contents);
  return {
    filename,
    sha256: sha256Hex(json),
    entries: contents.length,
  };
}

function stableJson(value: unknown): string {
  return JSON.stringify(value, sortedReplacer(new WeakSet()), 2);
}

function sortedReplacer(seen: WeakSet<object>): (key: string, value: unknown) => unknown {
  return (_key, value) => {
    if (value && typeof value === "object" && !Array.isArray(value)) {
      const obj = value as Record<string, unknown>;
      if (seen.has(obj)) return undefined;
      seen.add(obj);
      const out: Record<string, unknown> = {};
      for (const k of Object.keys(obj).sort()) out[k] = obj[k];
      return out;
    }
    return value;
  };
}

function sha256Hex(s: string): string {
  return createHash("sha256").update(s).digest("hex");
}

function collectSourceCitations(records: ParsedRecord[]): SourceCitation[] {
  const seen = new Map<string, SourceCitation>();
  for (const r of records) {
    if (r.kind !== "clause") continue;
    const c = r.data as { source: SourceCitation };
    if (!seen.has(c.source.id)) seen.set(c.source.id, c.source);
  }
  return [...seen.values()].sort((a, b) => a.id.localeCompare(b.id));
}

async function writeJsonFile(path: string, value: unknown): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, stableJson(value));
}

async function passThroughStarter(outDir: string): Promise<void> {
  const starter = join(process.cwd(), "dkb", "dist", "v0.0.1-starter");
  if (!existsSync(starter)) return;
  for (const name of ["dkb-jurisdictions.json", "dkb-definitions.json", "dkb-dark-patterns.json"]) {
    const src = join(starter, name);
    const dst = join(outDir, name);
    if (!existsSync(src) || existsSync(dst)) continue;
    const buf = await readFile(src);
    await writeFile(dst, buf);
  }
}

// ---------------------------------------------------------------------------
// CLI entry point. `npm run dkb:build` executes this with no args.

const isMain = import.meta.url === `file://${process.argv[1]}`;
if (isMain) {
  void runBuild({
    dry_run: process.argv.includes("--dry-run"),
  })
    .then((r) => {
      process.stdout.write(
        `dkb built: version=${r.version} clauses=${r.clauses.length} statutes=${r.statutes.length} vocab_categories=${r.vocab.length} patterns=${r.patterns.length}\n`,
      );
    })
    .catch((err) => {
      process.stderr.write(`${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
      process.exit(1);
    });
}
