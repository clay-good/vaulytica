#!/usr/bin/env tsx
/**
 * Top-level DKB build orchestrator (spec §15, build step 11).
 *
 * Pipeline:
 *   1. Read `sources.yaml`
 *   2. Run every fetcher (with cache) — skipped under `--offline`
 *   3. Reconcile taxonomies + train classifier vocab
 *   4. Load hand-authored classifier patterns
 *   5. Load the curated content baseline (`dkb/dist/v0.0.1-starter`)
 *      and merge fetched records into it by id
 *   6. Validate every artifact against its Zod schema
 *   7. Integrity gates: refuse empty content sections; refuse
 *      unacknowledged shrinkage vs. the previous released version
 *      (`dkb-shrinkage-ack.yml` carries the acknowledgments)
 *   8. Compute file SHA-256 hashes + write manifest — every manifest
 *      ref is computed from the exact content written to disk
 *   9. Write to `dkb/dist/{version}/`
 *
 * Determinism: a fixed `nowIso` is threaded through every fetcher so
 * re-runs from cache produce byte-identical artifacts.
 *
 * The script supports `--dry-run` to skip the disk write (used by the
 * GitHub Action when running the regression check on PRs) and
 * `--offline` to skip the network fetch stage and build from the
 * repo's curated sources alone.
 */

import { createHash } from "node:crypto";
import { existsSync, readdirSync, statSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import * as YAML from "js-yaml";
import { z } from "zod";
import type {
  ClassifierPatternEntry,
  ClassifierVocabEntry,
  ClauseLibraryEntry,
  DarkPatternEntry,
  DefinitionTemplate,
  DkbManifest,
  DkbShrinkageAck,
  JurisdictionRecord,
  SourceCitation,
  StatutoryIndexEntry,
} from "../../src/dkb/types.js";
import {
  ClassifierPatternSchema,
  ClassifierVocabSchema,
  ClauseLibrarySchema,
  DarkPatternSchema,
  DefinitionTemplateSchema,
  DkbManifestSchema,
  JurisdictionSchema,
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
  /**
   * When provided, the network fetch stage is skipped and these records
   * are used verbatim. `--offline` passes `[]`; tests inject fixtures.
   */
  records?: ParsedRecord[];
  /**
   * Hand-authored content baseline merged into every build. Defaults to
   * `dkb/dist/v0.0.1-starter/`.
   */
  curated_root?: string;
  /** Shrinkage acknowledgment file. Defaults to `dkb-shrinkage-ack.yml`. */
  ack_path?: string;
};

export type BuildResult = {
  version: string;
  manifest: DkbManifest;
  vocab: ClassifierVocabEntry[];
  patterns: ClassifierPatternEntry[];
  clauses: ClauseLibraryEntry[];
  statutes: StatutoryIndexEntry[];
  jurisdictions: JurisdictionRecord[];
  definitions: DefinitionTemplate[];
  dark_patterns: DarkPatternEntry[];
};

/** Manifest `files` keys whose entries are legal knowledge (not classifier artifacts). */
export const CONTENT_SECTIONS = [
  "clauses",
  "jurisdictions",
  "definitions",
  "dark_patterns",
  "statutes",
] as const;

export async function runBuild(opts: BuildOptions = {}): Promise<BuildResult> {
  const nowIso = opts.now_iso ?? new Date().toISOString();
  const version = opts.version ?? defaultVersion(nowIso, opts.commit_hash);

  const stopwords = await loadStopwords();
  const taxonomy = await loadTaxonomy();
  const aliasMap = buildAliasMap(taxonomy);

  // --- 2. Fetch every source (unless records are injected) ---
  let allRecords: ParsedRecord[];
  if (opts.records) {
    allRecords = opts.records;
  } else {
    allRecords = [];
    const sources = await loadSourcesYaml();
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
  }

  // --- 3. Train classifier vocab ---
  const examples: ClassifierExample[] = allRecords
    .filter((r) => r.kind === "classifier-example")
    .map((r) => ({
      category: reconcileCategory((r.data as { category: string }).category, aliasMap),
      text: (r.data as { text: string }).text,
    }));
  let vocab = trainTfIdf(examples, { stopwords });

  // --- 4. Patterns ---
  const patterns: ClassifierPatternEntry[] = [...PATTERNS];

  // --- 5. Curated baseline + fetched records, merged by id ---
  const curatedRoot = opts.curated_root ?? join(process.cwd(), "dkb", "dist", "v0.0.1-starter");
  const curated = await loadCurated(curatedRoot);

  const fetchedClauses: ClauseLibraryEntry[] = allRecords
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

  const fetchedStatutes: StatutoryIndexEntry[] = allRecords
    .filter((r) => r.kind === "statute")
    .map((r) => r.data as StatutoryIndexEntry);

  const clauses = mergeById(curated.clauses, fetchedClauses);
  const statutes = mergeById(curated.statutes, fetchedStatutes);
  const jurisdictions = curated.jurisdictions;
  const definitions = curated.definitions;
  const dark_patterns = curated.dark_patterns;

  // When the fetch stage produced no classifier examples, carry the
  // previous released version's trained vocab forward instead of
  // silently shipping an untrained classifier.
  const outRoot = opts.out_root ?? join(process.cwd(), "dkb", "dist");
  const priorDir = findPriorVersionDir(outRoot, version);
  if (vocab.length === 0 && priorDir) {
    const priorVocabPath = join(priorDir, "dkb-classifier-vocab.json");
    if (existsSync(priorVocabPath)) {
      vocab = ClassifierVocabSchema.parse(JSON.parse(await readFile(priorVocabPath, "utf8")));
    }
  }

  // --- 6. Validate ---
  ClassifierVocabSchema.parse(vocab);
  ClassifierPatternSchema.parse(patterns);
  ClauseLibrarySchema.parse(clauses);
  StatutorySchema.parse(statutes);
  JurisdictionSchema.parse(jurisdictions);
  DefinitionTemplateSchema.parse(definitions);
  DarkPatternSchema.parse(dark_patterns);

  // --- 7. Integrity gates (before any disk write) ---
  const contents = {
    clauses,
    jurisdictions,
    definitions,
    dark_patterns,
    statutes,
    classifier_vocab: vocab,
    classifier_patterns: patterns,
  };

  const emptySections = CONTENT_SECTIONS.filter((s) => contents[s].length === 0);
  if (emptySections.length > 0) {
    throw new Error(
      `dkb build: refusing to write ${version}: empty content section(s): ` +
        `${emptySections.join(", ")} — a DKB with no knowledge must not ship`,
    );
  }

  const shrinkageAcks = await checkShrinkage({
    priorDir,
    contents,
    ackPath: opts.ack_path ?? join(process.cwd(), "dkb-shrinkage-ack.yml"),
    version,
  });

  // --- Manifest: every ref is computed from the content written below ---
  const files = {
    clauses: makeFileRef("dkb-clauses.json", clauses),
    jurisdictions: makeFileRef("dkb-jurisdictions.json", jurisdictions),
    definitions: makeFileRef("dkb-definitions.json", definitions),
    dark_patterns: makeFileRef("dkb-dark-patterns.json", dark_patterns),
    statutes: makeFileRef("dkb-statutes.json", statutes),
    classifier_vocab: makeFileRef("dkb-classifier-vocab.json", vocab),
    classifier_patterns: makeFileRef("dkb-classifier-patterns.json", patterns),
  };

  const manifestSources = mergeSourceCitations(curated.sources, collectSourceCitations(allRecords));
  const manifest: DkbManifest = {
    version,
    schema_version: "1.0.0",
    built_at: nowIso,
    files,
    sources: manifestSources,
    ...(shrinkageAcks.length > 0 ? { shrinkage_acknowledgments: shrinkageAcks } : {}),
  };

  DkbManifestSchema.parse(manifest);

  // --- 8. Write artifacts ---
  if (!opts.dry_run) {
    const outDir = join(outRoot, version);
    await mkdir(outDir, { recursive: true });
    await writeJsonFile(join(outDir, "dkb-manifest.json"), manifest);
    await writeJsonFile(join(outDir, "dkb-clauses.json"), clauses);
    await writeJsonFile(join(outDir, "dkb-jurisdictions.json"), jurisdictions);
    await writeJsonFile(join(outDir, "dkb-definitions.json"), definitions);
    await writeJsonFile(join(outDir, "dkb-dark-patterns.json"), dark_patterns);
    await writeJsonFile(join(outDir, "dkb-statutes.json"), statutes);
    await writeJsonFile(join(outDir, "dkb-classifier-vocab.json"), vocab);
    await writeJsonFile(join(outDir, "dkb-classifier-patterns.json"), patterns);
  }

  return {
    version,
    manifest,
    vocab,
    patterns,
    clauses,
    statutes,
    jurisdictions,
    definitions,
    dark_patterns,
  };
}

// ---------------------------------------------------------------------------

type CuratedContent = {
  clauses: ClauseLibraryEntry[];
  jurisdictions: JurisdictionRecord[];
  definitions: DefinitionTemplate[];
  dark_patterns: DarkPatternEntry[];
  statutes: StatutoryIndexEntry[];
  sources: SourceCitation[];
};

/**
 * Load the hand-authored content baseline. Missing files load as empty
 * (and then fail the empty-section gate unless fetched records fill
 * the section) so a mispointed root cannot silently ship empties.
 */
async function loadCurated(root: string): Promise<CuratedContent> {
  const readArray = async <T>(name: string, parse: (v: unknown) => T[]): Promise<T[]> => {
    const path = join(root, name);
    if (!existsSync(path)) return [];
    return parse(JSON.parse(await readFile(path, "utf8")));
  };

  let sources: SourceCitation[] = [];
  const manifestPath = join(root, "dkb-manifest.json");
  if (existsSync(manifestPath)) {
    const manifest = DkbManifestSchema.parse(JSON.parse(await readFile(manifestPath, "utf8")));
    sources = manifest.sources;
  }

  return {
    clauses: await readArray("dkb-clauses.json", (v) => ClauseLibrarySchema.parse(v)),
    jurisdictions: await readArray("dkb-jurisdictions.json", (v) => JurisdictionSchema.parse(v)),
    definitions: await readArray("dkb-definitions.json", (v) => DefinitionTemplateSchema.parse(v)),
    dark_patterns: await readArray("dkb-dark-patterns.json", (v) => DarkPatternSchema.parse(v)),
    statutes: await readArray("dkb-statutes.json", (v) => StatutorySchema.parse(v)),
    sources,
  };
}

/** Curated entries first (stable order), then fetched entries with new ids, sorted by id. */
function mergeById<T extends { id: string }>(base: T[], extra: T[]): T[] {
  const seen = new Set(base.map((e) => e.id));
  const added = extra
    .filter((e) => {
      if (seen.has(e.id)) return false;
      seen.add(e.id);
      return true;
    })
    .sort((a, b) => a.id.localeCompare(b.id));
  return [...base, ...added];
}

/**
 * The most recent version directory in `outRoot` other than the one
 * being built — the shrinkage baseline. Sorted the same way
 * `pickLatestDkb` (vite.config.ts) resolves the artifact to ship.
 */
function findPriorVersionDir(outRoot: string, version: string): string | undefined {
  if (!existsSync(outRoot)) return undefined;
  const dirs = readdirSync(outRoot)
    .filter((name) => name !== version)
    .map((name) => join(outRoot, name))
    .filter((path) => statSync(path).isDirectory())
    .sort((a, b) => a.localeCompare(b));
  return dirs.length > 0 ? dirs[dirs.length - 1] : undefined;
}

const ShrinkageAckFileSchema = z.object({
  acknowledgments: z.array(
    z.object({
      section: z.string().min(1),
      new_count: z.number().int().nonnegative(),
      reason: z.string().min(1),
    }),
  ),
});

/**
 * Compare each manifest `files` section's entry count against the
 * previous released version. Any decrease must be acknowledged in the
 * ack file (matched on section + new count); unacknowledged shrinkage
 * is a hard build error. Returns the acknowledgments actually used so
 * the manifest records them.
 */
async function checkShrinkage(args: {
  priorDir: string | undefined;
  contents: Record<string, unknown[]>;
  ackPath: string;
  version: string;
}): Promise<DkbShrinkageAck[]> {
  if (!args.priorDir) return [];
  const priorManifestPath = join(args.priorDir, "dkb-manifest.json");
  if (!existsSync(priorManifestPath)) return [];
  const prior = DkbManifestSchema.parse(JSON.parse(await readFile(priorManifestPath, "utf8")));

  let acks: z.infer<typeof ShrinkageAckFileSchema>["acknowledgments"] = [];
  if (existsSync(args.ackPath)) {
    const raw = YAML.load(await readFile(args.ackPath, "utf8"));
    acks = ShrinkageAckFileSchema.parse(raw).acknowledgments;
  }

  const used: DkbShrinkageAck[] = [];
  const violations: string[] = [];
  for (const [section, entries] of Object.entries(args.contents)) {
    const priorCount = prior.files[section as keyof DkbManifest["files"]]?.entries ?? 0;
    const newCount = entries.length;
    if (newCount >= priorCount) continue;
    const ack = acks.find((a) => a.section === section && a.new_count === newCount);
    if (ack) {
      used.push({ section, prior_count: priorCount, new_count: newCount, reason: ack.reason });
    } else {
      violations.push(`${section} ${priorCount} → ${newCount}`);
    }
  }

  if (violations.length > 0) {
    throw new Error(
      `dkb build: refusing to write ${args.version}: unacknowledged shrinkage vs ` +
        `${prior.version}: ${violations.join(", ")} — acknowledge intentional drops in ` +
        `${args.ackPath}`,
    );
  }
  return used;
}

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

function mergeSourceCitations(base: SourceCitation[], extra: SourceCitation[]): SourceCitation[] {
  const seen = new Map<string, SourceCitation>();
  for (const s of [...base, ...extra]) {
    if (!seen.has(s.id)) seen.set(s.id, s);
  }
  return [...seen.values()].sort((a, b) => a.id.localeCompare(b.id));
}

async function writeJsonFile(path: string, value: unknown): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, stableJson(value));
}

// ---------------------------------------------------------------------------
// CLI entry point. `npm run dkb:build` executes this with no args;
// `npm run dkb:build -- --offline` builds from the repo's curated
// sources without touching the network.

const isMain = import.meta.url === `file://${process.argv[1]}`;
if (isMain) {
  void runBuild({
    dry_run: process.argv.includes("--dry-run"),
    ...(process.argv.includes("--offline") ? { records: [] } : {}),
  })
    .then((r) => {
      process.stdout.write(
        `dkb built: version=${r.version} clauses=${r.clauses.length} ` +
          `statutes=${r.statutes.length} jurisdictions=${r.jurisdictions.length} ` +
          `definitions=${r.definitions.length} dark_patterns=${r.dark_patterns.length} ` +
          `vocab_categories=${r.vocab.length} patterns=${r.patterns.length}\n`,
      );
    })
    .catch((err) => {
      process.stderr.write(`${err instanceof Error ? err.stack ?? err.message : String(err)}\n`);
      process.exit(1);
    });
}
