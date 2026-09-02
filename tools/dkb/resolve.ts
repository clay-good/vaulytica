/**
 * Shared DKB artifact resolution (fix-cli-browser-parity).
 *
 * The site build, the headless CLI, and the accuracy harness must all
 * run the SAME knowledge base — `dkb_version` is inside `result_hash`,
 * so a CLI that loads a different artifact than the browser can never
 * verify a browser-saved report. This module is the single source of
 * truth for "which DKB directory does a surface run":
 *
 *   - `pickLatestDkb` — the newest version directory in `dkb/dist/`
 *     (what the site ships; moved here from `vite.config.ts`).
 *   - `resolveDkbDir` — explicit `--dkb` path → report-pinned version →
 *     latest, with a hard error (never a silent fallback) when an
 *     explicit path has no valid manifest.
 *   - `loadDkbDirSync` — read + validate a DKB directory through the
 *     same Zod schemas the browser loader applies.
 *
 * Node-side only (vite config, tools/); never imported by `src/`.
 */

import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import type { DKB } from "../../src/dkb/types.js";
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

/**
 * Default artifact root: `dkb/dist/` under the working directory, and
 * failing that the one INSIDE THE INSTALLED PACKAGE.
 *
 * `process.cwd()` alone is right for everything run from a checkout — the
 * repo, the site build, the accuracy harness — and wrong for the surface the
 * package exists to provide. `npx vaulytica analyze contract.docx` runs in the
 * user's own directory, which has no `dkb/dist`, so every published install
 * died on "no DKB artifact found under ./dkb/dist" before reading a single
 * byte of the document. The package ships `dkb/dist/v0.0.1-starter/` for
 * exactly this, two levels up from this file.
 *
 * The working directory keeps priority, so a checkout still runs its own
 * artifact (which may be newer than the shipped starter) and a user who
 * places one beside their documents still gets it without `--dkb`.
 */
export function defaultDistRoot(): string {
  const cwdRoot = join(process.cwd(), "dkb", "dist");
  if (existsSync(cwdRoot)) return cwdRoot;
  return join(dirname(fileURLToPath(import.meta.url)), "..", "..", "dkb", "dist");
}

/**
 * The newest version directory in `distRoot` — the artifact the site
 * build copies into `dist/dkb/` (version names sort with localeCompare,
 * matching the vite build).
 */
export function pickLatestDkb(distRoot: string): string {
  if (!existsSync(distRoot)) return distRoot;
  const entries = readdirSync(distRoot)
    .map((name) => ({ name, path: resolve(distRoot, name) }))
    .filter((e) => statSync(e.path).isDirectory())
    .sort((a, b) => a.name.localeCompare(b.name));
  return entries.length > 0 ? entries[entries.length - 1]!.path : distRoot;
}

export type ResolveDkbOptions = {
  /** Explicit artifact directory (`--dkb <path>`). Invalid ⇒ hard error. */
  explicit?: string;
  /**
   * A saved report's stamped `dkb_version`. Used when still present under
   * `distRoot` (so old receipts stay checkable after a DKB release);
   * otherwise resolution falls through to latest.
   */
  pinnedVersion?: string;
  /** Defaults to {@link defaultDistRoot} — the working directory's
   * `dkb/dist/`, else the one shipped inside the package. */
  distRoot?: string;
};

/**
 * Resolve the DKB directory a run should load: explicit → report-pinned
 * → latest. An explicit path without a `dkb-manifest.json` is a hard
 * error — a mistyped `--dkb` must never silently analyze under a
 * different knowledge base.
 */
export function resolveDkbDir(opts: ResolveDkbOptions = {}): string {
  if (opts.explicit) {
    const dir = resolve(opts.explicit);
    if (!existsSync(join(dir, "dkb-manifest.json"))) {
      throw new Error(`--dkb ${opts.explicit}: no dkb-manifest.json found — not a DKB artifact`);
    }
    return dir;
  }
  const distRoot = opts.distRoot ?? defaultDistRoot();
  if (opts.pinnedVersion) {
    const pinned = join(distRoot, opts.pinnedVersion);
    if (existsSync(join(pinned, "dkb-manifest.json"))) return pinned;
  }
  const latest = pickLatestDkb(distRoot);
  if (!existsSync(join(latest, "dkb-manifest.json"))) {
    throw new Error(
      `no DKB artifact found under ${distRoot} — expected <version>/dkb-manifest.json`,
    );
  }
  return latest;
}

/**
 * Load a DKB directory into the in-memory aggregate, validating every
 * file through the same Zod schemas the browser loader applies — the
 * CLI must reject an artifact the browser would reject.
 */
export function loadDkbDirSync(dir: string): DKB {
  const read = (name: string): unknown =>
    JSON.parse(readFileSync(join(dir, name), "utf8")) as unknown;
  const manifest = DkbManifestSchema.parse(read("dkb-manifest.json"));
  return {
    manifest,
    clauses: ClauseLibrarySchema.parse(read(manifest.files.clauses.filename)),
    jurisdictions: JurisdictionSchema.parse(read(manifest.files.jurisdictions.filename)),
    definitions: DefinitionTemplateSchema.parse(read(manifest.files.definitions.filename)),
    dark_patterns: DarkPatternSchema.parse(read(manifest.files.dark_patterns.filename)),
    statutes: StatutorySchema.parse(read(manifest.files.statutes.filename)),
    classifier: {
      vocab: ClassifierVocabSchema.parse(read(manifest.files.classifier_vocab.filename)),
      patterns: ClassifierPatternSchema.parse(read(manifest.files.classifier_patterns.filename)),
    },
  };
}
