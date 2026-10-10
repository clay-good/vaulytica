/**
 * Which files a target names, and what each is called (spec-v48 §4).
 *
 * A path, a glob, a directory or a `.zip` becomes a sorted list of files; a
 * file becomes the label a reader is shown and the stem its artifacts are
 * written under. Pure: no argv, no stdout, no exit code — the CLI and the
 * headless API both call these.
 */

import { mkdir, mkdtemp, readdir, readFile, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, basename, extname, relative } from "node:path";
import { unzipSync } from "fflate";
import {
  ArchiveTooLargeError,
  MAX_BUNDLE_BYTES,
  MAX_COMPRESSION_RATIO,
} from "../../src/ingest/multi.js";

export const SUPPORTED_EXT = new Set([".txt", ".md", ".markdown", ".text", ".docx", ".pdf"]);

/**
 * Files under a directory whose extension is not one this tool reads.
 *
 * 🚨 A directory walk used to drop these SILENTLY, and the asymmetry with the
 * named-file branch below is the defect: naming `notes.rtf` directly is a hard
 * error that says "unsupported input type", while leaving the same file in a
 * folder produced a report that simply pretended it was not there.
 *
 * That is not a cosmetic omission, because the cross-document engine reasons
 * about what the bundle CONTAINS. Put `dpa.doc` — the old Word extension — in a
 * deal room and `CROSS-MISSING-001` reports *"sow.txt references the DPA but no
 * DPA is in the bundle"*, confidently, about a bundle the user believes holds
 * one. The same shape the named-file branch's own comment describes: an unknown
 * extension turning into "a full, confidently wrong findings report".
 *
 * These do NOT fail the run. A deal room legitimately holds a logo, a
 * spreadsheet and a README, and skipping those is correct behaviour — it just
 * has to be SAID.
 */
export const SKIPPED_UNSUPPORTED = "unsupported file type";

/** Thrown when a walk passes its file limit; `count` is how many it had found. */
export class FolderTooLargeError extends Error {
  constructor(
    readonly limit: number,
    readonly dir: string,
  ) {
    super(`${dir} holds more than ${limit} readable files`);
    this.name = "FolderTooLargeError";
  }
}

/** Bounds on a directory walk. Absent: unbounded, as the CLI has always walked. */
export type WalkLimits = { maxFiles: number; maxDepth: number };

/** Said of a directory the walk did not enter because it sat below `maxDepth`. */
export const SKIPPED_TOO_DEEP = "below the folder depth limit";

/**
 * Recursively collect supported files under a directory, and what it skipped.
 * With `limits`, the walk stops with {@link FolderTooLargeError} as soon as it
 * passes `maxFiles` — before reading the rest of a large tree — and reports a
 * directory below `maxDepth` as skipped instead of entering it.
 */
export async function walkDir(
  dir: string,
  skipped: Array<{ file: string; reason: string }> = [],
  limits?: WalkLimits,
  state: { files: number; depth: number; root: string } = { files: 0, depth: 1, root: dir },
) {
  const out: string[] = [];
  // Code-unit ordering (not `localeCompare`, which depends on the host
  // locale/ICU and would make a directory analysis non-reproducible across
  // machines) — and identical to the glob branch's bare `.sort()`, so
  // `analyze dir/` and `analyze 'dir/*.ext'` ingest files in the same order.
  for (const entry of (await readdir(dir, { withFileTypes: true })).sort((a, b) =>
    a.name < b.name ? -1 : a.name > b.name ? 1 : 0,
  )) {
    if (entry.name.startsWith(".")) continue;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (limits && state.depth >= limits.maxDepth) {
        skipped.push({ file: full, reason: SKIPPED_TOO_DEEP });
        continue;
      }
      state.depth++;
      out.push(...(await walkDir(full, skipped, limits, state)).files);
      state.depth--;
    } else if (SUPPORTED_EXT.has(extname(entry.name).toLowerCase())) {
      if (limits && ++state.files > limits.maxFiles) {
        throw new FolderTooLargeError(limits.maxFiles, state.root);
      }
      out.push(full);
    } else skipped.push({ file: full, reason: SKIPPED_UNSUPPORTED });
  }
  return { files: out, skipped };
}

/**
 * Split a `dir/pattern` glob into its directory and basename pattern. A glob
 * with no slash (e.g. `*.docx`) resolves against the current directory — the
 * previous `slice(0, lastIndexOf("/"))` produced a bogus directory (`*.doc`)
 * for that case, so a bare glob silently matched nothing.
 */
export function splitGlob(target: string): { dir: string; pattern: string } {
  const slash = target.lastIndexOf("/");
  return slash >= 0
    ? { dir: target.slice(0, slash) || "/", pattern: target.slice(slash + 1) }
    : { dir: ".", pattern: target };
}

/** Compile a single-segment glob pattern (`*` wildcard) to an anchored RegExp. */
export function globToRegExp(pattern: string): RegExp {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
  return new RegExp("^" + escaped + "$");
}

/** Resolve the target into a deterministic, sorted list of input files. */
export async function resolveInputs(
  target: string,
  opts: { asText?: boolean; limits?: WalkLimits } = {},
  /**
   * Filled with the entries a DIRECTORY walk skipped for an unsupported
   * extension. An out-parameter rather than a wider return type, so the many
   * callers that only want the file list are untouched — and optional, so a
   * caller that does not ask keeps the old behaviour exactly.
   */
  skipped?: Array<{ file: string; reason: string }>,
): Promise<string[]> {
  const st = await stat(target).catch(() => null);
  if (st?.isDirectory()) {
    const walked = await walkDir(target, [], opts.limits);
    if (skipped) skipped.push(...walked.skipped);
    return walked.files;
  }
  if (st?.isFile()) {
    // A directly named file honors the same allowlist directory and glob
    // resolution apply (fix-cli-input-type-honesty): an unknown extension
    // used to fall through to a silent UTF-8 decode and a full,
    // confidently wrong findings report. `--as-text` is the explicit
    // opt-in for extensionless / unconventionally named text files.
    if (!opts.asText && !SUPPORTED_EXT.has(extname(target).toLowerCase())) {
      throw new Error(
        `unsupported input type: ${target} (supported: ` +
          `${[...SUPPORTED_EXT].sort().join(", ")}; pass --as-text to ingest as UTF-8 text)`,
      );
    }
    return [target];
  }
  // Treat as a simple `dir/*.ext` glob (one wildcard segment).
  if (target.includes("*")) {
    const { dir, pattern } = splitGlob(target);
    const re = globToRegExp(pattern);
    const names = await readdir(dir).catch(() => [] as string[]);
    return names
      .filter((n) => re.test(n))
      .filter((n) => opts.asText || SUPPORTED_EXT.has(extname(n).toLowerCase()))
      .sort()
      .map((n) => join(dir, n));
  }
  throw new Error(`no such file or directory: ${target}`);
}

/**
 * A `.zip` given to `analyze` is unpacked to a temporary folder and read as
 * that folder (spec-v50 §7). `root` is where it was unpacked; `name` is the
 * archive as the caller typed it, which is what every printed path and every
 * document label shows — a temporary path differs on every run. Stdin is the
 * same arrangement with no archive: an empty `name`.
 */
export type ZipView = { root: string; name: string };

/**
 * Unpack the members this tool reads. An entry name is data from outside: a
 * member under a dot-segment (`..`, a hidden folder) is never written, so
 * nothing lands outside `root`. The size and ratio ceilings are the browser's
 * (`src/ingest/multi.ts`), checked on declared sizes before anything inflates.
 * Unsupported members are returned as skipped, as a directory walk reports them.
 */
export async function unpackZip(
  target: string,
): Promise<{ view: ZipView; skipped: Array<{ file: string; reason: string }> }> {
  const skipped: Array<{ file: string; reason: string }> = [];
  let total = 0;
  const entries = unzipSync(new Uint8Array(await readFile(target)), {
    filter: (f) => {
      const segments = f.name.split(/[\\/]/);
      if (f.name.endsWith("/") || segments.some((s) => s.startsWith(".") || s === "__MACOSX")) {
        return false;
      }
      if (!SUPPORTED_EXT.has(extname(f.name).toLowerCase())) {
        skipped.push({ file: `${target}/${f.name}`, reason: SKIPPED_UNSUPPORTED });
        return false;
      }
      const ratio = f.size > 0 ? f.originalSize / f.size : f.originalSize;
      total += f.originalSize;
      if (ratio > MAX_COMPRESSION_RATIO || total > MAX_BUNDLE_BYTES) {
        throw new ArchiveTooLargeError(
          `${target}: "${f.name}" inflates past the archive limits ` +
            `(${MAX_COMPRESSION_RATIO}× per entry, ${MAX_BUNDLE_BYTES / 1024 / 1024} MB in all).`,
        );
      }
      return true;
    },
  });
  const root = await mkdtemp(join(tmpdir(), "vaulytica-zip-"));
  for (const [name, bytes] of Object.entries(entries)) {
    const dest = join(root, ...name.split(/[\\/]/).filter((s) => s !== "" && s !== "."));
    await mkdir(join(dest, ".."), { recursive: true });
    await writeFile(dest, bytes);
  }
  return { view: { root, name: target }, skipped };
}

/** The path a reader is shown: the archive's name in place of the temp folder. */
export function shownPath(file: string, zip: ZipView | undefined): string {
  if (!zip) return file;
  const inside = relative(zip.root, file).split("\\").join("/");
  return zip.name ? `${zip.name}/${inside}` : inside;
}

/**
 * The `--out` file stem for each input (spec-v50 §6). `deal.md` beside
 * `deal.txt` used to write one `deal.json` and report two. A stem no other
 * input shares is used as it always was; a shared one keeps its extension
 * (`deal.md.json`); a shared file name keeps its folders too.
 */
export function outputStems(inputs: readonly string[]): Map<string, string> {
  const count = (key: (f: string) => string): Map<string, number> => {
    const m = new Map<string, number>();
    for (const f of inputs) m.set(key(f), (m.get(key(f)) ?? 0) + 1);
    return m;
  };
  // Compared case-folded: `Deal.txt` and `deal.md` are one file on macOS and Windows.
  const stem = (f: string): string => basename(f, extname(f)).toLowerCase();
  const name = (f: string): string => basename(f).toLowerCase();
  const stems = count(stem);
  const names = count(name);
  const out = new Map<string, string>();
  for (const f of inputs) {
    if (stems.get(stem(f)) === 1) out.set(f, basename(f, extname(f)));
    else if (names.get(name(f)) === 1) out.set(f, basename(f));
    else out.set(f, f.replace(/^[./\\]+/, "").replace(/[\\/:]+/g, "__"));
  }
  return out;
}

/**
 * Portable document identifier for coherence/posture artifacts
 * (fix-verify-receipt-depth): the basename, so an artifact hashes
 * identically no matter which machine or directory the bundle was
 * verified from — and never leaks the author's local paths. Collision
 * rule: when two inputs in the bundle share a basename, both keep their
 * as-given path (normalized to forward slashes), which must differ.
 */
export function documentLabel(file: string, all: readonly string[]): string {
  const base = basename(file);
  const collides = all.some((f) => f !== file && basename(f) === base);
  return collides ? file.split("\\").join("/") : base;
}
