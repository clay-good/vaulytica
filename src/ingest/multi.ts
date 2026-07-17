/**
 * Multi-document ingest (spec-v4.md §8, Step 41).
 *
 * Adds three new ingest modes behind the existing single drop-zone
 * affordance:
 *
 *   1. **Folder drop / folder picker** — `<input webkitdirectory>` paired
 *      with `DataTransferItem.webkitGetAsEntry()` recursive walk.
 *   2. **Zip drop** — `.zip` archives unpacked client-side via `fflate`
 *      (pure-JS, zero-dependency, MIT, runs offline, works behind the
 *      strict CSP).
 *   3. **Multi-file drop** — enumerate every entry in a `DataTransfer.files`
 *      `FileList` and ingest each through the existing `ingestPdfBuffer`
 *      / `ingestDocxBuffer` paths.
 *
 * Caps (spec §8 acceptance rules):
 *
 *   - Per-file: 50 MB (matches v1).
 *   - Per-bundle: 200 MB uncompressed, 50 files.
 *
 * Everything is pure-function and works in Node (for tests) and the
 * browser. Folder enumeration via the File System Access API is the
 * browser-only entry point and is provided as a separate helper.
 */

import { unzipSync, strFromU8 } from "fflate";
import { ingestPdfBuffer } from "./pdf.js";
import { ingestDocxBuffer } from "./docx.js";
import type { IngestResult } from "./types.js";

/** Per-file size ceiling. Matches v1 §28 step 12. */
export const MAX_FILE_BYTES = 50 * 1024 * 1024;
/** Per-bundle uncompressed-byte ceiling. Spec-v4 §8. */
export const MAX_BUNDLE_BYTES = 200 * 1024 * 1024;
/** Per-bundle file count ceiling. Spec-v4 §8. */
export const MAX_BUNDLE_FILES = 50;

/**
 * Per-entry decompression-ratio ceiling (spec-v8 §8). A legitimate DOCX (a
 * zip of XML) compresses ~5–10×; a PDF is already compressed (~1×). A zip
 * bomb inflates 1000×+. 200× is far past any real document yet catches the
 * classic bomb. Checked against the entry's *declared* uncompressed size
 * before fflate inflates it.
 */
export const MAX_COMPRESSION_RATIO = 200;

/** Typed, catchable rejection for a zip-bomb / oversized-archive entry. */
export class ArchiveTooLargeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ArchiveTooLargeError";
  }
}

/** User-facing copy when the bundle exceeds either bundle-level cap. */
export const BUNDLE_CAP_MESSAGE =
  "Vaulytica analyzes up to 50 files / 200 MB at once. Split your bundle or upload fewer files.";

export type AcceptedKind = "pdf" | "docx";

export type MultiIngestEntry =
  | {
      ok: true;
      filename: string;
      kind: AcceptedKind;
      bytes: ArrayBuffer;
      size_bytes: number;
    }
  | {
      ok: false;
      filename: string;
      reason: string;
    };

export type MultiIngestPlan =
  | { ok: true; entries: MultiIngestEntry[]; total_bytes: number }
  | { ok: false; reason: string };

/* ---------------- Validation helpers ---------------- */

export function classifyExtension(filename: string): AcceptedKind | null {
  const n = filename.toLowerCase();
  if (n.endsWith(".pdf")) return "pdf";
  if (n.endsWith(".docx")) return "docx";
  return null;
}

export function rejectionForFilename(filename: string): string {
  if (filename.toLowerCase().endsWith(".doc")) {
    return "Open it in Word or Google Docs and save it as .docx, then come back.";
  }
  return `Vaulytica accepts .pdf and .docx — not "${filename}".`;
}

/* ---------------- Production-QA data members ---------------- */

/**
 * Non-document bundle members (add-production-qa-pack). A `.csv` dropped
 * alongside the documents is the **privilege log**, not something to ingest as
 * a document — it rides beside the doc set and drives Bates / privilege-log
 * reconciliation. v1 recognizes exactly one data-member class: the privilege
 * log CSV.
 */
export type DataMemberKind = "csv";

export function classifyDataMember(filename: string): DataMemberKind | null {
  return filename.toLowerCase().endsWith(".csv") ? "csv" : null;
}

/** User-facing copy when a bundle carries more than one privilege-log CSV. */
export const MULTIPLE_PRIVILEGE_LOGS_MESSAGE =
  "A production set may include at most one privilege-log .csv. Remove the extras and re-upload.";

/** The single privilege-log member, decoded to text for {@link parsePrivilegeLog}. */
export type PrivilegeLogMember = { filename: string; csv: string };

/**
 * Pull the single privilege-log `.csv` out of a candidate list. Documents
 * (`.pdf`/`.docx`) are left for the normal bundle flow; a lone `.csv` is
 * decoded to text as the privilege log (matching the CLI's `--production-qa`
 * one-log-per-set rule). Zero CSVs → no member. More than one → a bundle-level
 * rejection, since a production set has a single privilege log.
 *
 * Pure over the candidate bytes — works in Node and the browser.
 */
export function selectPrivilegeLogMember(
  candidates: ReadonlyArray<{ filename: string; bytes: ArrayBuffer }>,
): { member?: PrivilegeLogMember; rejected: Array<{ filename: string; reason: string }> } {
  const logs = candidates.filter((c) => classifyDataMember(c.filename) === "csv");
  if (logs.length === 0) return { rejected: [] };
  if (logs.length > 1) {
    return {
      rejected: logs.map((c) => ({
        filename: c.filename,
        reason: MULTIPLE_PRIVILEGE_LOGS_MESSAGE,
      })),
    };
  }
  const only = logs[0]!;
  return {
    member: { filename: only.filename, csv: strFromU8(new Uint8Array(only.bytes)) },
    rejected: [],
  };
}

/* ---------------- Bundle planning ---------------- */

/**
 * Validate a candidate bundle without performing any ingest. Returns
 * the per-entry verdicts (accepted / rejected with a reason) plus the
 * total accepted-bytes count. Caller decides whether to proceed to
 * `ingestEntries`.
 *
 * The bundle-level caps are enforced up front: a bundle of > 50 files
 * or > 200 MB total returns a single bundle-level rejection.
 */
export function planBundle(
  files: ReadonlyArray<{ filename: string; bytes: ArrayBuffer; size_bytes: number }>,
): MultiIngestPlan {
  if (files.length === 0) {
    return { ok: false, reason: "No files to ingest." };
  }
  if (files.length > MAX_BUNDLE_FILES) {
    return { ok: false, reason: BUNDLE_CAP_MESSAGE };
  }
  let total = 0;
  for (const f of files) total += f.size_bytes;
  if (total > MAX_BUNDLE_BYTES) {
    return { ok: false, reason: BUNDLE_CAP_MESSAGE };
  }

  const entries: MultiIngestEntry[] = [];
  for (const f of files) {
    const kind = classifyExtension(f.filename);
    if (kind === null) {
      entries.push({ ok: false, filename: f.filename, reason: rejectionForFilename(f.filename) });
      continue;
    }
    if (f.size_bytes > MAX_FILE_BYTES) {
      entries.push({
        ok: false,
        filename: f.filename,
        reason: `${f.filename} exceeds the 50 MB per-file limit.`,
      });
      continue;
    }
    entries.push({
      ok: true,
      filename: f.filename,
      kind,
      bytes: f.bytes,
      size_bytes: f.size_bytes,
    });
  }
  return { ok: true, entries, total_bytes: total };
}

/* ---------------- Browser-side enumeration ---------------- */

/**
 * Read a browser `File` list into the candidate-bundle shape consumed
 * by {@link planBundle}. Browser-only — Node tests construct the
 * candidate-bundle shape directly.
 */
export async function filesToCandidates(
  files: ReadonlyArray<File>,
): Promise<Array<{ filename: string; bytes: ArrayBuffer; size_bytes: number }>> {
  const out = [];
  for (const f of files) {
    const bytes = await f.arrayBuffer();
    out.push({ filename: f.name, bytes, size_bytes: f.size });
  }
  return out;
}

/**
 * Recursively enumerate every `.pdf` / `.docx` under a
 * `FileSystemEntry` (the result of `DataTransferItem.webkitGetAsEntry()`
 * or the File System Access API). Browser-only.
 */
export async function enumerateFolderEntry(
  entry: FileSystemEntry,
  out: Array<{ filename: string; bytes: ArrayBuffer; size_bytes: number }> = [],
): Promise<Array<{ filename: string; bytes: ArrayBuffer; size_bytes: number }>> {
  if (entry.isFile) {
    const fileEntry = entry as FileSystemFileEntry;
    const file = await new Promise<File>((resolve, reject) => {
      fileEntry.file(resolve, reject);
    });
    if (classifyExtension(file.name) === null) return out;
    const bytes = await file.arrayBuffer();
    out.push({ filename: file.name, bytes, size_bytes: file.size });
    return out;
  }
  if (entry.isDirectory) {
    const dir = entry as FileSystemDirectoryEntry;
    const reader = dir.createReader();
    const children: FileSystemEntry[] = await readAllDirectoryEntries(reader);
    for (const child of children) await enumerateFolderEntry(child, out);
  }
  return out;
}

function readAllDirectoryEntries(reader: FileSystemDirectoryReader): Promise<FileSystemEntry[]> {
  // `readEntries` returns batches; spec requires draining until empty.
  return new Promise((resolve, reject) => {
    const acc: FileSystemEntry[] = [];
    const next = (): void => {
      reader.readEntries((batch) => {
        if (batch.length === 0) {
          resolve(acc);
          return;
        }
        for (const e of batch) acc.push(e);
        next();
      }, reject);
    };
    next();
  });
}

/* ---------------- Zip extraction ---------------- */

/**
 * Extract every `.pdf` / `.docx` from a zip archive. Pure function over
 * the archive bytes — works in Node and the browser. Uses `fflate`'s
 * synchronous `unzipSync`, which is pure JS, has zero dependencies,
 * and works behind the strict CSP (no WebAssembly compile, no eval).
 *
 * Spec §8: contents must be `.docx` / `.pdf`; any other extension is
 * rejected. The whole-archive rejection happens upstream via
 * `planBundle`'s cap check on the accumulated extracted bytes.
 *
 * Directory entries inside the zip are skipped silently. `__MACOSX/`
 * sidecar entries (the Finder's "Compress" output frequently includes
 * these) are also skipped because they don't carry usable content.
 */
export function extractZipEntries(
  archive: ArrayBuffer,
): Array<{ filename: string; bytes: ArrayBuffer; size_bytes: number }> {
  // Decompression-ratio guard (spec-v8 §8): inspect each entry's *declared*
  // sizes via fflate's filter — which runs BEFORE the entry is inflated — and
  // abort the whole archive the moment the cumulative uncompressed budget or
  // the per-entry ratio is breached, or a nested archive is seen. fflate skips
  // entries the filter rejects (returns false), so non-target files are never
  // inflated; only candidate (.pdf/.docx) entries count toward the budget.
  let cumulativeUncompressed = 0;
  // Declared per-entry sizes, captured for the post-inflate honesty check.
  const declaredSize = new Map<string, number>();
  const unzipped = unzipSync(new Uint8Array(archive), {
    filter: (file) => {
      const name = file.name;
      if (name.endsWith("/") || name.startsWith("__MACOSX/")) return false;
      const basename = name.split("/").pop() ?? name;
      if (basename.toLowerCase().endsWith(".zip")) {
        throw new ArchiveTooLargeError(`Nested archive "${name}" is not allowed inside a bundle.`);
      }
      // Documents plus the `.csv` privilege-log data member (add-production-qa-pack)
      // are inflated; anything else is skipped (not inflated). The privilege log
      // is subject to the same decompression-ratio / budget guards as documents.
      if (classifyExtension(basename) === null && classifyDataMember(basename) === null) {
        return false;
      }
      const ratio = file.size > 0 ? file.originalSize / file.size : file.originalSize;
      if (ratio > MAX_COMPRESSION_RATIO) {
        throw new ArchiveTooLargeError(
          `Archive entry "${name}" has a ${Math.round(ratio)}× compression ratio, exceeding the ${MAX_COMPRESSION_RATIO}× limit (possible zip bomb).`,
        );
      }
      cumulativeUncompressed += file.originalSize;
      if (cumulativeUncompressed > MAX_BUNDLE_BYTES) {
        throw new ArchiveTooLargeError(
          `Archive inflates to over ${MAX_BUNDLE_BYTES.toLocaleString("en-US")} uncompressed bytes; rejected before full expansion.`,
        );
      }
      declaredSize.set(name, file.originalSize);
      return true;
    },
  });
  // Produced-bytes checks (harden-determinism-guards): the filter above
  // reads DECLARED sizes — attacker-controlled header data. Measure what
  // inflation actually produced: any entry that out-inflates its own
  // header is a lying archive, and the cumulative produced bytes must
  // respect the bundle budget regardless of what the headers claimed.
  let producedBytes = 0;
  for (const [path, data] of Object.entries(unzipped)) {
    if (path.endsWith("/") || path.startsWith("__MACOSX/")) continue;
    const declared = declaredSize.get(path);
    if (declared !== undefined && data.byteLength > declared) {
      throw new ArchiveTooLargeError(
        `Archive entry "${path}" inflated to ${data.byteLength.toLocaleString("en-US")} bytes but declared ${declared.toLocaleString("en-US")} — dishonest header (possible zip bomb).`,
      );
    }
    producedBytes += data.byteLength;
    if (producedBytes > MAX_BUNDLE_BYTES) {
      throw new ArchiveTooLargeError(
        `Archive produced over ${MAX_BUNDLE_BYTES.toLocaleString("en-US")} uncompressed bytes — more than its headers declared (possible zip bomb).`,
      );
    }
  }

  const out: Array<{ filename: string; bytes: ArrayBuffer; size_bytes: number }> = [];
  for (const [path, data] of Object.entries(unzipped)) {
    if (path.endsWith("/")) continue; // directory entry
    if (path.startsWith("__MACOSX/")) continue;
    if (path.split("/").some((seg) => seg === "..")) {
      // Defensive: refuse any zip-slip-style path. fflate normalizes
      // separators but parent-traversal segments are still possible
      // for hand-crafted archives.
      continue;
    }
    const basename = path.split("/").pop() ?? path;
    if (classifyExtension(basename) === null && classifyDataMember(basename) === null) {
      // Spec §8: silently skip non-document entries inside the zip; the
      // user's intent is plainly the legal docs (plus an optional privilege-log
      // .csv), and bundling a README.txt alongside a contract shouldn't fail the
      // bundle.
      continue;
    }
    const bytes = data.buffer.slice(
      data.byteOffset,
      data.byteOffset + data.byteLength,
    ) as ArrayBuffer;
    out.push({ filename: basename, bytes, size_bytes: data.byteLength });
  }
  // Sort for determinism — zip entry order is implementation-defined
  // across producers, and the consistency engine's per-document hash
  // chain (spec-v4 §15) depends on a stable enumeration order.
  out.sort((a, b) => (a.filename < b.filename ? -1 : a.filename > b.filename ? 1 : 0));
  return out;
}

/** Heuristic: do these bytes look like a zip archive? Checks the PK magic. */
export function looksLikeZip(bytes: ArrayBuffer): boolean {
  if (bytes.byteLength < 4) return false;
  const v = new Uint8Array(bytes, 0, 4);
  return v[0] === 0x50 && v[1] === 0x4b && (v[2] === 0x03 || v[2] === 0x05 || v[2] === 0x07);
}

/* ---------------- Per-entry ingest ---------------- */

export type IngestedDocument = {
  filename: string;
  kind: AcceptedKind;
  result: IngestResult;
};

export type MultiIngestResult = {
  ingested: IngestedDocument[];
  rejected: Array<{ filename: string; reason: string }>;
  total_bytes: number;
};

/**
 * Run the existing single-file ingest paths over an accepted bundle.
 * `entries` must come from {@link planBundle} (which has already
 * enforced the per-file and per-bundle caps and the extension allow-
 * list); this function does not re-validate.
 *
 * Errors from the underlying `ingestPdfBuffer` / `ingestDocxBuffer`
 * surface as rejections so a single corrupt file does not poison the
 * whole bundle. The caller decides how to present per-document errors.
 */
export async function ingestEntries(
  entries: ReadonlyArray<MultiIngestEntry>,
  options: { pdf?: Parameters<typeof ingestPdfBuffer>[1] } = {},
): Promise<MultiIngestResult> {
  const ingested: IngestedDocument[] = [];
  const rejected: Array<{ filename: string; reason: string }> = [];
  let total = 0;
  for (const e of entries) {
    if (!e.ok) {
      rejected.push({ filename: e.filename, reason: e.reason });
      continue;
    }
    try {
      const result =
        e.kind === "pdf"
          ? await ingestPdfBuffer(e.bytes, options.pdf)
          : await ingestDocxBuffer(e.bytes);
      ingested.push({ filename: e.filename, kind: e.kind, result });
      total += e.size_bytes;
    } catch (err) {
      const reason = err instanceof Error ? err.message : String(err);
      rejected.push({ filename: e.filename, reason });
    }
  }
  return { ingested, rejected, total_bytes: total };
}

/* ---------------- Convenience: bytes-in, plan-and-ingest ---------------- */

/**
 * Convenience wrapper: take a flat list of candidate files, build a
 * plan, and ingest. Throws when the bundle fails the caps (callers
 * that want a non-throwing surface should call `planBundle` directly).
 */
export async function ingestBundle(
  candidates: ReadonlyArray<{ filename: string; bytes: ArrayBuffer; size_bytes: number }>,
  options: { pdf?: Parameters<typeof ingestPdfBuffer>[1] } = {},
): Promise<MultiIngestResult> {
  const plan = planBundle(candidates);
  if (!plan.ok) throw new Error(plan.reason);
  return ingestEntries(plan.entries, options);
}

/* ---------------- Re-exports for tests ---------------- */

/** `strFromU8` re-export for tests that need to decode UTF-8 zip entries. */
export const _internal = { strFromU8 };
