/**
 * Node engine API (spec-v8 §22, Step 143).
 *
 * A small, stable programmatic surface over the **already-parity-proven**
 * Node pipeline (`tools/accuracy/pipeline.ts`, proven byte-identical to the
 * browser `runReport` by `parity.test.ts`), so a team can run the engine
 * headless — in CI, a pre-commit hook, or a folder sweep — with the *same
 * determinism the browser gives*. The DKB ships *with* the tool (the
 * committed starter DKB), so analysis opens **no socket** — posture-
 * preserving "nothing leaves your machine."
 *
 * Build/CI-only and never imported by `src/` (asserted by
 * `accuracy-corpus-guard.test.ts`). It composes `src/` ingest + the
 * parity-proven downstream; it re-implements no engine logic.
 */

import { readFile } from "node:fs/promises";
import { extname, basename } from "node:path";

import { ingestPaste } from "../../src/ingest/paste.js";
import { ingestDocxBuffer } from "../../src/ingest/docx.js";
import { ingestPdfBuffer } from "../../src/ingest/pdf.js";
import type { IngestResult } from "../../src/ingest/types.js";
import type { EngineRun } from "../../src/engine/index.js";

import { loadAccuracyDeps, runIngested, type AccuracyDeps } from "../accuracy/pipeline.js";

export type AnalyzeResult = {
  run: EngineRun;
  playbook_id: string;
  auto_matched_playbook_id: string;
  /** The ingest result, so the report builders (JSON/HTML) can render. */
  ingest: IngestResult;
};

/** Format families the CLI can ingest, by extension. */
const TEXT_EXT = new Set([".txt", ".md", ".markdown", ".text"]);

/** Copy a Node Buffer into a fresh, standalone ArrayBuffer. */
function toArrayBuffer(bytes: Buffer): ArrayBuffer {
  const ab = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(ab).set(bytes);
  return ab;
}

async function ingestByExtension(path: string, bytes: Buffer): Promise<IngestResult> {
  const ext = extname(path).toLowerCase();
  if (TEXT_EXT.has(ext)) return ingestPaste(bytes.toString("utf8"));
  if (ext === ".docx") return ingestDocxBuffer(toArrayBuffer(bytes));
  if (ext === ".pdf") return ingestPdfBuffer(toArrayBuffer(bytes));
  // Unknown extension: treat as UTF-8 text (the most forgiving default; a
  // truly binary blob produces an empty/garbled tree, never a crash —
  // Thrust A guards the ingest functions).
  return ingestPaste(bytes.toString("utf8"));
}

/**
 * Analyze a single file on disk → an `EngineRun` plus the matched playbook.
 * `playbookId` forces a specific playbook; otherwise the same auto-match
 * the browser performs selects one.
 */
export async function analyzeFile(
  path: string,
  opts: { playbookId?: string; deps?: AccuracyDeps } = {},
): Promise<AnalyzeResult> {
  const deps = opts.deps ?? (await loadAccuracyDeps());
  const bytes = await readFile(path);
  const ingest = await ingestByExtension(path, bytes);
  const result = await runIngested(ingest, basename(path), opts.playbookId, deps);
  return { ...result, ingest };
}

/**
 * Analyze in-memory text (no filesystem) → an `EngineRun`. The headless
 * analog of pasting into the tab; identical to {@link analyzeFile} for a
 * `.txt`.
 */
export async function analyzeText(
  text: string,
  filename: string,
  opts: { playbookId?: string; deps?: AccuracyDeps } = {},
): Promise<AnalyzeResult> {
  const deps = opts.deps ?? (await loadAccuracyDeps());
  const ingest = await ingestPaste(text);
  const result = await runIngested(ingest, filename, opts.playbookId, deps);
  return { ...result, ingest };
}

export { loadAccuracyDeps };
