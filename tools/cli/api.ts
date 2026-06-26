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
import { flattenText } from "../../src/ingest/types.js";
import type { EngineRun } from "../../src/engine/index.js";
import {
  scanDelivery,
  type DeliveryReport,
  type ContainerSource,
} from "../../src/delivery/index.js";
import { extractAll } from "../../src/extract/index.js";
import { buildCriticalDates, type CriticalDatesRegister } from "../../src/report/critical-dates.js";
import {
  buildClosingChecklist,
  type ClosingChecklist,
} from "../../src/report/closing-checklist.js";
import {
  evaluateNegotiationPosture,
  type NegotiationPosture,
} from "../../src/playbooks/custom-interpreter.js";
import type { CustomPlaybook } from "../../src/playbooks/custom-playbook.js";

import { loadAccuracyDeps, runIngested, type AccuracyDeps } from "../accuracy/pipeline.js";

export type AnalyzeResult = {
  run: EngineRun;
  playbook_id: string;
  auto_matched_playbook_id: string;
  /** The ingest result, so the report builders (JSON/HTML) can render. */
  ingest: IngestResult;
  /**
   * Pre-disclosure scan (spec-v9 Thrust A), populated only when `--delivery`
   * is passed. Reads the ORIGINAL bytes for tracked changes, comments, hidden
   * content, metadata, and sensitive-data patterns; carries its own
   * `delivery_hash` outside `run.result_hash`.
   */
  delivery?: DeliveryReport;
  /**
   * Critical-dates register (spec-v9 Thrust C), populated only when
   * `--critical-dates` is passed. The deadlines the document's own temporal
   * terms compute to (auto-renewal notice, cure window, opt-out, survival end,
   * notice period), as absolute dates; carries its own `critical_dates_hash`
   * outside `run.result_hash`. Omitted when no derivable date is found.
   */
  critical_dates?: CriticalDatesRegister;
  /**
   * Closing checklist (spec-v9 Thrust B), populated only when `--checklist`
   * is passed. The consolidated execution-readiness items projected from the
   * run's findings (and the delivery handoff items when `--delivery` also
   * ran). Outside `run.result_hash`; omitted when no readiness item is found.
   */
  closing_checklist?: ClosingChecklist;
  /**
   * Negotiation posture (spec-v10 Thrust B, Step 172), populated only when a
   * `--playbook-file` carrying `negotiation_positions` is supplied with
   * `--posture`. Which rung of the team's ideal/acceptable ladder the draft
   * meets on each dimension; carries its own `posture_hash` outside
   * `run.result_hash`. Advisory — never a legal conclusion.
   */
  negotiation_posture?: NegotiationPosture;
};

function containerSource(path: string): ContainerSource {
  const ext = extname(path).toLowerCase();
  if (ext === ".docx") return "docx";
  if (ext === ".pdf") return "pdf";
  return "paste";
}

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
  opts: {
    playbookId?: string;
    deps?: AccuracyDeps;
    delivery?: boolean;
    criticalDates?: boolean;
    checklist?: boolean;
    /** A validated custom playbook; its `negotiation_positions` drive `--posture`. */
    customPlaybook?: CustomPlaybook;
    posture?: boolean;
  } = {},
): Promise<AnalyzeResult> {
  const deps = opts.deps ?? (await loadAccuracyDeps());
  const bytes = await readFile(path);
  const ingest = await ingestByExtension(path, bytes);
  const result = await runIngested(ingest, basename(path), opts.playbookId, deps);
  const out: AnalyzeResult = { ...result, ingest };
  if (opts.delivery) {
    out.delivery = await scanDelivery({
      bytes: toArrayBuffer(bytes),
      source: containerSource(path),
      text: flattenText(ingest.tree),
    });
  }
  if (opts.criticalDates) {
    // The register reads only dates/definitions/obligations, so a classifier-
    // free re-extract suffices; outside `run.result_hash`.
    const extracted = extractAll(ingest.tree);
    const register = await buildCriticalDates(extracted, ingest.tree);
    if (register.register.length > 0) out.critical_dates = register;
  }
  if (opts.checklist) {
    const checklist = buildClosingChecklist(
      out.run,
      (out.delivery?.findings ?? []).map((f) => ({
        rule_id: f.rule_id,
        title: f.title,
        count: f.count,
      })),
    );
    if (checklist.items.length > 0) out.closing_checklist = checklist;
  }
  // spec-v10 Thrust B Step 172 — headless negotiation posture from a supplied
  // custom playbook's `negotiation_positions` (the posture only — the playbook's
  // custom rules are not merged into the run in this pass).
  if (opts.posture && opts.customPlaybook?.negotiation_positions?.length) {
    const extracted = extractAll(ingest.tree);
    out.negotiation_posture = await evaluateNegotiationPosture(
      opts.customPlaybook.negotiation_positions,
      { tree: ingest.tree, extracted },
    );
  }
  return out;
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
