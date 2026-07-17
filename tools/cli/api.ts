/**
 * Node engine API (spec-v8 §22, Step 143).
 *
 * A small, stable programmatic surface over the **already-parity-proven**
 * Node pipeline (`tools/accuracy/pipeline.ts`, proven byte-identical to the
 * browser `runReport` by `parity.test.ts`), so a team can run the engine
 * headless — in CI, a pre-commit hook, or a folder sweep — with the *same
 * determinism the browser gives*. The DKB ships *with* the tool (the
 * latest committed `dkb/dist/` artifact — the same one the site build
 * serves, so browser reports verify headless), so analysis opens **no
 * socket** — posture-preserving "nothing leaves your machine."
 *
 * Build/CI-only and never imported by `src/` (asserted by
 * `accuracy-corpus-guard.test.ts`). It composes `src/` ingest + the
 * parity-proven downstream; it re-implements no engine logic.
 */

import { readFile, readdir, stat } from "node:fs/promises";
import { extname, basename, join } from "node:path";
import { unzipSync, strFromU8 } from "fflate";

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
import type { CourtProfile } from "../../src/filing/court-profile.js";
import type { BriefKind } from "../../src/filing/run-options.js";
import type { RegimeId } from "../../src/privacy/regime-data.js";
import {
  buildCriticalDates,
  type CriticalDatesRegister,
  type DeadlineResolution,
} from "../../src/report/critical-dates.js";
import {
  buildClosingChecklist,
  type ClosingChecklist,
} from "../../src/report/closing-checklist.js";
import {
  evaluateNegotiationPosture,
  resolvePositionsForDealValue,
  type NegotiationPosture,
} from "../../src/playbooks/custom-interpreter.js";
import { extractDealValue } from "../../src/extract/deal-value.js";
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
/** Every extension the CLI ingests without `--as-text`. */
export const SUPPORTED_INPUT_EXT: ReadonlySet<string> = new Set([...TEXT_EXT, ".docx", ".pdf"]);

/** Copy a Node Buffer into a fresh, standalone ArrayBuffer. */
function toArrayBuffer(bytes: Buffer): ArrayBuffer {
  const ab = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(ab).set(bytes);
  return ab;
}

/**
 * The DOCX ingest path parses mammoth's HTML output with `DOMParser`, which
 * the browser provides natively but Node does not. Register happy-dom's
 * `DOMParser` — the same DOM engine the test suite validates DOCX parsing
 * against, so the headless CLI stays byte-identical to the browser run — the
 * first time a binary document needs it. Lazy and Node-only: this file lives
 * under `tools/cli` and is never imported by `src/` (asserted by
 * `accuracy-corpus-guard.test.ts`), so happy-dom never reaches the web bundle.
 */
async function ensureDomParser(): Promise<void> {
  const g = globalThis as { DOMParser?: unknown };
  if (typeof g.DOMParser !== "undefined") return;
  // happy-dom's `DOMParser` must be bound to a `Window` (the bare class export
  // dereferences its owning window for `HTMLDocument`); take the window's
  // instance, which is wired to a real document context.
  const { Window } = await import("happy-dom");
  g.DOMParser = new Window().DOMParser;
}

async function ingestByExtension(
  path: string,
  bytes: Buffer,
  asText = false,
): Promise<IngestResult> {
  const ext = extname(path).toLowerCase();
  if (asText) {
    // Explicit opt-in for extensionless / unconventionally named text files.
    // Binary containers must never be decoded as text, flag or not.
    if (ext === ".docx" || ext === ".pdf") {
      throw new Error(`--as-text cannot apply to a binary ${ext} document: ${path}`);
    }
    return ingestPaste(bytes.toString("utf8"));
  }
  if (TEXT_EXT.has(ext)) return ingestPaste(bytes.toString("utf8"));
  if (ext === ".docx") {
    await ensureDomParser();
    return ingestDocxBuffer(toArrayBuffer(bytes));
  }
  if (ext === ".pdf") return ingestPdfBuffer(toArrayBuffer(bytes));
  // No silent fallback (fix-cli-input-type-honesty): decoding unknown bytes
  // as UTF-8 produced a full, confidently wrong findings report on garbage.
  // An unrecognized extension is a hard error unless the user opts the file
  // into text ingestion with --as-text.
  throw new Error(
    `unsupported input type "${ext || "(no extension)"}": ${path} — supported: ` +
      `${[...SUPPORTED_INPUT_EXT].sort().join(", ")}; pass --as-text to ingest as UTF-8 text`,
  );
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
    /** Explicit DKB artifact directory (`--dkb`); default resolves latest. */
    dkbDir?: string;
    /** `--as-text`: ingest as UTF-8 text regardless of extension (never .docx/.pdf). */
    asText?: boolean;
    delivery?: boolean;
    criticalDates?: boolean;
    checklist?: boolean;
    /** A validated custom playbook; its `negotiation_positions` drive `--posture`. */
    customPlaybook?: CustomPlaybook;
    posture?: boolean;
    /**
     * Filing-format-lint activation (`--court`). When set and the document
     * matches a filing playbook, the FILE pack runs against the profile's
     * limits; otherwise it is ignored and the run is unchanged.
     */
    filing?: { profile: CourtProfile; brief_kind: BriefKind };
    /**
     * Deadline-computation resolution (`--deadline-profile` / `--service-method`).
     * When set, the critical-dates register resolves business-day/court-day and
     * roll-forward offsets under the profile; otherwise the register is unchanged.
     */
    deadline?: DeadlineResolution;
    /**
     * Privacy-notice regimes (`--regime`). When set and the document matches a
     * privacy-notice playbook, the PNOT presence rules for those regimes run;
     * otherwise the run is unchanged.
     */
    regimes?: readonly RegimeId[];
    /**
     * Estate-checks assertion (`--estate-checks`). When set and the document is
     * a will/trust/codicil, the EST deepening rules run; otherwise unchanged.
     */
    estateChecks?: boolean;
  } = {},
): Promise<AnalyzeResult> {
  const deps = opts.deps ?? (await loadAccuracyDeps({ dkbDir: opts.dkbDir }));
  const bytes = await readFile(path);
  const ingest = await ingestByExtension(path, bytes, opts.asText);
  const result = await runIngested(
    ingest,
    basename(path),
    opts.playbookId,
    deps,
    bytes.byteLength,
    opts.filing,
    opts.regimes,
    opts.estateChecks,
  );
  const out: AnalyzeResult = { ...result, ingest };
  if (opts.delivery) {
    out.delivery = await scanDelivery({
      bytes: toArrayBuffer(bytes),
      source: containerSource(path),
      text: flattenText(ingest.tree),
    });
  }
  if (opts.criticalDates || opts.deadline) {
    // The register reads only dates/definitions/obligations, so a classifier-
    // free re-extract suffices; outside `run.result_hash`. A `--deadline-profile`
    // implies the register (it is what the profile resolves).
    const extracted = extractAll(ingest.tree);
    const register = await buildCriticalDates(extracted, ingest.tree, opts.deadline);
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
    let positions = opts.customPlaybook.negotiation_positions;
    // add-negotiation-ladder-playbooks — when the caller left size_bands
    // unresolved (no explicit `--deal-value`), resolve them from the document's
    // *labeled* total value. Honest: only a stated total ("total contract
    // value: $X") is used, never a guess; an unlabeled document keeps each
    // position's base default (and the report says so).
    if (positions.some((p) => p.size_bands?.length)) {
      const dv = extractDealValue(ingest.tree);
      // Plain, locale-independent formatting (deterministic; no Intl/ICU).
      const source = dv ? `auto-detected from "${dv.label}": $${dv.value}` : undefined;
      positions = resolvePositionsForDealValue(positions, dv?.value, source);
    }
    out.negotiation_posture = await evaluateNegotiationPosture(positions, {
      tree: ingest.tree,
      extracted,
    });
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
  opts: { playbookId?: string; deps?: AccuracyDeps; dkbDir?: string } = {},
): Promise<AnalyzeResult> {
  const deps = opts.deps ?? (await loadAccuracyDeps({ dkbDir: opts.dkbDir }));
  const ingest = await ingestPaste(text);
  const result = await runIngested(
    ingest,
    filename,
    opts.playbookId,
    deps,
    Buffer.byteLength(text),
  );
  return { ...result, ingest };
}

export { loadAccuracyDeps };

/* ─────────────────────────────────────────────────────────────────────────
 * Production QA (add-production-qa-pack) — a bundle-level pass over a
 * directory or .zip production set: Bates + privilege-log reconciliation and a
 * pre-production HANDOFF sweep. CLI-only in v1; self-contained (does not touch
 * the browser bundle pipeline or the consistency engine).
 * ──────────────────────────────────────────────────────────────────────── */

type ProductionMember = { filename: string; bytes: ArrayBuffer };

/** Enumerate the members of a production set (a directory or a `.zip`). */
async function collectProductionMembers(target: string): Promise<ProductionMember[]> {
  const info = await stat(target);
  if (info.isDirectory()) {
    const names = await readdir(target);
    const members: ProductionMember[] = [];
    for (const name of names.sort()) {
      const p = join(target, name);
      const s = await stat(p);
      if (!s.isFile()) continue;
      const buf = await readFile(p);
      members.push({ filename: name, bytes: toArrayBuffer(buf) });
    }
    return members;
  }
  if (target.toLowerCase().endsWith(".zip")) {
    const buf = await readFile(target);
    const entries = unzipSync(new Uint8Array(buf));
    return Object.keys(entries)
      .filter((name) => !name.endsWith("/") && !name.startsWith("__MACOSX/"))
      .sort()
      .map((name) => {
        const data = entries[name]!;
        return { filename: basename(name), bytes: toArrayBuffer(Buffer.from(data)) };
      });
  }
  throw new Error(`--production-qa expects a directory or a .zip, got: ${target}`);
}

/**
 * Analyze a production set: reconcile Bates numbering and the privilege log,
 * and sweep each document member for pre-production leaks. The single `.csv`
 * member (if present) is the privilege log.
 */
export async function runProductionQa(
  target: string,
): Promise<import("../../src/production/report.js").ProductionQaReport> {
  const { buildProductionQaReport } = await import("../../src/production/report.js");
  const members = await collectProductionMembers(target);
  const filenames = members.map((m) => m.filename);
  const csvMembers = members.filter((m) => m.filename.toLowerCase().endsWith(".csv"));
  const logCsv =
    csvMembers.length === 1 ? strFromU8(new Uint8Array(csvMembers[0]!.bytes)) : undefined;

  // Pre-production sweep: HANDOFF scan over each .docx/.pdf member.
  const deliveries: DeliveryReport[] = [];
  for (const m of members) {
    const ext = extname(m.filename).toLowerCase();
    if (ext !== ".docx" && ext !== ".pdf") continue;
    const source: ContainerSource = ext === ".pdf" ? "pdf" : "docx";
    let text = "";
    try {
      const ingest =
        ext === ".pdf" ? await ingestPdfBuffer(m.bytes) : await ingestDocxBuffer(m.bytes);
      text = flattenText(ingest.tree);
    } catch {
      // A member that fails to ingest still gets a container-level scan.
    }
    deliveries.push(await scanDelivery({ bytes: m.bytes, source, text }));
  }

  return buildProductionQaReport({
    filenames,
    logCsv,
    deliveries: deliveries.length > 0 ? deliveries : undefined,
  });
}
