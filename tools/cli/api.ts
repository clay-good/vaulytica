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

import { mkdir, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { dirname, extname, basename, join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { unzipSync, strFromU8 } from "fflate";

import { ingestPaste } from "../../src/ingest/paste.js";
import { ingestDocxBuffer } from "../../src/ingest/docx.js";
import { countRevisions } from "../../src/ingest/docx-notices.js";
import { collectRevisionTexts } from "../../src/ingest/docx-revisions.js";
import { inflateOoxmlParts } from "../../src/ingest/ooxml.js";
import { attributeRevisions } from "../../src/report/redline-attribution.js";
import { checkConformity, type Conformity } from "../../src/report/conformity.js";
import {
  buildClosingSet,
  pairClosingSet,
  pairingTitle,
  type ClosingRow,
  type ClosingSet,
} from "../../src/report/closing-set.js";
import { titleCorpus } from "../../src/playbooks/matcher.js";
import { walkDir } from "./inputs.js";
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
import type { SecondaryFamilyRun } from "../../src/engine/secondary-families.js";
import type { RelatedDocument } from "../../src/report/companions.js";
import type { Playbook } from "../../src/playbooks/types.js";
import {
  findSource,
  findStatuteCitation,
  type Rule,
  type Severity,
} from "../../src/engine/finding.js";
import {
  LAUNCH_RULES,
  V3_RULES,
  V4_RULES,
  V5_RULES,
  V6_RULES,
  V7_RULES,
} from "../../src/engine/index.js";
import { compareRuns, type Comparison } from "../../src/report/compare.js";
import { buildClauseDiff, type ClauseDiff } from "../../src/report/clause-diff.js";
import { comparePosture, type PostureMovement } from "../../src/report/posture-movement.js";
import { buildDefinitionsReport } from "../../src/report/definitions.js";
import {
  FORMAT_EXT,
  renderDocxReport,
  renderFormat,
  renderReviewedDocx,
  type Format,
} from "./artifacts.js";
import {
  FolderTooLargeError,
  documentLabel,
  resolveInputs,
  shownPath,
  unpackZip,
  type WalkLimits,
  type ZipView,
} from "./inputs.js";
import { runConsistency } from "../../src/engine/consistency/runner.js";
import { ALL_CONSISTENCY_RULES } from "../../src/engine/consistency/rules/index.js";
import type { ConsistencyRun } from "../../src/engine/consistency/types.js";
import { nonAdviceStatement } from "../../src/report/disclaimers.js";
import { sha256Hex } from "../../src/ingest/hash.js";
import { ENGINE_VERSION } from "../../src/engine/runner.js";
import { buildTriage, type Triage } from "./triage.js";

export { FolderTooLargeError };
export type { ConsistencyRun };
/** The not-legal-advice line for a result about several documents. */
export const NOT_LEGAL_ADVICE_BUNDLE = nonAdviceStatement("bundle");

export type AnalyzeResult = {
  run: EngineRun;
  /**
   * The matched playbook itself, not just its id.
   *
   * `buildDocxReport` needs the object — its scope-of-review and executive
   * summary read the playbook's own fields — and only the analyzer has it in
   * hand. Carrying just the id meant the headless surface could never produce
   * the DOCX report at all, which is the artifact this tool's whole output is
   * shaped around.
   */
  playbook: Playbook;
  playbook_id: string;
  auto_matched_playbook_id: string;
  /**
   * The OTHER families this document clearly contains, each scanned with the
   * rules gated to it (fix-headless-secondary-families). Kept OUTSIDE `run`
   * exactly as the browser keeps it, so `result_hash` and every `--fail-on`
   * gate are unchanged. Empty for a document that contains only its match.
   */
  secondary_families: SecondaryFamilyRun[];
  /**
   * How many families the document clearly contains, before
   * `MAX_SECONDARY_FAMILIES` caps the list. Greater than
   * `secondary_families.length` means the cap bit and the extra families were
   * never scanned — which the terminal says rather than leaving to inference.
   */
  secondary_families_present: number;
  /** The matched family's normal pairings, resolved to display names. */
  related_documents: RelatedDocument[];
  /**
   * For an UNMATCHED document: the family that came closest, and its score —
   * the fact behind "Best score was … at 0.4". Absent when a family matched,
   * and when nothing came close enough to be worth naming. Outside `run`.
   */
  near_miss?: { playbook_id: string; score: number };
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
  revisions: "accepted" | "rejected" = "accepted",
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
    return ingestDocxBuffer(toArrayBuffer(bytes), { revisions });
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
/**
 * The packs a caller ASSERTS — each off unless asked for, each leaving the run
 * and its `result_hash` untouched. Shared by {@link analyzeFile} and
 * {@link analyzeText} so the two entry points cannot offer different ones.
 */
export interface AssertedPackOptions {
  /**
   * Deadline-computation resolution (`--deadline-profile` / `--service-method`).
   * When set, the critical-dates register resolves business-day/court-day and
   * roll-forward offsets under the profile; otherwise the register is unchanged.
   */
  deadline?: DeadlineResolution;
  /** `--critical-dates`: the derived-deadline register. Implied by `deadline`. */
  criticalDates?: boolean;
  /** `--checklist`: the closing checklist derived from the run. */
  checklist?: boolean;
  /** A validated custom playbook; its `negotiation_positions` drive `--posture`. */
  customPlaybook?: CustomPlaybook;
  posture?: boolean;
  /**
   * Scan the OTHER families the document clearly contains — a composite MSA
   * with a data-processing exhibit gets the DPA checks too, exactly as the
   * browser does (fix-headless-secondary-families).
   *
   * **Off by default, and that default is a performance decision.** Each
   * secondary family costs an extra engine pass, and this entry point is what
   * every corpus relation in `tests/integration` calls — 312 specimens times
   * five transforms times a dozen relations, all of which read `run.findings`
   * alone. Defaulting it on took the Deploy workflow's test step past its
   * 20-minute budget. `vaulytica analyze` passes `true`, so the product
   * surface is unaffected.
   */
  secondaryFamilies?: boolean;
}

export async function analyzeFile(
  path: string,
  opts: {
    playbookId?: string;
    deps?: AccuracyDeps;
    /** Explicit DKB artifact directory (`--dkb`); default resolves latest. */
    dkbDir?: string;
    /** `--as-text`: ingest as UTF-8 text regardless of extension (never .docx/.pdf). */
    asText?: boolean;
    /**
     * The name to record as `source_file.name`, when it is not the path's own.
     * The name is inside `result_hash`, so `verify` re-derives a renamed copy
     * under the name the report recorded.
     */
    sourceName?: string;
    /** `--delivery`: a CONTAINER scan; file-only, since pasted text has none. */
    delivery?: boolean;
    /**
     * Which reading of a DOCX redline to analyze. `rejected` is the draft
     * before its tracked changes; the default is what every analysis reads.
     */
    revisions?: "accepted" | "rejected";
    /** `--sec-exhibit`: the document is an SEC exhibit, so HANDOFF-008 reads its omission legend. */
    secExhibit?: boolean;
    /**
     * Filing-format-lint activation (`--court`). When set and the document
     * matches a filing playbook, the FILE pack runs against the profile's
     * limits; otherwise it is ignored and the run is unchanged.
     */
    filing?: { profile: CourtProfile; brief_kind: BriefKind };
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
    /**
     * Normalized `us-xx` state (`--state`). Implies the estate-checks pack on
     * a will/trust/codicil and selects the verified per-state formalities
     * overlay when the state is seeded; otherwise unchanged.
     */
    estateState?: string;
  } & AssertedPackOptions = {},
): Promise<AnalyzeResult> {
  const deps = opts.deps ?? (await loadAccuracyDeps({ dkbDir: opts.dkbDir }));
  const bytes = await readFile(path);
  const ingest = await ingestByExtension(path, bytes, opts.asText, opts.revisions);
  const result = await runIngested(
    ingest,
    opts.sourceName ?? basename(path),
    opts.playbookId,
    deps,
    bytes.byteLength,
    opts.filing,
    opts.regimes,
    opts.estateChecks,
    opts.estateState,
    opts.secondaryFamilies ?? false,
  );
  const out: AnalyzeResult = { ...result, ingest };
  if (opts.delivery) {
    out.delivery = await scanDelivery({
      bytes: toArrayBuffer(bytes),
      source: containerSource(path),
      text: flattenText(ingest.tree),
      playbookId: result.playbook_id,
      ...(opts.secExhibit ? { secExhibit: true } : {}),
    });
  }
  return applyAssertedPacks(out, ingest, opts);
}

/**
 * The asserted packs, in ONE place.
 *
 * `analyzeText` documented itself as "identical to {@link analyzeFile} for a
 * `.txt`" and its options as "the same asserted-pack options", and it was
 * neither: `criticalDates`, `deadline`, `checklist` and `posture` existed only
 * on the file path, so a caller who passed one to `analyzeText` got a silently
 * unchanged result. The critical-dates register was therefore unreachable from
 * the in-memory entry point every corpus relation in `tests/integration` is
 * built on — which is why no relation covers a surface that ships its own
 * hash. Two copies of a tail drift; one cannot.
 *
 * `delivery` stays on the file path alone, and that is not drift: it scans the
 * CONTAINER — the .docx/.pdf bytes — and pasted text has none.
 */
async function applyAssertedPacks(
  out: AnalyzeResult,
  ingest: IngestResult,
  opts: AssertedPackOptions,
): Promise<AnalyzeResult> {
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
  opts: {
    playbookId?: string;
    deps?: AccuracyDeps;
    dkbDir?: string;
    /** Same asserted-pack options as {@link analyzeFile} — the verifier
     * re-derives assertion-gated reports through this path. */
    filing?: { profile: CourtProfile; brief_kind: BriefKind };
    regimes?: readonly RegimeId[];
    estateChecks?: boolean;
    estateState?: string;
  } & AssertedPackOptions = {},
): Promise<AnalyzeResult> {
  const deps = opts.deps ?? (await loadAccuracyDeps({ dkbDir: opts.dkbDir }));
  const ingest = await ingestPaste(text);
  const result = await runIngested(
    ingest,
    filename,
    opts.playbookId,
    deps,
    Buffer.byteLength(text),
    opts.filing,
    opts.regimes,
    opts.estateChecks,
    opts.estateState,
    opts.secondaryFamilies ?? false,
  );
  return applyAssertedPacks({ ...result, ingest }, ingest, opts);
}

export { loadAccuracyDeps };
export type { AccuracyDeps };
// The compact projection is part of this surface: the MCP server imports
// only this module.
export { buildBrief, BRIEF_SCHEMA, type Brief, type BriefFinding } from "./brief.js";
export { isActionable } from "../../src/engine/finding.js";
export {
  buildComparisonBrief,
  comparisonBriefMarkdown,
  type ComparisonBrief,
} from "./comparison-brief.js";
export {
  buildTriage,
  buildTriageJson,
  buildTriageMarkdown,
  SLOT_QUESTION,
  type Triage,
  type TriageRow,
} from "./triage.js";

/* ─────────────────────────────────────────────────────────────────────────
 * Production QA (add-production-qa-pack) — a bundle-level pass over a
 * directory or .zip production set: Bates + privilege-log reconciliation and a
 * pre-production HANDOFF sweep. CLI-only in v1; self-contained (does not touch
 * the browser bundle pipeline or the consistency engine).
 * ──────────────────────────────────────────────────────────────────────── */

type ProductionMember = { filename: string; bytes: ArrayBuffer };

/** Enumerate the members of a production set (a directory or a `.zip`).
 * Directories are walked RECURSIVELY — real productions arrive volume-
 * structured (`VOL001/…`), and the old non-recursive readdir returned zero
 * members with exit 0 (audit finding: zip/dir parity break). Hidden files
 * (`.DS_Store`) are skipped in both paths so the same substantive set
 * hashes identically across machines. */
async function collectProductionMembers(target: string): Promise<ProductionMember[]> {
  const info = await stat(target);
  if (info.isDirectory()) {
    const members: ProductionMember[] = [];
    const walk = async (dir: string): Promise<void> => {
      const names = await readdir(dir);
      for (const name of names.sort()) {
        if (name.startsWith(".")) continue;
        const p = join(dir, name);
        const s = await stat(p);
        if (s.isDirectory()) {
          await walk(p);
          continue;
        }
        if (!s.isFile()) continue;
        const buf = await readFile(p);
        members.push({ filename: name, bytes: toArrayBuffer(buf) });
      }
    };
    await walk(target);
    members.sort((a, b) => a.filename.localeCompare(b.filename, "en"));
    return members;
  }
  if (target.toLowerCase().endsWith(".zip")) {
    const buf = await readFile(target);
    const entries = unzipSync(new Uint8Array(buf));
    return Object.keys(entries)
      .filter(
        (name) =>
          !name.endsWith("/") && !name.startsWith("__MACOSX/") && !basename(name).startsWith("."),
      )
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
  // With several CSVs (a load file beside the log), prefer the one whose
  // name says privilege log; ambiguity is REPORTED, never silently dropped
  // (audit finding: privlog.csv + loadfile.csv → "no privilege log" with
  // no warning, then a false PROD-011 on the logged gap).
  let chosenCsv = csvMembers.length === 1 ? csvMembers[0] : undefined;
  if (!chosenCsv && csvMembers.length > 1) {
    const privNamed = csvMembers.filter((m) => /priv/i.test(m.filename));
    if (privNamed.length === 1) chosenCsv = privNamed[0];
    else
      process.stderr.write(
        `vaulytica: warning: ${csvMembers.length} .csv members found (${csvMembers.map((m) => m.filename).join(", ")}) and none is unambiguously the privilege log — the log reconciliation checks did NOT run\n`,
      );
  }
  const logCsv = chosenCsv ? strFromU8(new Uint8Array(chosenCsv.bytes)) : undefined;

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

/* ────────────────────────────────────────────────────────────────────────
 * The callable surface behind the commands (spec-v48 §4).
 *
 * Folder runs, comparison, export and the catalog lookups used to exist only
 * inside `runAnalyze` / `runCompare`, which parse argv, write to stdout and set
 * `process.exitCode`. Each is a function here: it takes values, returns
 * values, and writes only the files it is asked to. The commands call these.
 * ──────────────────────────────────────────────────────────────────────── */

type AnalyzeFileOptions = NonNullable<Parameters<typeof analyzeFile>[1]>;

/** One document handed to the API: a file on disk, or text already in hand. */
export type DocumentInput =
  | {
      path: string;
      /** A DOCX redline's reading; see `analyzeFile`'s `revisions`. */
      revisions?: "accepted" | "rejected";
      /** The `source_file.name` to record, when it is not the path's own. */
      sourceName?: string;
    }
  | { text: string; filename?: string };

/** Analyze a {@link DocumentInput}. Text is named `pasted-text.txt` unless told otherwise. */
export async function analyzeDocument(
  input: DocumentInput,
  opts: AnalyzeFileOptions = {},
): Promise<AnalyzeResult> {
  if (!("path" in input)) return analyzeText(input.text, input.filename ?? "pasted-text.txt", opts);
  return analyzeFile(input.path, {
    ...opts,
    ...(input.revisions ? { revisions: input.revisions } : {}),
    ...(input.sourceName ? { sourceName: input.sourceName } : {}),
  });
}

/**
 * Analyze each file in turn. A file that cannot be read is yielded with its
 * `error` and the walk continues — one corrupt `.docx` does not cost the
 * caller the rest of the folder. What to do about it (the CLI fails the run;
 * a single input rethrows) is the caller's decision.
 */
export async function* analyzeEach(
  files: readonly string[],
  opts: AnalyzeFileOptions & {
    /** A file larger than this is yielded as an error, unread. */
    maxFileBytes?: (file: string) => number;
    /**
     * A per-file document type, ahead of `playbookId` (a project
     * configuration's `document_types`). Undefined for a file falls back to
     * `playbookId`, then to detection.
     */
    playbookFor?: (file: string) => string | undefined;
  } = {},
): AsyncGenerator<{ file: string; result: AnalyzeResult } | { file: string; error: unknown }> {
  const { maxFileBytes, playbookFor, ...analyzeOpts } = opts;
  const deps = opts.deps ?? (await loadAccuracyDeps({ dkbDir: opts.dkbDir }));
  for (const file of files) {
    try {
      const limit = maxFileBytes?.(file);
      if (limit !== undefined && (await stat(file)).size > limit) {
        throw new Error(
          `larger than the ${limit.toLocaleString("en-US")} bytes this surface reads for that file type`,
        );
      }
      const playbookId = playbookFor?.(file) ?? analyzeOpts.playbookId;
      yield { file, result: await analyzeFile(file, { ...analyzeOpts, playbookId, deps }) };
    } catch (error) {
      yield { file, error };
    }
  }
}

export type FolderAnalysis = {
  /** Every document read, in the walk's order, under the label a reader is shown. */
  documents: Array<{ file: string; label: string; result: AnalyzeResult }>;
  /** Files of a supported type that could not be read, with the reason. */
  unreadable: Array<{ file: string; reason: string }>;
  /** Files passed over for an unsupported type. A partial run says so. */
  skipped: Array<{ file: string; reason: string }>;
  /** With `dedupe`: byte-identical copies, each named with the file analyzed in its place. */
  duplicates: Array<{ file: string; of: string }>;
};

/**
 * Analyze a directory, a glob, a `.zip`, or an explicit list of paths.
 * `onDocument` is called after each file — a long folder can report progress
 * or stop (return `false`) between documents.
 */
export async function analyzeFolder(
  target: string | readonly string[],
  opts: AnalyzeFileOptions & {
    onDocument?: (done: number, total: number) => boolean | void | Promise<boolean | void>;
    /** Bounds on a directory walk; with them, a folder past `maxFiles` is an error. */
    limits?: WalkLimits;
    /** A file larger than this is reported unreadable, unread. */
    maxFileBytes?: (file: string) => number;
    /** Analyze byte-identical files once; the copies are listed in `duplicates`. */
    dedupe?: boolean;
    /** A per-file document type; see {@link analyzeEach}. */
    playbookFor?: (file: string) => string | undefined;
  } = {},
): Promise<FolderAnalysis> {
  const { onDocument, limits, dedupe, ...analyzeOpts } = opts;
  const skipped: FolderAnalysis["skipped"] = [];
  let zip: ZipView | undefined;
  let files: string[];
  if (typeof target !== "string") {
    files = [...target];
  } else if (target.toLowerCase().endsWith(".zip") && (await stat(target)).isFile()) {
    const unpacked = await unpackZip(target);
    zip = unpacked.view;
    skipped.push(...unpacked.skipped);
    files = await resolveInputs(zip.root, { limits }, skipped);
  } else {
    files = await resolveInputs(target, { asText: opts.asText, limits }, skipped);
  }
  const out: FolderAnalysis = { documents: [], unreadable: [], skipped, duplicates: [] };
  try {
    if (dedupe) {
      const first = new Map<string, string>();
      const unique: string[] = [];
      for (const file of files) {
        const bytes = await readFile(file).catch(() => null);
        // An unreadable file keeps its place; the analysis reports why.
        const sha = bytes ? await sha256Hex(bytes) : null;
        const original = sha ? first.get(sha) : undefined;
        if (original !== undefined) {
          out.duplicates.push({ file: shownPath(file, zip), of: shownPath(original, zip) });
          continue;
        }
        if (sha) first.set(sha, file);
        unique.push(file);
      }
      files = unique;
    }
    let done = 0;
    for await (const item of analyzeEach(files, analyzeOpts)) {
      const label = shownPath(item.file, zip);
      if ("result" in item) out.documents.push({ file: item.file, label, result: item.result });
      else {
        const reason = item.error instanceof Error ? item.error.message : String(item.error);
        out.unreadable.push({ file: label, reason });
      }
      if ((await onDocument?.(++done, files.length)) === false) break;
    }
  } finally {
    if (zip) await rm(zip.root, { recursive: true, force: true });
  }
  return out;
}

/**
 * The cross-document rules over documents the CALLER says are one deal.
 * A directory is not a bundle: over unrelated files these rules report true,
 * meaningless conflicts, so nothing runs this without being asked. `null`
 * with fewer than two documents — there is nothing to be consistent with.
 */
export async function checkConsistency(
  documents: FolderAnalysis["documents"],
  deps: AccuracyDeps,
): Promise<ConsistencyRun | null> {
  if (documents.length < 2) return null;
  const labels = documents.map((d) => d.label);
  return runConsistency({
    rules: ALL_CONSISTENCY_RULES,
    documents: documents.map((d) => ({
      doc_id: documentLabel(d.label, labels),
      source_file_name: basename(d.file),
      playbook_id: d.result.playbook_id,
      tree: d.result.ingest.tree,
      extracted: extractAll(d.result.ingest.tree),
    })),
    dkb: deps.dkb,
  });
}

export type FileComparison = {
  comparison: Comparison;
  clause_diff: ClauseDiff;
  /** Set when `pinType` held the revision to the base draft's document type. */
  pinned_type?: string;
  /**
   * `compareRedline` only: finding id → the authors of the tracked changes its
   * quoted text contains. Render-side, outside every hash; a finding about an
   * absence has none (see `redline-attribution.ts`).
   */
  revision_authors?: Record<string, string[]>;
  posture_movement?: PostureMovement;
  base: AnalyzeResult;
  revised: AnalyzeResult;
};

/**
 * Compare two versions of a document: the finding delta, the clause redline,
 * and — with a custom playbook and `posture` — the posture movement. Throws
 * `ComparisonRefusedError` for a cross-family pair unless `confirmPairing`.
 */
export async function compareFiles(
  base: DocumentInput,
  revised: DocumentInput,
  opts: {
    playbookId?: string;
    customPlaybook?: CustomPlaybook;
    posture?: boolean;
    confirmPairing?: boolean;
    /**
     * Analyze the revision under the BASE draft's document type. A heavy
     * rewrite can flip which type a draft matches, and then every type-specific
     * rule looks resolved or introduced — or the pair is refused outright. In a
     * drafting loop the two drafts are one document by construction.
     */
    pinType?: boolean;
    deps?: AccuracyDeps;
    dkbDir?: string;
  } = {},
): Promise<FileComparison> {
  const deps = opts.deps ?? (await loadAccuracyDeps({ dkbDir: opts.dkbDir }));
  const analyzeOpts = {
    playbookId: opts.playbookId,
    deps,
    customPlaybook: opts.customPlaybook,
    posture: opts.posture,
  };
  const baseR = await analyzeDocument(base, analyzeOpts);
  const pin = opts.pinType && !opts.playbookId ? baseR.playbook_id : undefined;
  let revisedR = await analyzeDocument(revised, analyzeOpts);
  // Only when the match actually moved: a revision that still matches the
  // base's type is the same run either way, and so is its hash.
  const pinned = pin !== undefined && revisedR.playbook_id !== pin;
  if (pinned) revisedR = await analyzeDocument(revised, { ...analyzeOpts, playbookId: pin });
  const comparison = await compareRuns(baseR.run, revisedR.run, {
    confirmPairing: opts.confirmPairing,
    warnings: { base: baseR.ingest.warnings, revised: revisedR.ingest.warnings },
  });
  const posture_movement =
    opts.posture && baseR.negotiation_posture && revisedR.negotiation_posture
      ? await comparePosture(baseR.negotiation_posture, revisedR.negotiation_posture)
      : undefined;
  return {
    comparison,
    clause_diff: buildClauseDiff(baseR.ingest.tree, revisedR.ingest.tree),
    ...(pinned ? { pinned_type: pin } : {}),
    ...(posture_movement ? { posture_movement } : {}),
    base: baseR,
    revised: revisedR,
  };
}

/** A file `compareRedline` cannot read as a redline, with the reason. */
export class RedlineRefusedError extends Error {}

/**
 * Compare the two readings of one DOCX redline: every tracked change rejected
 * (the draft as it stood) against every change accepted (the draft the
 * reviser wants). The finding delta is what the markup fixed, broke and
 * removed. It is {@link compareFiles} over the same bytes read twice, with
 * the revision pinned to the base draft's type, since a redline is one
 * document by construction. Each reading's name is suffixed (`#rejected`,
 * `#accepted`) because the name is inside `result_hash` and the two runs
 * must not collide.
 *
 * Refuses a file that is not a DOCX, or one with no tracked changes, since
 * both readings of it are the same document.
 */
export async function compareRedline(
  path: string,
  opts: Omit<Parameters<typeof compareFiles>[2], "pinType"> = {},
): Promise<FileComparison> {
  if (extname(path).toLowerCase() !== ".docx") {
    throw new RedlineRefusedError(
      `--redline reads a Word redline (.docx); ${basename(path)} is not one. To compare two versions, pass both files.`,
    );
  }
  const bytes = toArrayBuffer(await readFile(path));
  const counts = countRevisions(bytes);
  if (counts.insertions + counts.deletions + counts.moves === 0) {
    throw new RedlineRefusedError(
      `${basename(path)} has no tracked changes, so both of its readings are the same document. To compare two versions, pass both files.`,
    );
  }
  const name = basename(path);
  const result = await compareFiles(
    { path, revisions: "rejected", sourceName: `${name}#rejected` },
    { path, revisions: "accepted", sourceName: `${name}#accepted` },
    { ...opts, pinType: true },
  );
  const xml = inflateOoxmlParts(bytes, new Set(["word/document.xml"]))["word/document.xml"] ?? "";
  const revision_authors = attributeRevisions(result.comparison, collectRevisionTexts(xml));
  return { ...result, revision_authors };
}

/** A pair `compareExecuted` cannot check, with the reason. */
export class ExecutedRefusedError extends Error {}

/**
 * Check a signed copy against the final draft (add-executed-copy-conformity):
 * the comparison of the two, plus the conformity verdict with what execution
 * fills in set aside. The signed copy is held to the final's type. An
 * image-only scan has no text to compare, and no surface runs OCR, so it is refused.
 */
export async function compareExecuted(
  finalPath: string,
  signedPath: string,
  opts: Omit<Parameters<typeof compareFiles>[2], "pinType"> = {},
): Promise<FileComparison & { conformity: Conformity }> {
  const result = await compareFiles(
    { path: finalPath },
    { path: signedPath },
    { ...opts, pinType: true },
  );
  if (result.revised.ingest.word_count === 0) {
    throw new ExecutedRefusedError(
      `${basename(signedPath)} has no text layer, so there is nothing to compare. It looks like an image-only scan, and no Vaulytica surface runs OCR: run OCR on it first (Acrobat, Preview or the scanner's software), then compare again.`,
    );
  }
  const conformity = await checkConformity(result.base.ingest.tree, result.revised.ingest.tree);
  return { ...result, conformity };
}

/**
 * Check a closing set (add-executed-copy-conformity): every final draft in one
 * folder against its signed copy in the other, paired by the document's own
 * title. A pair the CLI cannot compare (an image-only scan) is a row that says
 * so; unpaired files and tied titles are listed, never guessed. Paths are
 * relative to each folder, with `/`, so the set's `conformity_hash` is the
 * same on any machine.
 */
export async function compareExecutedSet(
  finalDir: string,
  signedDir: string,
  opts: Omit<NonNullable<Parameters<typeof compareFiles>[2]>, "pinType"> = {},
): Promise<ClosingSet> {
  const deps = opts.deps ?? (await loadAccuracyDeps({ dkbDir: opts.dkbDir }));
  const side = async (dir: string) => {
    const { files } = await walkDir(dir);
    return Promise.all(
      files.map(async (path) => {
        const file = relative(dir, path).split(sep).join("/");
        const ingest = await ingestByExtension(path, await readFile(path));
        return { path, file, title: pairingTitle(titleCorpus(ingest.tree, basename(path))) };
      }),
    );
  };
  const [finals, signed] = await Promise.all([side(finalDir), side(signedDir)]);
  const { pairs, unpaired, ties } = pairClosingSet(finals, signed);
  const pathOf = new Map([
    ...finals.map((f) => [`final:${f.file}`, f.path] as const),
    ...signed.map((f) => [`signed:${f.file}`, f.path] as const),
  ]);
  const rows: ClosingRow[] = [];
  for (const p of pairs) {
    const base = { title: p.title, final: p.final, signed: p.signed };
    try {
      const { conformity } = await compareExecuted(
        pathOf.get(`final:${p.final}`)!,
        pathOf.get(`signed:${p.signed}`)!,
        { ...opts, deps },
      );
      rows.push({
        ...base,
        verdict: conformity.verdict,
        difference_count: conformity.difference_count,
        conformity_hash: conformity.conformity_hash,
      });
    } catch (e) {
      if (!(e instanceof ExecutedRefusedError)) throw e;
      rows.push({ ...base, verdict: "unreadable", reason: "no text layer (image-only scan)" });
    }
  }
  return buildClosingSet(rows, unpaired, ties);
}

/**
 * The formats {@link exportArtifacts} writes: every per-document artifact that
 * needs nothing but the document. The posture formats need a custom playbook
 * and the bundle formats a deal room; both stay with `analyze`.
 */
export const EXPORT_FORMATS = [
  "json",
  "brief-json",
  "sarif",
  "html",
  "md",
  "csv",
  "docx",
  "docx-comments",
  "checklist-md",
  "checklist-csv",
  "dates-md",
  "dates-ics",
  "obligations-csv",
  "deadlines-ics",
  "definitions-csv",
  "abstract-json",
  "abstract-csv",
] as const satisfies readonly Format[];
export type ExportFormat = (typeof EXPORT_FORMATS)[number];

export type ExportResult = {
  written: Array<{ format: ExportFormat; path: string }>;
  /** A format the document had nothing to say on — never written as an empty file. */
  skipped: Array<{ format: ExportFormat; reason: string }>;
};

/**
 * Analyze `path` once and write the requested artifacts into `outDir`, named
 * as `analyze --out` names them and rendered by the same functions, so the
 * bytes are the CLI's. Refuses to replace an existing file unless `overwrite`.
 */
export async function exportArtifacts(
  path: string,
  formats: readonly ExportFormat[],
  outDir: string,
  opts: {
    overwrite?: boolean;
    playbookId?: string;
    deps?: AccuracyDeps;
    dkbDir?: string;
    /** The project configuration that shaped this run, recorded in the JSON formats. */
    config?: import("./config.js").ConfigProvenance;
  } = {},
): Promise<ExportResult> {
  for (const f of formats) {
    if (!(EXPORT_FORMATS as readonly string[]).includes(f)) {
      throw new Error(`unsupported export format "${f}" (supported: ${EXPORT_FORMATS.join(", ")})`);
    }
  }
  if (formats.includes("docx-comments") && extname(path).toLowerCase() !== ".docx") {
    throw new Error("docx-comments writes comments into the original .docx; this file is not one");
  }
  const stem = basename(path, extname(path));
  const target = (f: ExportFormat): string => join(outDir, stem + FORMAT_EXT[f]);
  if (!opts.overwrite) {
    const existing: string[] = [];
    for (const f of formats) if (await stat(target(f)).catch(() => null)) existing.push(target(f));
    if (existing.length > 0) {
      throw new Error(
        `refusing to overwrite ${existing.join(", ")} — pass overwrite: true to replace`,
      );
    }
  }
  const deps = opts.deps ?? (await loadAccuracyDeps({ dkbDir: opts.dkbDir }));
  const wants = (prefix: string): boolean => formats.some((f) => f.startsWith(prefix));
  const r = await analyzeFile(path, {
    deps,
    playbookId: opts.playbookId,
    secondaryFamilies: true,
    checklist: wants("checklist-"),
    criticalDates: wants("dates-"),
  });
  const definitions = formats.includes("definitions-csv")
    ? await buildDefinitionsReport(extractAll(r.ingest.tree), r.ingest.tree)
    : undefined;
  const nothing: Partial<Record<ExportFormat, string>> = {
    ...(r.closing_checklist
      ? {}
      : { "checklist-md": "no closing checklist", "checklist-csv": "no closing checklist" }),
    ...(r.critical_dates
      ? {}
      : { "dates-md": "no critical-dates register", "dates-ics": "no critical-dates register" }),
  };
  const out: ExportResult = { written: [], skipped: [] };
  await mkdir(outDir, { recursive: true });
  for (const f of formats) {
    if (nothing[f]) {
      out.skipped.push({ format: f, reason: `${nothing[f]} to render for this document` });
      continue;
    }
    const content =
      f === "docx"
        ? await renderDocxReport(r, deps.dkb)
        : f === "docx-comments"
          ? renderReviewedDocx(await readFile(path), r).bytes
          : await renderFormat(f, r, deps.dkb, definitions, undefined, opts.config);
    await writeFile(target(f), content);
    out.written.push({ format: f, path: target(f) });
  }
  return out;
}

/* ---------------- The catalog: document types and rules ---------------- */

/**
 * One catalog entry, as `tools/site/doc-types.json` holds it. Declared here
 * rather than imported from the site generator: this module ships to a clone
 * that runs the CLI, and must not pull the site's build tools in with it.
 */
export type DocType = {
  id: string;
  name: string;
  group: string;
  summary: string;
  checks: Array<{ id: string; name: string; description: string; severity: string }>;
  general_checks: number;
  companions: string[];
  sources: Array<{ title: string; url: string }>;
};
type DocTypesData = { types: DocType[]; groups: string[]; superseded: Record<string, string> };

let docTypesCache: DocTypesData | undefined;

/**
 * The committed catalog the site is built from (`tools/site/doc-types.json`,
 * held equal to its generator by `site-doc-types.test.ts`), resolved beside
 * this file so it loads from any working directory.
 */
async function docTypes(): Promise<DocTypesData> {
  // A path, not a `URL`: under a DOM test environment the global `URL` is not
  // Node's, and `readFile` refuses it.
  const file = join(dirname(fileURLToPath(import.meta.url)), "..", "site", "doc-types.json");
  docTypesCache ??= JSON.parse(await readFile(file, "utf8")) as DocTypesData;
  return docTypesCache;
}

/**
 * The document types the catalog names. With no `query`: id and name only —
 * all of them with descriptions is 75 KB. With one: every word must appear in
 * the id, name, group or summary, and the summary is returned.
 */
export async function listDocumentTypes(
  opts: { query?: string; limit?: number; offset?: number } = {},
): Promise<{
  total: number;
  types: Array<{ id: string; name: string; summary?: string }>;
  next_offset?: number;
}> {
  const words = (opts.query ?? "").toLowerCase().split(/\s+/).filter(Boolean);
  const matched = (await docTypes()).types.filter((t) => {
    const hay = `${t.id} ${t.name} ${t.group} ${t.summary}`.toLowerCase();
    return words.every((w) => hay.includes(w));
  });
  const offset = Math.max(0, opts.offset ?? 0);
  const limit = Math.min(Math.max(1, opts.limit ?? 50), 100);
  const end = offset + limit;
  return {
    total: matched.length,
    types: matched.slice(offset, end).map((t) => ({
      id: t.id,
      name: t.name,
      ...(words.length > 0 ? { summary: t.summary } : {}),
    })),
    ...(end < matched.length ? { next_offset: end } : {}),
  };
}

/** Whether `id` names a document type an analysis can be forced to. */
export async function isDocumentType(id: string): Promise<boolean> {
  const data = await docTypes();
  return data.types.some((t) => t.id === id) || id in data.superseded;
}

/**
 * What the triage page needs to know about a rule: its name, what it looks
 * for, and whether it is gated to a document type or runs on every document.
 */
export function ruleCatalog(): ReadonlyMap<
  string,
  { name: string; description: string; family: boolean }
> {
  return new Map(
    ALL_RULES.map((r) => [
      r.id,
      {
        name: r.name,
        description: r.description,
        family: (r.applies_to_playbooks?.length ?? 0) > 0,
      },
    ]),
  );
}

/**
 * Analyze a folder and build its triage page (spec-v52). Byte-identical files
 * are analyzed once. The cross-document rules are not run: a folder is not a
 * bundle.
 */
export async function triageFolder(
  target: string | readonly string[],
  opts: Parameters<typeof analyzeFolder>[1] & { root?: string } = {},
): Promise<{ triage: Triage; folder: FolderAnalysis }> {
  const { root, ...folderOpts } = opts;
  const deps = opts.deps ?? (await loadAccuracyDeps({ dkbDir: opts.dkbDir }));
  const folder = await analyzeFolder(target, {
    ...folderOpts,
    deps,
    secondaryFamilies: true,
    dedupe: true,
  });
  const triage = await buildTriage(folder, {
    root: root ?? (typeof target === "string" ? target : undefined),
    rules: ruleCatalog(),
    engineVersion: ENGINE_VERSION,
    dkbVersion: deps.dkb.manifest.version,
  });
  return { triage, folder };
}

const ALL_RULES: readonly Rule[] = [
  ...LAUNCH_RULES,
  ...V3_RULES,
  ...V4_RULES,
  ...V5_RULES,
  ...V6_RULES,
  ...V7_RULES,
];

/** A rule's `dkb_citations`, resolved against the shipped DKB. Unknown ids are dropped. */
function resolveAuthorities(
  rule: Rule,
  dkb: AccuracyDeps["dkb"],
): Array<{ source: string; url: string }> {
  return rule.dkb_citations
    .map((id) => findStatuteCitation(dkb, id) ?? findSource(dkb, id))
    .filter((c) => c !== undefined)
    .map((c) => ({ source: c.source, url: c.source_url }));
}

/**
 * What one document type is checked for: the family's own checks in plain
 * words, each with the authorities its rule cites, plus how many general
 * checks run on every document. `null` for an id the catalog does not name;
 * a retired id answers with the type that superseded it.
 */
export async function describeDocumentType(
  id: string,
  opts: { deps?: AccuracyDeps; dkbDir?: string } = {},
): Promise<
  | (Omit<DocType, "checks"> & {
      checks: Array<
        DocType["checks"][number] & { authorities: Array<{ source: string; url: string }> }
      >;
      superseded_from?: string;
    })
  | null
> {
  const data = await docTypes();
  const resolved = data.superseded[id] ?? id;
  const type = data.types.find((t) => t.id === resolved);
  if (!type) return null;
  const deps = opts.deps ?? (await loadAccuracyDeps({ dkbDir: opts.dkbDir }));
  const byId = new Map(ALL_RULES.map((r) => [r.id, r]));
  return {
    ...type,
    checks: type.checks.map((c) => ({
      ...c,
      authorities: byId.has(c.id) ? resolveAuthorities(byId.get(c.id)!, deps.dkb) : [],
    })),
    ...(resolved !== id ? { superseded_from: id } : {}),
  };
}

/** A document with no legal content: what fires on it is what a rule wants ADDED. */
const BARE_DOCUMENT = "The parties met on a Tuesday and discussed the weather.";

export type GeneralCheck = {
  id: string;
  name: string;
  /** What the check looks for — never the pattern it matches. */
  description: string;
  severity: Severity;
  /**
   * What the rule tells a drafter to do when the thing is missing. Absent for
   * a check that flags a clause that is present (it has nothing to ask of an
   * empty page).
   */
  recommendation?: string;
};

/**
 * The GENERAL checks that run on a document of this type (spec-v51 §6).
 *
 * The catalog lists each type's own checks and gives the general ones as a
 * number — and on the specimens 87% of findings come from general rules. A
 * drafter working to the checklist needs them. They are read off a run: the
 * type's rule set is applied to a document with no legal content, every
 * general rule that RAN is listed with its description, and one that fired
 * brings the advice it gave. `null` for an unknown type.
 */
export async function generalChecksFor(
  id: string,
  opts: { deps?: AccuracyDeps; dkbDir?: string } = {},
): Promise<GeneralCheck[] | null> {
  const data = await docTypes();
  const resolved = data.superseded[id] ?? id;
  if (!data.types.some((t) => t.id === resolved)) return null;
  const deps = opts.deps ?? (await loadAccuracyDeps({ dkbDir: opts.dkbDir }));
  const { run } = await analyzeText(BARE_DOCUMENT, "blank.txt", { deps, playbookId: resolved });
  const byId = new Map(ALL_RULES.map((r) => [r.id, r]));
  const advice = new Map(run.findings.map((f) => [f.rule_id, f.recommendation]));
  const out: GeneralCheck[] = [];
  for (const entry of run.execution_log) {
    const rule = byId.get(entry.rule_id);
    if (!entry.ran || !rule || (rule.applies_to_playbooks?.length ?? 0) > 0) continue;
    const recommendation = advice.get(rule.id);
    out.push({
      id: rule.id,
      name: rule.name,
      description: rule.description,
      severity: rule.default_severity,
      ...(recommendation ? { recommendation } : {}),
    });
  }
  return out;
}

/**
 * What a rule carries: its name, version, category, default severity,
 * description, the document types it is gated to (absent: every document),
 * and the citations it declares. Many rules attach their citation to the
 * finding when they fire instead of declaring it, so an empty list here is
 * not "uncited" — the finding carries it. A rule has no "what satisfies it"
 * field, so none is returned. `null` for an unknown id.
 */
export async function explainRule(
  ruleId: string,
  opts: { deps?: AccuracyDeps; dkbDir?: string } = {},
): Promise<{
  rule_id: string;
  name: string;
  version: string;
  category: string;
  default_severity: Severity;
  description: string;
  applies_to_document_types?: string[];
  citations: Array<{ source: string; url: string }>;
} | null> {
  const rule = ALL_RULES.find((r) => r.id.toLowerCase() === ruleId.trim().toLowerCase());
  if (!rule) return null;
  const deps = opts.deps ?? (await loadAccuracyDeps({ dkbDir: opts.dkbDir }));
  return {
    rule_id: rule.id,
    name: rule.name,
    version: rule.version,
    category: rule.category,
    default_severity: rule.default_severity,
    description: rule.description,
    ...(rule.applies_to_playbooks?.length
      ? { applies_to_document_types: [...rule.applies_to_playbooks] }
      : {}),
    citations: resolveAuthorities(rule, deps.dkb),
  };
}
