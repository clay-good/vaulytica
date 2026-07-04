/**
 * Consolidated bundle report (spec-v4.md §11, Step 44).
 *
 * When multiple documents are processed together, callers receive:
 *
 *   1. Per-document DOCX + per-document JSON (built by the existing
 *      `buildDocxReport` / `buildJsonReport` for each {@link EngineRun}).
 *   2. **Consolidated bundle DOCX** — cover, exec summary, per-document
 *      subsections (top 10 findings each), cross-doc consistency
 *      appendix, deduped bibliography, audit trail, disclaimer block.
 *   3. **Bundle JSON** — `{ runs, cross_doc_findings, bundle_fingerprint }`.
 *   4. **Bundle zip** packaging (1)–(3) together via `fflate.zipSync`.
 *
 * The bundle fingerprint is `sha256(sorted-per-doc-result-hashes joined by "\n")`.
 * This is intentionally derived from the per-document `result_hash`es
 * (which themselves include the file SHA-256 via `EngineRun.source_file`)
 * so the fingerprint covers both the inputs and the rule outcomes.
 *
 * Determinism: every artifact in this module is a pure function of its
 * inputs. The zip is produced with deterministic mtimes and lexicographic
 * file ordering so two runs of the same bundle produce identical bytes.
 */

import {
  AlignmentType,
  BorderStyle,
  Document,
  HeadingLevel,
  Packer,
  PageBreak,
  Paragraph,
  ShadingType,
  Table,
  TableCell,
  TableRow,
  TextRun,
  WidthType,
  type IParagraphOptions,
} from "docx";
import { zipSync, type Zippable } from "fflate";

import type { EngineRun, Finding, Severity } from "../engine/finding.js";
import type {
  ConsistencyRun,
  ConsistencyFinding,
  ConsistencyExecutionLogEntry,
} from "../engine/consistency/types.js";
import type { DKB, SourceCitation } from "../dkb/types.js";
import { sha256Hex } from "../ingest/hash.js";
import { stableStringify } from "../engine/runner.js";
import { formatBibliographyEntry, dkbCurrency } from "./citations.js";
import type { ReportSecondaryFamily } from "./json.js";
import { buildJsonReport } from "./json.js";
import { buildFixListMarkdown, buildFixListCsv, buildDeadlinesIcs } from "./exports.js";
import type { ExtractedData } from "../extract/types.js";
import type { PostureCoherence, PostureCoherenceKind } from "./posture-coherence.js";
import type {
  CoherenceMovement,
  CoherenceShift,
  CoherenceFrontMovement,
} from "./coherence-movement.js";
import type { PostureMovementKind } from "./posture-movement.js";
import type { NegotiationTier } from "../playbooks/custom-interpreter.js";
import type { IngestResult } from "../ingest/types.js";
import {
  buildPortfolioMatrix,
  buildPortfolioExecutiveSummary,
  portfolioFingerprint,
  type PortfolioMatrix,
  type PortfolioExecutiveSummary,
  type PortfolioStatus,
} from "./portfolio.js";

const MINT = "00A883";
const DEFAULT_FONT = "Arial";
const BODY_SIZE = 22;

/** Cap on per-document findings surfaced in the consolidated DOCX (spec §11). */
export const BUNDLE_TOP_N = 10;

/**
 * Cap on cross-document findings rendered in the consolidated DOCX appendix
 * (spec-v8 §11). The cross-document pass is O(documents × findings); paired
 * with the bundle input caps the count is bounded, but a large bundle can
 * still produce more cross-doc findings than a reader needs in the DOCX. Mirror
 * the per-document `BUNDLE_TOP_N` truncation with an honest "N more" footer —
 * the full set always remains in the bundle JSON's `cross_doc_findings`.
 */
export const BUNDLE_CROSS_DOC_TOP_N = 100;

const DETERMINISM_STATEMENT =
  "This consolidated report was produced by a deterministic process. Given the same input files, the same Vaulytica engine version, and the same Deterministic Knowledge Base version, the rules in this report will produce an identical report on any machine, at any time. The bundle fingerprint is recorded above for verification. No part of this analysis was performed by a language model or any other non-deterministic system.";

const PRIVACY_STATEMENT =
  "This analysis was performed entirely inside the user's web browser. No portion of any input document was transmitted to any server. Vaulytica is a static web page; the page has no backend, no database, no analytics, and no telemetry. The developer of Vaulytica has no record of this analysis, no ability to recover it, and no way to identify the user who performed it.";

const NON_ADVICE_STATEMENT =
  "Vaulytica is a software tool, not a lawyer. This report is a checklist of mechanical findings produced by a deterministic rule engine against documents you provided. It is not legal advice, and using Vaulytica does not create an attorney-client relationship with anyone. The findings may be incorrect, incomplete, or inapplicable to your situation. Consult a licensed attorney in the relevant jurisdiction.";

// ---------------------------------------------------------------------------
// Public surface

export type BundleDocument = {
  doc_id: string;
  /** Display name shown in the per-document subsection header. */
  source_file_name: string;
  /** Sub-domain / playbook label, e.g. "Mutual NDA" or "MSA / Commercial". */
  detected_family?: string;
  /**
   * v3 `detectV3Family` confidence in `[0, 1]`. When threaded through
   * by the caller, it rides through to both the bundle DOCX
   * per-document subsection and the bundle JSON `documents[]` entry.
   * Optional / back-compat: omitting it preserves prior renderer
   * output verbatim (the DOCX subsection just shows the family label
   * without a confidence suffix, and the JSON entry omits the field).
   */
  detection_confidence?: number;
  /**
   * Whether the matched playbook carries `deprecated: true` in its
   * JSON. When `true`, the bundle DOCX per-document subsection
   * annotates the "Playbook:" line ("legacy" or
   * "legacy; superseded by <id>"). Optional / back-compat: omitting
   * preserves prior renderer output verbatim.
   */
  playbook_deprecated?: boolean;
  /**
   * Id of the playbook that supersedes this one, when
   * `playbook_deprecated` is true. Mirrors the optional Playbook
   * field of the same name.
   */
  playbook_superseded_by?: string;
  run: EngineRun;
  /**
   * Extracted data for this document (obligations, dates). When present,
   * the bundle "everything" archive (spec-v8 §25) emits a per-document
   * `.ics` deadlines file and threads unresolved dates into the per-document
   * fix-list. Optional / back-compat: omitting it just drops the `.ics`.
   */
  extracted?: ExtractedData;
  /**
   * Ingest summary for this document. When present, the "everything"
   * archive emits a per-document JSON report. Optional / back-compat.
   */
  ingest?: IngestResult;
  /**
   * Additional families this document also contains beyond the primary
   * match (spec-v6 multi-family activation). Same per-document semantics as
   * the single-document report: a composite document (e.g. an MSA embedding
   * a DPA exhibit) inside a bundle is scanned with every present family's
   * rule set, not just its primary playbook's, so a family is never silently
   * skipped just because the document arrived in a bundle. Each family's
   * findings ride through to the per-document subsection in the bundle DOCX
   * and to the `documents[]` entry in the bundle JSON. Optional / back-compat:
   * omitting it (or passing an empty array) preserves prior renderer output
   * verbatim for single-family documents.
   */
  secondary_families?: ReadonlyArray<ReportSecondaryFamily>;
};

export type RejectedBundleEntry = {
  filename: string;
  reason: string;
};

export type BundleReportInput = {
  documents: ReadonlyArray<BundleDocument>;
  consistency: ConsistencyRun;
  dkb: DKB;
  /** Engine version recorded on the cover; falls back to the first run's version. */
  engine_version?: string;
  /** ISO 8601 timestamp printed on the cover. Excluded from `bundle_fingerprint`. */
  executed_at?: string;
  /**
   * Files in the dropped bundle that `planBundle` refused to ingest
   * (unsupported extension, oversized, etc.). When non-empty, the
   * executive summary mentions the skipped count and a small "Skipped
   * Files" appendix enumerates them. Optional / back-compat: omitting
   * the field preserves prior renderer output verbatim.
   */
  rejected?: ReadonlyArray<RejectedBundleEntry>;
  /**
   * Whether the user kept the spec-v3 §62 cross-document consistency
   * toggle enabled for this run. When explicitly `false`, the cover
   * and executive summary say "disabled by user" so a reader of the
   * report alone understands why no cross-document findings appear.
   * When omitted, the renderer falls back to the implicit signal
   * (`consistency.execution_log.length > 0`), preserving prior
   * behavior for callers that don't set the field.
   */
  consistency_enabled?: boolean;
  /**
   * Cross-document negotiation-posture coherence (spec-v12 Thrust C). Present
   * only when the active custom playbook defined `negotiation_positions`, so
   * every document carries a posture against the **same** ladder. When set, the
   * bundle DOCX renders a trailing "Posture Coherence" section: one row per
   * front (Front · Coherence · per-document rung · binding floor), color-coded
   * by coherence. Omitted (back-compat) when no positions were supplied — every
   * existing bundle golden is byte-unchanged. Advisory: it reports where each
   * front sits across the team's own ladder, never which document legally
   * governs (spec-v12 §3 corollary 3).
   */
  posture_coherence?: PostureCoherence;
  /**
   * Cross-document posture **movement** between two rounds (spec-v13 Thrust C).
   * Present only when the bundle was analyzed with a `--baseline` round (a
   * two-round deliverable), so this report carries the diff of two v12
   * coherences computed against the **same** ladder. When set, the bundle DOCX
   * renders a trailing "Posture Movement (Across the Package)" section: one row
   * per front (Front · Floor movement · Floor base→revised · Coherence shift),
   * color-coded by the binding-floor movement. Omitted (back-compat) when no
   * baseline was supplied — every existing bundle golden is byte-unchanged.
   * Advisory: it reports where the bundle's binding floor moved on the team's
   * own ladder and whether the package fractured or reconciled, never that a
   * term became legally adequate or that the weakest document legally governs
   * (spec-v13 §3 corollary 3).
   */
  posture_movement?: CoherenceMovement;
};

/**
 * Per-document metadata surfaced alongside `runs` so a programmatic
 * consumer of the bundle JSON can correlate each engine run with its
 * UI-visible label (spec-v3 §60 detected family) and stable bundle
 * doc-id without re-deriving them from `runs`. Spec-v3 §62 follow-up.
 */
export type BundleJsonDocument = {
  doc_id: string;
  source_file_name: string;
  /** Same display label the bundle DOCX uses in per-document headings. */
  detected_family?: string;
  /**
   * Matched v2 playbook id (same value the bundle DOCX prints under
   * "Playbook:"). Always present when `documents[]` is emitted so a
   * programmatic consumer can group runs by playbook without indexing
   * back into `runs[i].playbook_id`.
   */
  playbook_id: string;
  /**
   * Matcher confidence in `[0, 1]`, when the runner recorded one.
   * Mirrors `EngineRun.playbook_match_confidence`; omitted when the run
   * did not carry a confidence (e.g. forced playbook with no match).
   */
  playbook_match_confidence?: number;
  /**
   * SHA-256 of the source file bytes — mirrors the value the bundle
   * DOCX prints under "File SHA-256:" in each per-document subsection,
   * so a programmatic consumer can verify a per-document artifact by
   * file hash without indexing back into `runs[i].source_file.sha256`.
   */
  source_file_sha256: string;
  /**
   * v3 `detectV3Family` confidence in `[0, 1]`. Omitted when the
   * caller did not thread one through (see `BundleDocument`).
   */
  detection_confidence?: number;
  /** Echo of the per-doc result hash — keys this record to the run. */
  result_hash: string;
  /**
   * Per-document severity totals — mirrors the
   * "Findings: N critical, M warning, K informational." sentence the
   * bundle DOCX prints in each per-document subsection. Always present
   * whenever the `documents[]` array is emitted so dashboards and
   * alerting pipelines can answer "which doc has critical findings?"
   * without scanning `runs[i].findings` themselves.
   */
  severity_counts: { critical: number; warning: number; info: number };
  /**
   * Mirrors `BundleDocument.playbook_deprecated`. Emitted only when the
   * matched playbook carries `deprecated: true` in its JSON; absent
   * otherwise so non-deprecated bundles serialize byte-identically to
   * prior output.
   */
  playbook_deprecated?: true;
  /**
   * Mirrors `BundleDocument.playbook_superseded_by`. Emitted only when
   * `playbook_deprecated` is also emitted AND the playbook JSON
   * carries `superseded_by`.
   */
  playbook_superseded_by?: string;
  /**
   * Additional detected families this document also contains (spec-v6
   * multi-family activation), mirroring the single-document JSON's
   * `secondary_families`. Emitted only when at least one secondary family
   * was activated for this document; absent for single-family documents so
   * existing consumers and goldens are byte-unaffected.
   */
  secondary_families?: ReportSecondaryFamily[];
};

export type BundleJson = {
  runs: EngineRun[];
  cross_doc_findings: ConsistencyFinding[];
  bundle_fingerprint: string;
  dkb_version: string;
  engine_version: string;
  /**
   * Cross-document consistency engine version (`ConsistencyRun.version`).
   * Mirrors the "Consistency engine version:" line the bundle DOCX
   * audit trail already prints; surfaced separately from the
   * single-doc `engine_version` because the two engines version
   * independently.
   */
  consistency_version: string;
  /**
   * Full cross-document execution log (one entry per CC-NNN / CROSS-*
   * rule, recording ran/skipped + findings_count + elapsed_ms). Mirrors
   * the "Cross-document rule execution" block the bundle DOCX audit
   * trail already prints; surfacing it in the JSON lets a programmatic
   * consumer distinguish "rule ran and produced zero findings"
   * (`ran: true, findings_count: 0`) from "rule skipped because its
   * `requires: DocKind[]` was not satisfied" (`ran: false`) — both
   * paths surface as zero in `cross_doc_findings` alone.
   */
  consistency_execution_log: ConsistencyExecutionLogEntry[];
  /** Spec-v4 §11 transparency: the planner-rejected entries, when present. */
  rejected?: RejectedBundleEntry[];
  /**
   * Spec-v3 §62: when the user explicitly disabled the cross-document
   * consistency toggle, surface that in the JSON output too so a
   * programmatic consumer can distinguish "user disabled consistency"
   * from "consistency ran and found zero issues". Omitted (back-compat)
   * when the caller did not set `consistency_enabled` on the input or
   * set it to `true`.
   */
  consistency_enabled?: false;
  /**
   * Spec-v3 §60 + §62 follow-up: per-document metadata (stable doc-id,
   * source file name, detected family, result hash) so the JSON output
   * carries the same human-readable labels the bundle DOCX already
   * shows. Omitted (back-compat) when no document carries a non-empty
   * `detected_family` — preserves byte-for-byte prior renderer output
   * for callers that don't set the field.
   */
  documents?: BundleJsonDocument[];
  /**
   * Portfolio risk matrix (spec-v6 Part V): a documents × key-checks grid
   * plus rollups, a deterministic aggregation over the per-document runs.
   * Always emitted for a bundle. `portfolio_fingerprint` extends
   * `bundle_fingerprint` with the canonical matrix.
   */
  portfolio: PortfolioMatrix;
  portfolio_fingerprint: string;
  /**
   * Portfolio executive summary (spec-v7 §17): rolled-up
   * critical/warning/info counts across the bundle + a one-line digest
   * per document, so a deal folder opens with the headline. Pure
   * aggregation over the per-document runs; outside every result_hash.
   */
  executive_summary: PortfolioExecutiveSummary;
};

/**
 * Bundle fingerprint per spec §11: sorted SHA-256 of file hashes
 * (encoded via the per-document `result_hash`, which itself folds in
 * the source file SHA-256) joined by a single newline and re-hashed.
 */
export async function bundleFingerprint(
  per_doc_result_hashes: ReadonlyArray<string>,
): Promise<string> {
  const sorted = [...per_doc_result_hashes].sort();
  return sha256Hex(sorted.join("\n"));
}

// ---------------------------------------------------------------------------
// Bundle JSON

export async function buildBundleJson(input: BundleReportInput): Promise<BundleJson> {
  const runs = input.documents.map((d) => d.run);
  const fingerprint = await bundleFingerprint(runs.map((r) => r.result_hash));
  const portfolio = buildPortfolioMatrix(
    input.documents.map((d) => ({
      doc_id: d.doc_id,
      source_file_name: d.source_file_name,
      run: d.run,
    })),
  );
  const out: BundleJson = {
    runs,
    cross_doc_findings: [...input.consistency.findings],
    bundle_fingerprint: fingerprint,
    dkb_version: input.dkb.manifest.version,
    engine_version: input.engine_version ?? runs[0]?.version ?? "0.0.0",
    consistency_version: input.consistency.version,
    consistency_execution_log: [...input.consistency.execution_log],
    portfolio,
    portfolio_fingerprint: await portfolioFingerprint(fingerprint, portfolio),
    executive_summary: buildPortfolioExecutiveSummary(
      input.documents.map((d) => ({
        doc_id: d.doc_id,
        source_file_name: d.source_file_name,
        run: d.run,
      })),
    ),
  };
  if (input.rejected && input.rejected.length > 0) {
    out.rejected = input.rejected.map((r) => ({ filename: r.filename, reason: r.reason }));
  }
  if (input.consistency_enabled === false) {
    out.consistency_enabled = false;
  }
  const anyFamily = input.documents.some(
    (d) => typeof d.detected_family === "string" && d.detected_family.length > 0,
  );
  if (anyFamily) {
    out.documents = input.documents.map((d) => {
      const entry: BundleJsonDocument = {
        doc_id: d.doc_id,
        source_file_name: d.source_file_name,
        playbook_id: d.run.playbook_id,
        source_file_sha256: d.run.source_file.sha256,
        result_hash: d.run.result_hash,
        severity_counts: countFindings(d.run.findings),
      };
      if (typeof d.detected_family === "string" && d.detected_family.length > 0) {
        entry.detected_family = d.detected_family;
      }
      if (typeof d.run.playbook_match_confidence === "number") {
        entry.playbook_match_confidence = d.run.playbook_match_confidence;
      }
      if (typeof d.detection_confidence === "number") {
        entry.detection_confidence = d.detection_confidence;
      }
      if (d.playbook_deprecated === true) {
        entry.playbook_deprecated = true;
        if (typeof d.playbook_superseded_by === "string" && d.playbook_superseded_by.length > 0) {
          entry.playbook_superseded_by = d.playbook_superseded_by;
        }
      }
      if (d.secondary_families && d.secondary_families.length > 0) {
        entry.secondary_families = d.secondary_families.map((s) => ({ ...s }));
      }
      return entry;
    });
  }
  return out;
}

export async function buildBundleJsonBlob(input: BundleReportInput): Promise<Blob> {
  const payload = await buildBundleJson(input);
  const json = JSON.stringify(payload, null, 2);
  return new Blob([json], { type: "application/json" });
}

// ---------------------------------------------------------------------------
// Consolidated DOCX

export async function buildBundleDocxReport(input: BundleReportInput): Promise<Blob> {
  const fingerprint = await bundleFingerprint(input.documents.map((d) => d.run.result_hash));
  const aggregate = aggregateSeverityCounts(input);
  const bibliography = buildBundleBibliography(input);

  const portfolio = buildPortfolioMatrix(
    input.documents.map((d) => ({
      doc_id: d.doc_id,
      source_file_name: d.source_file_name,
      run: d.run,
    })),
  );

  const children: (Paragraph | Table)[] = [
    ...renderCover(input, fingerprint),
    ...renderExecutiveSummary(input, aggregate),
    ...renderPortfolioMatrix(portfolio),
    ...renderPerDocumentSection(input),
    ...renderCrossDocAppendix(input.consistency),
    ...renderSkippedFilesAppendix(input.rejected),
    ...renderPostureCoherenceSection(input.posture_coherence),
    ...renderPostureMovementSection(input.posture_movement),
    ...renderBibliography(bibliography, dkbCurrency(input.dkb.manifest)),
    ...renderAuditTrail(input),
    ...renderDisclaimer(),
  ];

  const doc = new Document({
    creator: "Vaulytica",
    title: "Vaulytica Bundle Report",
    description: "Deterministic multi-document linter report",
    styles: {
      default: {
        document: {
          run: { font: DEFAULT_FONT, size: BODY_SIZE },
        },
      },
    },
    sections: [
      {
        properties: {
          page: {
            size: { width: 12240, height: 15840 },
            margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 },
          },
        },
        children,
      },
    ],
  });

  const blob = await Packer.toBlob(doc);
  if (blob.type === "") {
    return new Blob([blob], {
      type: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    });
  }
  return blob;
}

// ---------------------------------------------------------------------------
// Bundle zip — per-doc DOCX + per-doc JSON + consolidated DOCX + bundle JSON.

export type BundleZipArtifact = {
  filename: string;
  bytes: Uint8Array;
};

export type BundleZipInput = BundleReportInput & {
  /**
   * Optional per-document artifacts. When omitted, the zip only
   * contains the consolidated DOCX and the bundle JSON. Callers that
   * want the per-document DOCX/JSON in the same zip pass them in
   * (the UI pipeline already builds them via `buildDocxReport` /
   * `buildJsonReport` for download buttons).
   */
  per_document_artifacts?: ReadonlyArray<BundleZipArtifact>;
  /**
   * Bundle "everything" archive (spec-v8 §25). When true, the zip also
   * carries, per document, the action exports a portfolio reviewer would
   * otherwise download one at a time: a fix-list (Markdown + CSV), a
   * deadlines `.ics` (when `extracted` is present), and the per-document
   * JSON report (when `ingest` is present). All are deterministic
   * projections of artifacts that already exist; nothing new is computed.
   */
  include_per_document_exports?: boolean;
};

/**
 * Build the consolidated bundle zip. Returns a Blob with the zip MIME
 * type. File order inside the zip is lexicographic by basename so two
 * runs over the same bundle produce byte-identical archives (assuming
 * the inputs were themselves deterministic).
 */
export async function buildBundleZip(input: BundleZipInput): Promise<Blob> {
  const consolidatedDocx = await buildBundleDocxReport(input);
  const bundleJsonBlob = await buildBundleJsonBlob(input);

  const files: Zippable = {};

  files["consolidated-report.docx"] = new Uint8Array(await consolidatedDocx.arrayBuffer());
  files["bundle.json"] = new Uint8Array(await bundleJsonBlob.arrayBuffer());

  if (input.per_document_artifacts) {
    for (const a of input.per_document_artifacts) {
      const path = `per-document/${a.filename}`;
      files[path] = a.bytes;
    }
  }

  // spec-v8 §25 — the "everything" archive: per-document action exports,
  // each a deterministic projection of the document's run / extracted data.
  if (input.include_per_document_exports) {
    const enc = new TextEncoder();
    for (const doc of input.documents) {
      const stem = `per-document/${doc.doc_id}`;
      files[`${stem}.fixlist.md`] = enc.encode(
        buildFixListMarkdown(doc.run, doc.extracted, dkbCurrency(input.dkb.manifest)),
      );
      files[`${stem}.fixlist.csv`] = enc.encode(
        buildFixListCsv(doc.run, dkbCurrency(input.dkb.manifest)),
      );
      if (doc.extracted) {
        files[`${stem}.deadlines.ics`] = enc.encode(buildDeadlinesIcs(doc.extracted));
      }
      if (doc.ingest) {
        const jsonBlob = buildJsonReport(doc.run, doc.ingest);
        files[`${stem}.report.json`] = new Uint8Array(await jsonBlob.arrayBuffer());
      }
    }
  }

  const orderedKeys = Object.keys(files).sort();
  const ordered: Zippable = {};
  // Per-entry fixed mtime (2000-01-01 UTC — comfortably inside fflate's
  // 1980-2099 range) keeps the archive byte-identical across runs.
  const FIXED_MTIME = new Date(Date.UTC(2000, 0, 1, 0, 0, 0));
  for (const k of orderedKeys) {
    ordered[k] = [files[k] as Uint8Array, { mtime: FIXED_MTIME }];
  }

  const bytes = zipSync(ordered);
  return new Blob([new Uint8Array(bytes)], { type: "application/zip" });
}

// ---------------------------------------------------------------------------
// Section renderers

function renderCover(input: BundleReportInput, fingerprint: string): Paragraph[] {
  const engineVersion = input.engine_version ?? input.documents[0]?.run.version ?? "0.0.0";
  const iso = input.executed_at ?? "";
  const human = iso ? formatHumanDate(iso) : "(omitted from hash)";
  return [
    para({
      text: "Vaulytica Bundle Report",
      heading: HeadingLevel.TITLE,
      color: MINT,
      bold: true,
      alignment: AlignmentType.CENTER,
    }),
    spacer(),
    coverField("Documents", String(input.documents.length)),
    coverField("Bundle fingerprint", fingerprint),
    coverField("Engine version", engineVersion),
    coverField("DKB version", input.dkb.manifest.version),
    coverField(
      "Cross-document consistency",
      input.consistency_enabled === false
        ? "disabled by user"
        : `${input.consistency.execution_log.length} rules executed`,
    ),
    coverField("Analysis date", iso ? `${iso}  (${human})` : "(omitted from hash)"),
    spacer(),
    para({ text: DETERMINISM_STATEMENT, italics: true }),
    spacer(2),
    para({ text: "Vaulytica", color: MINT, bold: true, alignment: AlignmentType.CENTER }),
    pageBreak(),
  ];
}

function renderExecutiveSummary(
  input: BundleReportInput,
  counts: SeverityAggregate,
): (Paragraph | Table)[] {
  const docs = input.documents.length;
  const crossCounts = countConsistency(input.consistency.findings);
  const rejectedCount = input.rejected?.length ?? 0;
  const rejectedSentence =
    rejectedCount === 0
      ? ""
      : ` ${plural(rejectedCount, "file")} in the drop ${rejectedCount === 1 ? "was" : "were"} skipped — see the Skipped Files appendix.`;
  const consistencyClause =
    input.consistency_enabled === false
      ? "The cross-document consistency pass was disabled by the user; no cross-document findings were computed."
      : `The cross-document consistency pass executed ${plural(input.consistency.execution_log.length, "rule")} and surfaced ${plural(crossCounts.critical + crossCounts.warning + crossCounts.info, "cross-document finding")}.`;
  const intro = `This bundle contains ${plural(docs, "document")}.${rejectedSentence} Across all documents the engine emitted ${plural(counts.critical, "critical finding")}, ${plural(counts.warning, "warning")}, and ${plural(counts.info, "informational item")}. ${consistencyClause}`;
  return [
    h1("Executive Summary"),
    para({ text: intro }),
    spacer(),
    new Table({
      width: { size: 60, type: WidthType.PERCENTAGE },
      rows: [
        headerRow(["Severity", "Per-document total", "Cross-document"]),
        bodyRow(["Critical", String(counts.critical), String(crossCounts.critical)]),
        bodyRow(["Warning", String(counts.warning), String(crossCounts.warning)]),
        bodyRow(["Informational", String(counts.info), String(crossCounts.info)]),
      ],
    }),
    pageBreak(),
  ];
}

// Portfolio matrix shading — mirrors the v3 compliance-matrix vocabulary
// (green pass / yellow attention / red fail / grey N/A).
const PORTFOLIO_FILL: Record<PortfolioStatus, string> = {
  ok: "C8E6C9",
  flag: "FFF59D",
  risk: "FFCDD2",
  na: "EEEEEE",
};
const PORTFOLIO_TEXT: Record<PortfolioStatus, string> = {
  ok: "1B5E20",
  flag: "8D6E00",
  risk: "B71C1C",
  na: "555555",
};

function renderPortfolioMatrix(matrix: PortfolioMatrix): (Paragraph | Table)[] {
  const out: (Paragraph | Table)[] = [h1("Portfolio Risk Matrix")];
  out.push(
    para({
      text: "A deterministic projection of the per-document runs: one row per document, one column per high-signal check. Each cell is shaded green (in place), yellow (present and noteworthy), red (a gap or risk), or grey (not applicable — the underlying rule did not run for that document). A grey cell is never a claim that the clause is missing.",
    }),
  );
  out.push(spacer());

  const header = new TableRow({
    tableHeader: true,
    children: ["Document", ...matrix.checks.map((c) => c.label)].map(
      (text) =>
        new TableCell({
          shading: { type: ShadingType.CLEAR, fill: MINT, color: "auto" },
          children: [
            new Paragraph({
              children: [
                new TextRun({
                  text,
                  bold: true,
                  color: "FFFFFF",
                  font: DEFAULT_FONT,
                  size: BODY_SIZE,
                }),
              ],
            }),
          ],
        }),
    ),
  });
  const dataRows = matrix.rows.map(
    (row) =>
      new TableRow({
        children: [
          styledCell(truncate(row.source_file_name, 48), { bold: true }),
          ...row.cells.map((cell) => portfolioCell(cell.status, cell.label, cell.rule_ids)),
        ],
      }),
  );
  out.push(
    new Table({ width: { size: 100, type: WidthType.PERCENTAGE }, rows: [header, ...dataRows] }),
  );
  out.push(spacer());

  if (matrix.truncated) {
    out.push(
      para({
        text: `Note: this bundle contains ${matrix.total} documents; the matrix shows the first ${matrix.included} (sorted by file name). The portfolio cap is ${matrix.included} rows.`,
        italics: true,
      }),
    );
  } else {
    out.push(
      para({
        text: `${matrix.total} ${matrix.total === 1 ? "document" : "documents"} included.`,
        italics: true,
      }),
    );
  }

  if (matrix.rollups.length > 0) {
    out.push(spacer());
    out.push(h2("Portfolio rollups"));
    for (const r of matrix.rollups) {
      out.push(para({ text: r.text, bold: r.count > 0 }));
      if (r.count > 0 && r.documents.length > 0) {
        out.push(para({ text: `  ${r.documents.join(", ")}`, italics: true }));
      }
    }
  }
  out.push(pageBreak());
  return out;
}

function portfolioCell(status: PortfolioStatus, label: string, ruleIds?: string[]): TableCell {
  const lines = [label];
  if (ruleIds && ruleIds.length > 0) lines.push(ruleIds.join(", "));
  return new TableCell({
    shading: { type: ShadingType.CLEAR, fill: PORTFOLIO_FILL[status], color: "auto" },
    children: lines.map(
      (line, i) =>
        new Paragraph({
          children: [
            new TextRun({
              text: line,
              bold: i === 0,
              color: i === 0 ? PORTFOLIO_TEXT[status] : "555555",
              font: DEFAULT_FONT,
              size: BODY_SIZE,
            }),
          ],
        }),
    ),
  });
}

function styledCell(text: string, opts: { bold?: boolean } = {}): TableCell {
  return new TableCell({
    borders: {
      top: { style: BorderStyle.SINGLE, size: 4, color: "CCCCCC" },
      bottom: { style: BorderStyle.SINGLE, size: 4, color: "CCCCCC" },
      left: { style: BorderStyle.SINGLE, size: 4, color: "CCCCCC" },
      right: { style: BorderStyle.SINGLE, size: 4, color: "CCCCCC" },
    },
    children: [
      new Paragraph({
        children: [new TextRun({ text, bold: opts.bold, font: DEFAULT_FONT, size: BODY_SIZE })],
      }),
    ],
  });
}

function renderPerDocumentSection(input: BundleReportInput): (Paragraph | Table)[] {
  const out: (Paragraph | Table)[] = [h1("Per-Document Findings")];
  for (const doc of input.documents) {
    const top = pickTop(doc.run.findings, BUNDLE_TOP_N);
    const familyLabel = doc.detected_family ?? doc.run.playbook_id;
    const familyLine =
      typeof doc.detection_confidence === "number"
        ? `Detected family: ${familyLabel} (confidence ${doc.detection_confidence.toFixed(2)})`
        : `Detected family: ${familyLabel}`;
    out.push(h2(doc.source_file_name));
    out.push(para({ text: familyLine }));
    const deprecationSuffix =
      doc.playbook_deprecated === true
        ? doc.playbook_superseded_by
          ? ` — legacy; superseded by ${doc.playbook_superseded_by}`
          : " — legacy"
        : "";
    out.push(para({ text: `Playbook: ${doc.run.playbook_id}${deprecationSuffix}` }));
    out.push(para({ text: `File SHA-256: ${doc.run.source_file.sha256}` }));
    out.push(para({ text: `Per-document result hash: ${doc.run.result_hash}` }));
    const totals = countFindings(doc.run.findings);
    out.push(
      para({
        text: `Findings: ${totals.critical} critical, ${totals.warning} warning, ${totals.info} informational.`,
      }),
    );
    if (top.length === 0) {
      out.push(para({ text: "No findings.", italics: true }));
    } else {
      out.push(para({ text: `Top ${top.length} findings:`, bold: true }));
      for (const f of top) {
        out.push(
          para({
            text: `[${f.severity.toUpperCase()}] ${f.rule_id} — ${f.title}`,
            bold: true,
            color: severityColor(f.severity),
          }),
        );
        out.push(para({ text: f.description }));
      }
    }
    out.push(...renderPerDocumentSecondaryFamilies(doc.secondary_families));
    out.push(spacer());
  }
  out.push(pageBreak());
  return out;
}

// Additional families a bundled document also contains beyond its primary
// match (spec-v6 multi-family activation). The same composite document dropped
// alone gets these families in its single-document report; this keeps the
// bundle's per-document subsection consistent with that. Rendered compactly —
// the family label with severity counts plus each finding's headline — since
// the document's own per-document DOCX download carries the full section.
function renderPerDocumentSecondaryFamilies(
  secondary: ReadonlyArray<ReportSecondaryFamily> | undefined,
): Paragraph[] {
  if (!secondary || secondary.length === 0) return [];
  const out: Paragraph[] = [
    para({ text: "Also checked (other detected families):", bold: true, italics: true }),
  ];
  for (const fam of secondary) {
    const c = fam.counts;
    out.push(
      para({
        text: `${fam.playbook_name} (${fam.playbook_id}) — ${c.critical} critical, ${c.warning} warning, ${c.info} informational`,
        bold: true,
      }),
    );
    if (fam.findings.length === 0) {
      out.push(
        para({ text: "No findings — this family's requirements appear to be met.", italics: true }),
      );
      continue;
    }
    for (const f of pickTop(fam.findings, BUNDLE_TOP_N)) {
      out.push(
        para({
          text: `[${f.severity.toUpperCase()}] ${f.rule_id} — ${f.title}`,
          color: severityColor(f.severity),
        }),
      );
    }
  }
  return out;
}

function renderSkippedFilesAppendix(
  rejected: ReadonlyArray<RejectedBundleEntry> | undefined,
): (Paragraph | Table)[] {
  if (!rejected || rejected.length === 0) return [];
  const out: (Paragraph | Table)[] = [h1("Skipped Files")];
  out.push(
    para({
      text: `${plural(rejected.length, "file")} from the drop ${rejected.length === 1 ? "was" : "were"} not analyzed. Each row records the filename and the reason the planner refused to ingest it (unsupported extension, exceeds the per-file size cap, etc.).`,
    }),
  );
  out.push(spacer());
  for (const r of rejected) {
    out.push(para({ text: r.filename, bold: true }));
    out.push(para({ text: r.reason }));
  }
  out.push(pageBreak());
  return out;
}

// Posture-coherence shading (spec-v12 Thrust C). The fill encodes whether the
// bundle holds one line on a front: green = aligned, red = divergent, blue =
// stated by one document, grey = stated by none.
const COHERENCE_FILL: Record<PostureCoherenceKind, string> = {
  aligned: "E6F4EA",
  divergent: "FBE9E7",
  single: "E8EEF9",
  unstated: "EFEFEF",
};
const COHERENCE_TEXT: Record<PostureCoherenceKind, string> = {
  aligned: "1A8F5A",
  divergent: "B00020",
  single: "2D6CDF",
  unstated: "555555",
};
const COHERENCE_LABEL: Record<PostureCoherenceKind, string> = {
  aligned: "Aligned",
  divergent: "Divergent",
  single: "Stated by one",
  unstated: "Unstated",
};
const TIER_SHORT_LABEL: Record<NegotiationTier, string> = {
  ideal: "ideal",
  acceptable: "acceptable",
  "below-acceptable": "below floor",
  unevaluable: "not stated",
};

/**
 * Posture Coherence section (spec-v12 Thrust C). A trailing, optional section:
 * one row per negotiation front — Front · Coherence · per-document rung ·
 * binding floor — color-coded by coherence. Omitted entirely when no posture
 * coherence was supplied (no positions), so every existing bundle golden is
 * byte-unchanged. Advisory: it reports where each front sits across the team's
 * own ladder, never which document legally governs (spec-v12 §3 corollary 3).
 */
function renderPostureCoherenceSection(
  coherence: PostureCoherence | undefined,
): (Paragraph | Table)[] {
  if (!coherence || coherence.dimensions.length === 0) return [];
  const c = coherence.counts;
  const out: (Paragraph | Table)[] = [h1("Posture Coherence")];
  out.push(
    para({
      text: "How the team's negotiation posture sits across the whole bundle. Each document was classified against the same positions; this section reports, per front, whether the documents agree on the rung (aligned), disagree (divergent), are stated by only one document (stated by one), or stated by none (unstated). The binding floor is the weakest stated rung and the document(s) carrying it — in a deal package the weakest document usually governs exposure.",
    }),
  );
  out.push(
    para({
      text: `${c.aligned} aligned · ${c.divergent} divergent · ${c.single} stated by one · ${c.unstated} unstated.`,
      bold: true,
    }),
  );
  out.push(spacer());

  const header = headerRow(["Front", "Coherence", "Rung by document", "Binding floor"]);
  const rows = coherence.dimensions.map((d) => {
    const perDoc = d.tiers.map((t) => `${t.document}: ${TIER_SHORT_LABEL[t.tier]}`).join("; ");
    const floor =
      d.weakest_tier === null
        ? "—"
        : `${TIER_SHORT_LABEL[d.weakest_tier]} (${d.weakest_documents.join(", ")})`;
    return new TableRow({
      children: [
        styledCell(d.dimension, { bold: true }),
        coherenceCell(d.coherence),
        styledCell(perDoc),
        styledCell(floor),
      ],
    });
  });
  out.push(
    new Table({ width: { size: 100, type: WidthType.PERCENTAGE }, rows: [header, ...rows] }),
  );
  out.push(spacer());
  out.push(
    para({
      text: "Computed deterministically from your playbook's positions — it reports where each front sits across your own ladder and names the weakest document; it is not a legal conclusion and does not decide which document legally governs on a conflict.",
      italics: true,
    }),
  );
  out.push(pageBreak());
  return out;
}

function coherenceCell(kind: PostureCoherenceKind): TableCell {
  return new TableCell({
    shading: { type: ShadingType.CLEAR, fill: COHERENCE_FILL[kind], color: "auto" },
    children: [
      new Paragraph({
        children: [
          new TextRun({
            text: COHERENCE_LABEL[kind],
            bold: true,
            color: COHERENCE_TEXT[kind],
            font: DEFAULT_FONT,
            size: BODY_SIZE,
          }),
        ],
      }),
    ],
  });
}

// Binding-floor-movement shading (spec-v13 Thrust C). The fill encodes which way
// the bundle's weakest stated rung moved between rounds: green = improved, red =
// regressed, grey = unchanged, blue = newly stated, amber = no longer stated.
// Mirrors the v11 compare-docx movement palette (one axis over) so a reader of
// either report reads the same colors for the same direction.
const MOVEMENT_FILL: Record<PostureMovementKind, string> = {
  improved: "E6F4EA",
  regressed: "FBE9E7",
  unchanged: "EFEFEF",
  "newly-stated": "E8EEF9",
  "now-unstated": "FBF1E0",
  appeared: "E8EEF9",
  disappeared: "FBF1E0",
};
const MOVEMENT_TEXT: Record<PostureMovementKind, string> = {
  improved: "1A8F5A",
  regressed: "B00020",
  unchanged: "555555",
  "newly-stated": "2D6CDF",
  "now-unstated": "A86700",
  appeared: "2D6CDF",
  disappeared: "A86700",
};
const MOVEMENT_LABEL: Record<PostureMovementKind, string> = {
  improved: "Improved",
  regressed: "Regressed",
  unchanged: "Unchanged",
  "newly-stated": "Newly stated",
  "now-unstated": "No longer stated",
  appeared: "Added front",
  disappeared: "Removed front",
};

// Coherence-shift shading (spec-v13 Thrust C, the advisory companion). Green =
// reconciled (a divergent front closed), red = fractured (a held front split),
// grey = realigned / unchanged (the stating set changed without crossing the
// divergence line, or no change).
const SHIFT_TEXT: Record<CoherenceShift, string> = {
  reconciled: "1A8F5A",
  fractured: "B00020",
  realigned: "555555",
  unchanged: "555555",
};
const SHIFT_LABEL: Record<CoherenceShift, string> = {
  reconciled: "Reconciled",
  fractured: "Fractured",
  realigned: "Realigned",
  unchanged: "Unchanged",
};

/** "ideal → acceptable" style floor transition; "—" for an unstated side. */
function floorTransition(front: CoherenceFrontMovement): string {
  const fmt = (t: NegotiationTier | null): string => (t === null ? "—" : TIER_SHORT_LABEL[t]);
  return `${fmt(front.base_floor)} → ${fmt(front.revised_floor)}`;
}

/**
 * Posture Movement section (spec-v13 Thrust C). A trailing, optional section in
 * a two-round deliverable: one row per negotiation front — Front · Floor
 * movement · Floor (base → revised) · Coherence shift — color-coded by the
 * binding-floor movement. Omitted entirely when no movement was supplied (no
 * baseline round), so every existing bundle golden is byte-unchanged. Advisory:
 * it reports where the bundle's binding floor moved on the team's own ladder and
 * whether the package fractured or reconciled, never that a term became legally
 * adequate or that the weakest document legally governs (spec-v13 §3 corollary 3).
 */
function renderPostureMovementSection(
  movement: CoherenceMovement | undefined,
): (Paragraph | Table)[] {
  if (!movement || movement.fronts.length === 0) return [];
  const fc = movement.floor_counts;
  const sc = movement.shift_counts;
  const out: (Paragraph | Table)[] = [h1("Posture Movement (Across the Package)")];
  out.push(
    para({
      text: "How the team's negotiation posture moved across the whole bundle between the baseline round and this round. Each round was scored against the same positions; this section reports, per front, how the binding floor (the weakest stated rung, which governs exposure across a deal package) moved — and whether the package fractured (a front it agreed on now diverges) or reconciled (a divergent front no longer diverges).",
    }),
  );
  out.push(
    para({
      text: `Binding floor: ${fc.improved} improved · ${fc.regressed} regressed · ${fc.unchanged} unchanged · ${fc["newly-stated"]} newly stated · ${fc["now-unstated"]} no longer stated. Coherence: ${sc.fractured} fractured · ${sc.reconciled} reconciled · ${sc.realigned} realigned.`,
      bold: true,
    }),
  );
  out.push(coverField("Movement hash", movement.movement_hash));
  out.push(spacer());

  const header = headerRow([
    "Front",
    "Floor movement",
    "Binding floor (base → revised)",
    "Coherence shift",
  ]);
  const rows = movement.fronts.map(
    (f) =>
      new TableRow({
        children: [
          styledCell(f.dimension, { bold: true }),
          movementCell(f.floor_movement),
          styledCell(floorTransition(f)),
          shiftCell(f.coherence_shift),
        ],
      }),
  );
  out.push(
    new Table({ width: { size: 100, type: WidthType.PERCENTAGE }, rows: [header, ...rows] }),
  );
  out.push(spacer());
  out.push(
    para({
      text: "Computed deterministically by diffing the two rounds' coherences against your team's same positions — it reports where the binding floor that governs your exposure moved on your own ladder; it is not a legal conclusion and does not assert a term became adequate, enforceable, or that the weakest document legally governs.",
      italics: true,
    }),
  );
  out.push(pageBreak());
  return out;
}

function movementCell(kind: PostureMovementKind): TableCell {
  return new TableCell({
    shading: { type: ShadingType.CLEAR, fill: MOVEMENT_FILL[kind], color: "auto" },
    children: [
      new Paragraph({
        children: [
          new TextRun({
            text: MOVEMENT_LABEL[kind],
            bold: true,
            color: MOVEMENT_TEXT[kind],
            font: DEFAULT_FONT,
            size: BODY_SIZE,
          }),
        ],
      }),
    ],
  });
}

function shiftCell(kind: CoherenceShift): TableCell {
  return new TableCell({
    borders: {
      top: { style: BorderStyle.SINGLE, size: 4, color: "CCCCCC" },
      bottom: { style: BorderStyle.SINGLE, size: 4, color: "CCCCCC" },
      left: { style: BorderStyle.SINGLE, size: 4, color: "CCCCCC" },
      right: { style: BorderStyle.SINGLE, size: 4, color: "CCCCCC" },
    },
    children: [
      new Paragraph({
        children: [
          new TextRun({
            text: SHIFT_LABEL[kind],
            bold: kind === "fractured" || kind === "reconciled",
            color: SHIFT_TEXT[kind],
            font: DEFAULT_FONT,
            size: BODY_SIZE,
          }),
        ],
      }),
    ],
  });
}

function renderCrossDocAppendix(consistency: ConsistencyRun): (Paragraph | Table)[] {
  const out: (Paragraph | Table)[] = [h1("Cross-Document Consistency Appendix")];
  if (consistency.findings.length === 0) {
    out.push(para({ text: "No cross-document inconsistencies were detected.", italics: true }));
    out.push(pageBreak());
    return out;
  }
  const shown = consistency.findings.slice(0, BUNDLE_CROSS_DOC_TOP_N);
  for (const f of shown) {
    out.push(
      para({
        text: `[${f.severity.toUpperCase()}] ${f.rule_id} — ${f.title}`,
        bold: true,
        color: severityColor(f.severity),
      }),
    );
    out.push(para({ text: f.description }));
    out.push(para({ text: f.explanation }));
    if (f.recommendation) {
      out.push(para({ text: `Recommendation: ${f.recommendation}`, bold: true }));
    }
    for (const e of f.excerpts) {
      out.push(
        para({
          text: `  ${e.source_file_name} (${e.section_id ?? "doc"} @ ${e.start_offset}–${e.end_offset}): "${truncate(e.text, 320)}"`,
          italics: true,
        }),
      );
    }
    out.push(spacer());
  }
  const hidden = consistency.findings.length - shown.length;
  if (hidden > 0) {
    out.push(
      para({
        text: `… and ${hidden} more cross-document finding${hidden === 1 ? "" : "s"} not shown here. The complete set is in the bundle JSON (cross_doc_findings).`,
        italics: true,
      }),
    );
  }
  out.push(pageBreak());
  return out;
}

function renderBibliography(
  entries: BundleBibliographyEntry[],
  currency?: import("./citations.js").CitationCurrency,
): Paragraph[] {
  const out: Paragraph[] = [h1("Citation Bibliography")];
  if (entries.length === 0) {
    out.push(para({ text: "No DKB sources were referenced by any finding in this bundle." }));
    out.push(pageBreak());
    return out;
  }
  for (const e of entries) {
    out.push(para({ text: formatBibliographyEntry(e.index, e.source, currency) }));
  }
  out.push(pageBreak());
  return out;
}

function renderAuditTrail(input: BundleReportInput): Paragraph[] {
  const out: Paragraph[] = [h1("Audit Trail")];
  out.push(
    para({
      text: `Engine version: ${input.engine_version ?? input.documents[0]?.run.version ?? "0.0.0"}`,
    }),
  );
  out.push(para({ text: `DKB version: ${input.dkb.manifest.version}` }));
  out.push(para({ text: `Consistency engine version: ${input.consistency.version}` }));
  out.push(spacer());
  out.push(h2("Per-document playbooks"));
  for (const d of input.documents) {
    const deprecationSuffix =
      d.playbook_deprecated === true
        ? d.playbook_superseded_by
          ? ` — legacy; superseded by ${d.playbook_superseded_by}`
          : " — legacy"
        : "";
    out.push(
      para({
        text: `${d.source_file_name} → ${d.run.playbook_id}${d.run.playbook_match_confidence !== undefined ? ` (confidence ${d.run.playbook_match_confidence})` : ""}${deprecationSuffix}`,
      }),
    );
  }
  out.push(spacer());
  out.push(h2("Per-document rule execution"));
  for (const d of input.documents) {
    out.push(para({ text: `— ${d.source_file_name}`, bold: true }));
    for (const e of d.run.execution_log) {
      out.push(
        para({
          text: `${e.rule_id} v${e.rule_version} — ${e.fired ? "fired" : "silent"}${e.fired && e.finding_id ? ` → ${e.finding_id}` : ""} (${formatElapsed(e.elapsed_ms)} ms)`,
        }),
      );
    }
  }
  out.push(spacer());
  out.push(h2("Cross-document rule execution"));
  for (const e of input.consistency.execution_log) {
    out.push(
      para({
        text: `${e.rule_id} v${e.rule_version} — ${e.ran ? `ran, ${plural(e.findings_count, "finding")}` : "skipped (requires not satisfied)"} (${formatElapsed(e.elapsed_ms)} ms)`,
      }),
    );
  }
  out.push(pageBreak());
  return out;
}

function renderDisclaimer(): Paragraph[] {
  return [
    h1("Disclaimer"),
    h3("Determinism"),
    para({ text: DETERMINISM_STATEMENT }),
    spacer(),
    h3("Privacy"),
    para({ text: PRIVACY_STATEMENT }),
    spacer(),
    h3("Not legal advice"),
    para({ text: NON_ADVICE_STATEMENT }),
  ];
}

// ---------------------------------------------------------------------------
// Helpers

type SeverityAggregate = Record<Severity, number>;

function aggregateSeverityCounts(input: BundleReportInput): SeverityAggregate {
  const out: SeverityAggregate = { critical: 0, warning: 0, info: 0 };
  for (const d of input.documents) {
    for (const f of d.run.findings) out[f.severity]++;
  }
  return out;
}

function countConsistency(findings: ConsistencyFinding[]): SeverityAggregate {
  const out: SeverityAggregate = { critical: 0, warning: 0, info: 0 };
  for (const f of findings) out[f.severity]++;
  return out;
}

function countFindings(findings: Finding[]): SeverityAggregate {
  const out: SeverityAggregate = { critical: 0, warning: 0, info: 0 };
  for (const f of findings) out[f.severity]++;
  return out;
}

function pickTop(findings: ReadonlyArray<Finding>, n: number): Finding[] {
  // Findings inside an EngineRun are already sorted (severity, rule_id,
  // document_position) by the runner. Take the first N — that yields
  // the critical findings first, then warnings, then informational,
  // which matches the "top findings" intent in spec §11.
  return findings.slice(0, n);
}

type BundleBibliographyEntry = { index: number; source: SourceCitation; first_doc_id: string };

function buildBundleBibliography(input: BundleReportInput): BundleBibliographyEntry[] {
  const seen = new Map<string, BundleBibliographyEntry>();
  let next = 1;
  for (const d of input.documents) {
    for (const f of d.run.findings) {
      for (const c of f.source_citations) {
        if (seen.has(c.id)) continue;
        seen.set(c.id, { index: next++, source: c, first_doc_id: d.doc_id });
      }
    }
  }
  for (const f of input.consistency.findings) {
    for (const c of f.source_citations) {
      if (seen.has(c.id)) continue;
      seen.set(c.id, { index: next++, source: c, first_doc_id: "(cross-doc)" });
    }
  }
  return [...seen.values()];
}

// ---------------------------------------------------------------------------
// DOCX primitives (kept local — the report layer intentionally avoids a
// shared component module so each renderer is self-contained).

type ParaOpts = {
  text: string;
  bold?: boolean;
  italics?: boolean;
  color?: string;
  size?: number;
  heading?: IParagraphOptions["heading"];
  alignment?: IParagraphOptions["alignment"];
};

function para(opts: ParaOpts): Paragraph {
  return new Paragraph({
    heading: opts.heading,
    alignment: opts.alignment,
    children: [
      new TextRun({
        text: opts.text,
        bold: opts.bold,
        italics: opts.italics,
        color: opts.color,
        font: DEFAULT_FONT,
        size: opts.size ?? BODY_SIZE,
      }),
    ],
  });
}

function coverField(label: string, value: string): Paragraph {
  return new Paragraph({
    children: [
      new TextRun({ text: `${label}: `, bold: true, font: DEFAULT_FONT, size: BODY_SIZE }),
      new TextRun({ text: value, font: DEFAULT_FONT, size: BODY_SIZE }),
    ],
  });
}

function h1(text: string): Paragraph {
  return para({ text, heading: HeadingLevel.HEADING_1, color: MINT, bold: true, size: 32 });
}

function h2(text: string): Paragraph {
  return para({ text, heading: HeadingLevel.HEADING_2, color: MINT, bold: true, size: 28 });
}

function h3(text: string): Paragraph {
  return para({ text, heading: HeadingLevel.HEADING_3, bold: true, size: 24 });
}

function spacer(_count = 1): Paragraph {
  return new Paragraph({ children: [new TextRun({ text: "" })] });
}

function pageBreak(): Paragraph {
  return new Paragraph({ children: [new PageBreak()] });
}

function headerRow(cells: string[]): TableRow {
  return new TableRow({
    children: cells.map(
      (text) =>
        new TableCell({
          shading: { type: ShadingType.CLEAR, fill: MINT, color: "auto" },
          children: [
            new Paragraph({
              children: [
                new TextRun({
                  text,
                  bold: true,
                  color: "FFFFFF",
                  font: DEFAULT_FONT,
                  size: BODY_SIZE,
                }),
              ],
            }),
          ],
        }),
    ),
  });
}

function bodyRow(cells: string[]): TableRow {
  return new TableRow({
    children: cells.map(
      (text) =>
        new TableCell({
          borders: {
            top: { style: BorderStyle.SINGLE, size: 4, color: "CCCCCC" },
            bottom: { style: BorderStyle.SINGLE, size: 4, color: "CCCCCC" },
            left: { style: BorderStyle.SINGLE, size: 4, color: "CCCCCC" },
            right: { style: BorderStyle.SINGLE, size: 4, color: "CCCCCC" },
          },
          children: [
            new Paragraph({
              children: [new TextRun({ text, font: DEFAULT_FONT, size: BODY_SIZE })],
            }),
          ],
        }),
    ),
  });
}

function severityColor(severity: Severity): string {
  switch (severity) {
    case "critical":
      return "B00020";
    case "warning":
      return "A86700";
    case "info":
      return "555555";
  }
}

function truncate(text: string, limit: number): string {
  if (text.length <= limit) return text;
  return text.slice(0, limit - 1) + "…";
}

function plural(n: number, noun: string): string {
  return `${n} ${noun}${n === 1 ? "" : "s"}`;
}

function formatElapsed(ms: number): string {
  return (Math.round(ms * 1000) / 1000).toFixed(3);
}

function formatHumanDate(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toUTCString();
}

// Reserved for future canonicalization hashing inside the bundle (e.g.
// when we add a bundle-level execution-log digest separate from the
// per-doc result hashes). Kept exported as `void` to preserve the import
// without forcing a re-bundle when the hash field lands.
void stableStringify;
