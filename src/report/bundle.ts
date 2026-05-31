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
import { formatBibliographyEntry } from "./citations.js";
import {
  buildPortfolioMatrix,
  portfolioFingerprint,
  type PortfolioMatrix,
  type PortfolioStatus,
} from "./portfolio.js";

const MINT = "00A883";
const DEFAULT_FONT = "Arial";
const BODY_SIZE = 22;

/** Cap on per-document findings surfaced in the consolidated DOCX (spec §11). */
export const BUNDLE_TOP_N = 10;

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
};

/**
 * Bundle fingerprint per spec §11: sorted SHA-256 of file hashes
 * (encoded via the per-document `result_hash`, which itself folds in
 * the source file SHA-256) joined by a single newline and re-hashed.
 */
export async function bundleFingerprint(per_doc_result_hashes: ReadonlyArray<string>): Promise<string> {
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
    ...renderBibliography(bibliography),
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
    para({ text: "Vaulytica Bundle Report", heading: HeadingLevel.TITLE, color: MINT, bold: true, alignment: AlignmentType.CENTER }),
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
              children: [new TextRun({ text, bold: true, color: "FFFFFF", font: DEFAULT_FONT, size: BODY_SIZE })],
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
  out.push(new Table({ width: { size: 100, type: WidthType.PERCENTAGE }, rows: [header, ...dataRows] }));
  out.push(spacer());

  if (matrix.truncated) {
    out.push(
      para({
        text: `Note: this bundle contains ${matrix.total} documents; the matrix shows the first ${matrix.included} (sorted by file name). The portfolio cap is ${matrix.included} rows.`,
        italics: true,
      }),
    );
  } else {
    out.push(para({ text: `${matrix.total} ${matrix.total === 1 ? "document" : "documents"} included.`, italics: true }));
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
    out.push(spacer());
  }
  out.push(pageBreak());
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

function renderCrossDocAppendix(consistency: ConsistencyRun): (Paragraph | Table)[] {
  const out: (Paragraph | Table)[] = [h1("Cross-Document Consistency Appendix")];
  if (consistency.findings.length === 0) {
    out.push(para({ text: "No cross-document inconsistencies were detected.", italics: true }));
    out.push(pageBreak());
    return out;
  }
  for (const f of consistency.findings) {
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
  out.push(pageBreak());
  return out;
}

function renderBibliography(entries: BundleBibliographyEntry[]): Paragraph[] {
  const out: Paragraph[] = [h1("Citation Bibliography")];
  if (entries.length === 0) {
    out.push(para({ text: "No DKB sources were referenced by any finding in this bundle." }));
    out.push(pageBreak());
    return out;
  }
  for (const e of entries) {
    out.push(para({ text: formatBibliographyEntry(e.index, e.source) }));
  }
  out.push(pageBreak());
  return out;
}

function renderAuditTrail(input: BundleReportInput): Paragraph[] {
  const out: Paragraph[] = [h1("Audit Trail")];
  out.push(para({ text: `Engine version: ${input.engine_version ?? input.documents[0]?.run.version ?? "0.0.0"}` }));
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
              children: [new TextRun({ text, bold: true, color: "FFFFFF", font: DEFAULT_FONT, size: BODY_SIZE })],
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
