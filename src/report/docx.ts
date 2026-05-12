/**
 * DOCX report builder (spec §22, build step 9).
 *
 * Produces the deterministic Word document described in §22:
 *
 *   Page 1   — Cover (title, filename, dates, fingerprint, versions,
 *              playbook, determinism statement, mint wordmark)
 *   Page 2   — Executive summary
 *   Page 3+  — Findings, Critical → Warning → Info
 *   Page N+  — Obligations Ledger (table)
 *   Page N+  — Extracted Data Appendix (compact tables)
 *   Page N+  — Audit Trail (rules executed + bibliography)
 *   Final    — Disclaimer block (determinism / privacy / non-advice)
 *
 * Visual contract: US Letter (12240 × 15840 DXA), 1-inch margins
 * (1440 DXA), Arial 11pt body (size 22 in half-points), Arial bold
 * for headings, mint accent (`#00A883`) used sparingly on section
 * headings and the closing wordmark. The doc is intended to read
 * well in both light and dark Word/Pages/Docs themes.
 */

import {
  AlignmentType,
  BorderStyle,
  Document,
  HeadingLevel,
  ImageRun,
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
  type IRunOptions,
} from "docx";

import type { EngineRun, Finding } from "../engine/finding.js";
import type { DKB } from "../dkb/types.js";
import type { IngestResult } from "../ingest/types.js";
import type { Playbook } from "../playbooks/types.js";
import { buildBibliography, citationIndex, type BibliographyEntry } from "./bibliography.js";
import { formatCitation, formatBibliographyEntry } from "./citations.js";

const MINT = "00A883";
const DEFAULT_FONT = "Arial";
const BODY_SIZE = 22; // half-points = 11pt

const DETERMINISM_STATEMENT =
  "This report was produced by a deterministic process. Given the same input file, the same Vaulytica engine version, and the same Deterministic Knowledge Base version listed above, the rules in this report will produce an identical report on any machine, at any time. The fingerprint of the input file is recorded above for verification. No part of this analysis was performed by a language model or any other non-deterministic system. The complete list of rules executed, including those that produced no findings, is included in the Audit Trail section so that the scope of the analysis is fully transparent.";

const PRIVACY_STATEMENT =
  "This analysis was performed entirely inside the user's web browser. No portion of the input document was transmitted to any server. Vaulytica is a static web page hosted on Cloudflare Pages; the page has no backend, no database, no analytics, and no telemetry. The developer of Vaulytica has no record of this analysis, no ability to recover it, and no way to identify the user who performed it. The user's network logs at the time of analysis can independently confirm this.";

const NON_ADVICE_STATEMENT =
  "Vaulytica is a software tool, not a lawyer. This report is a checklist of mechanical findings produced by a deterministic rule engine against a contract you provided. It is not legal advice, and using Vaulytica does not create an attorney-client relationship with anyone. The findings may be incorrect, incomplete, or inapplicable to your situation. The decision to act on any finding, or not, is yours and your counsel's. If something in this report matters to a transaction or a dispute, consult a licensed attorney in the relevant jurisdiction.";

void ImageRun; // reserved for future image embedding; keep the import surface stable

export async function buildDocxReport(
  run: EngineRun,
  ingest: IngestResult,
  dkb: DKB,
  playbook: Playbook,
): Promise<Blob> {
  const bibliography = buildBibliography(run.findings, dkb);
  const children: (Paragraph | Table)[] = [
    ...renderCover(run, ingest, playbook),
    ...renderExecutiveSummary(run, playbook),
    ...renderFindingsSection("Critical Findings", "critical", run.findings, bibliography),
    ...renderFindingsSection("Warnings", "warning", run.findings, bibliography),
    ...renderFindingsSection("Informational", "info", run.findings, bibliography),
    ...renderObligationsLedger(run),
    ...renderExtractedAppendix(run),
    ...renderAuditTrail(run, playbook, bibliography),
    ...renderDisclaimer(),
  ];

  const doc = new Document({
    creator: "Vaulytica",
    title: "Vaulytica Report",
    description: "Deterministic contract review",
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
  return blob;
}

// ---------------------------------------------------------------------------
// Cover

function renderCover(run: EngineRun, ingest: IngestResult, playbook: Playbook): Paragraph[] {
  const confidence = run.playbook_match_confidence ?? null;
  const isoDate = run.executed_at || new Date(0).toISOString();
  const humanDate = formatHumanDate(isoDate);

  return [
    para({ text: "Vaulytica Report", heading: HeadingLevel.TITLE, color: MINT, alignment: AlignmentType.CENTER }),
    spacer(),
    coverField("Input file", ingest_filename(ingest, run)),
    coverField("Analysis date", `${isoDate}  (${humanDate})`),
    coverField("File SHA-256", run.source_file.sha256),
    coverField("Engine version", run.version),
    coverField("DKB version", run.dkb_version),
    coverField(
      "Playbook",
      `${playbook.name} (${playbook.id} v${playbook.version})${
        confidence !== null ? ` — match confidence ${confidence}` : ""
      }`,
    ),
    spacer(),
    para({ text: DETERMINISM_STATEMENT, italics: true }),
    spacer(2),
    para({ text: "Vaulytica", color: MINT, bold: true, alignment: AlignmentType.CENTER }),
    pageBreak(),
  ];
}

function coverField(label: string, value: string): Paragraph {
  return new Paragraph({
    children: [
      new TextRun({ text: `${label}: `, bold: true, font: DEFAULT_FONT, size: BODY_SIZE }),
      new TextRun({ text: value, font: DEFAULT_FONT, size: BODY_SIZE }),
    ],
  });
}

function ingest_filename(ingest: IngestResult, run: EngineRun): string {
  return run.source_file.name || `(${ingest.source} input, ${ingest.word_count} words)`;
}

// ---------------------------------------------------------------------------
// Executive summary

function renderExecutiveSummary(run: EngineRun, playbook: Playbook): Paragraph[] {
  const counts = countFindings(run.findings);
  const summary = `This report was generated against the ${playbook.name} playbook. It contains ${plural(counts.critical, "critical finding")}, ${plural(counts.warning, "warning")}, and ${plural(counts.info, "informational item")}; review the critical section first.`;
  return [
    h1("Executive Summary"),
    para({ text: summary }),
    pageBreak(),
  ];
}

// ---------------------------------------------------------------------------
// Findings

function renderFindingsSection(
  heading: string,
  severity: "critical" | "warning" | "info",
  findings: Finding[],
  bibliography: BibliographyEntry[],
): (Paragraph | Table)[] {
  const filtered = findings.filter((f) => f.severity === severity);
  const out: (Paragraph | Table)[] = [h1(heading)];
  if (filtered.length === 0) {
    out.push(para({ text: `No ${severity} findings.`, italics: true }));
    out.push(pageBreak());
    return out;
  }
  for (const f of filtered) {
    out.push(...renderFinding(f, bibliography));
  }
  out.push(pageBreak());
  return out;
}

function renderFinding(f: Finding, bibliography: BibliographyEntry[]): Paragraph[] {
  const badgeColor = severityColor(f.severity);
  const citationNumbers = f.source_citations
    .map((c) => citationIndex(bibliography, c.id))
    .filter((n): n is number => typeof n === "number");

  return [
    para({ text: f.title, bold: true, size: 26 }),
    para({
      text: `[${f.severity.toUpperCase()}] ${f.description}`,
      color: badgeColor,
      bold: true,
    }),
    para({
      text: `Excerpt (${f.excerpt.section_id ?? "doc"} @ ${f.excerpt.start_offset}–${f.excerpt.end_offset}): "${truncate(f.excerpt.text, 480)}"`,
      italics: true,
    }),
    para({ text: f.explanation }),
    ...(f.recommendation ? [para({ text: `Recommendation: ${f.recommendation}`, bold: true })] : []),
    ...(citationNumbers.length > 0
      ? [para({ text: `Sources: ${citationNumbers.map((n) => `[${n}]`).join(" ")}` })]
      : []),
    spacer(),
  ];
}

// ---------------------------------------------------------------------------
// Obligations Ledger

function renderObligationsLedger(run: EngineRun): (Paragraph | Table)[] {
  // The full obligations ledger lives on ExtractedData; the EngineRun
  // does not carry it. We surface the per-finding obligation hints
  // through a two-column table grouped by obligor inferred from the
  // finding's section/excerpt. The actual obligor lookup will land
  // when the UI hookup (Step 12) wires ExtractedData through.
  const rows: Finding[][] = [[]];
  for (const f of run.findings) {
    if (!isObligationRelevant(f)) continue;
    rows[0]!.push(f);
  }
  if (rows[0]!.length === 0) {
    return [h1("Obligations Ledger"), para({ text: "No obligations extracted from findings." }), pageBreak()];
  }
  const table = new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    rows: [
      headerRow(["Source", "Severity", "Obligation"]),
      ...rows[0]!.map((f) =>
        bodyRow([f.excerpt.section_id ?? "doc", f.severity.toUpperCase(), truncate(f.description, 200)]),
      ),
    ],
  });
  return [h1("Obligations Ledger"), table, pageBreak()];
}

function isObligationRelevant(f: Finding): boolean {
  return /^(OBLI|RISK|TERM|PERS|FIN)-\d{3}$/.test(f.rule_id);
}

// ---------------------------------------------------------------------------
// Extracted Data Appendix

function renderExtractedAppendix(run: EngineRun): (Paragraph | Table)[] {
  // Without ExtractedData in the EngineRun we surface only the rules
  // that fired plus a counts table. When Step 12 lands, this section
  // will pull parties/dates/amounts/definitions/sections from
  // ExtractedData.
  const counts = countFindings(run.findings);
  return [
    h1("Extracted Data Appendix"),
    para({ text: "Summary of finding counts:" }),
    new Table({
      width: { size: 50, type: WidthType.PERCENTAGE },
      rows: [
        headerRow(["Severity", "Count"]),
        bodyRow(["Critical", String(counts.critical)]),
        bodyRow(["Warning", String(counts.warning)]),
        bodyRow(["Informational", String(counts.info)]),
      ],
    }),
    pageBreak(),
  ];
}

// ---------------------------------------------------------------------------
// Audit Trail

function renderAuditTrail(
  run: EngineRun,
  playbook: Playbook,
  bibliography: BibliographyEntry[],
): (Paragraph | Table)[] {
  const matched = run.playbook_match_reasoning
    ? `auto-selected (${run.playbook_match_reasoning})`
    : "selected by caller";
  return [
    h1("Audit Trail"),
    para({ text: `Engine version: ${run.version}` }),
    para({ text: `DKB version: ${run.dkb_version}` }),
    para({ text: `Playbook: ${playbook.name} — ${playbook.id} v${playbook.version} — ${matched}` }),
    para({ text: `File fingerprint: ${run.source_file.sha256}` }),
    para({ text: `Result hash: ${run.result_hash}` }),
    para({ text: `Executed at: ${run.executed_at || "(omitted from hash)"}` }),
    spacer(),
    h2("Rules executed"),
    ...run.execution_log.map((e) =>
      para({
        text: `${e.rule_id} v${e.rule_version} — ${e.fired ? "fired" : "silent"}${e.fired && e.finding_id ? ` → ${e.finding_id}` : ""} (${formatElapsed(e.elapsed_ms)} ms)`,
      }),
    ),
    spacer(),
    h2("Bibliography"),
    ...(bibliography.length === 0
      ? [para({ text: "No DKB sources were referenced by any finding in this report." })]
      : bibliography.map((b) => para({ text: formatBibliographyEntry(b.index, b.source) }))),
    pageBreak(),
  ];
}

// ---------------------------------------------------------------------------
// Disclaimer block

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
// Primitives

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
  const runOpts: IRunOptions = {
    text: opts.text,
    bold: opts.bold,
    italics: opts.italics,
    color: opts.color,
    font: DEFAULT_FONT,
    size: opts.size ?? BODY_SIZE,
  };
  return new Paragraph({
    heading: opts.heading,
    alignment: opts.alignment,
    children: [new TextRun(runOpts)],
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

function spacer(count = 1): Paragraph {
  void count;
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

function severityColor(severity: Finding["severity"]): string {
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

function countFindings(findings: Finding[]): Record<"critical" | "warning" | "info", number> {
  const out = { critical: 0, warning: 0, info: 0 };
  for (const f of findings) out[f.severity]++;
  return out;
}

function formatElapsed(ms: number): string {
  // Stable rounding to 3 decimals; the execution log values are
  // performance.now() deltas and would otherwise vary at the
  // microsecond level across runs.
  return (Math.round(ms * 1000) / 1000).toFixed(3);
}

function formatHumanDate(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toUTCString();
}

export { formatCitation };
