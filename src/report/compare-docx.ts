/**
 * Comparison report — DOCX builder (spec-v6 Part I §6, Step 90).
 *
 *   Page 1   — Cover (both versions + hashes, comparison hash, determinism,
 *              DKB-mismatch / confirmed-pairing flags)
 *   Page 2   — Executive summary (the risk-surface delta headline)
 *   Page 3+  — Resolved → Introduced → Unchanged findings
 *   Page N   — Clause-level delta appendix (base vs revised text, where the
 *              triggering clause moved between versions)
 *   Final    — Disclaimer
 *
 * Deterministic: built entirely from a {@link Comparison}, which is itself a
 * pure function of two deterministic runs. No wall-clock, no randomness; the
 * same two runs produce a byte-identical document.
 *
 * Visual contract matches the single-document report (US Letter, 1-inch
 * margins, Arial 11pt, mint accent) — see report/docx.ts.
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
  type IRunOptions,
} from "docx";

import type { Finding, Severity } from "../engine/finding.js";
import type { Comparison, SeverityCounts, UnchangedPair } from "./compare.js";
import type { Clause, ClauseDiff } from "./clause-diff.js";

/**
 * Cap on redline rows rendered per category. A pathological redline (a
 * thousand rewritten clauses) would bloat the DOCX; past the cap the report
 * shows the first N and an honest "and X more" footer rather than truncating
 * silently. Real legal redlines are far under this.
 */
const MAX_REDLINE_ROWS = 100;

const MINT = "00A883";
const DEFAULT_FONT = "Arial";
const BODY_SIZE = 22; // half-points = 11pt

const DETERMINISM_STATEMENT =
  "This comparison was produced by a deterministic process. It is the difference between two deterministic Vaulytica runs: given the same two input files, the same engine version, and the same Deterministic Knowledge Base version, this comparison reproduces byte-for-byte on any machine, at any time. The comparison hash above is the SHA-256 of the two run hashes and the canonical delta. No part of this analysis was performed by a language model or any other non-deterministic system.";

const PRIVACY_STATEMENT =
  "Both documents were analyzed entirely inside the user's web browser. Neither file, nor any portion of it, was transmitted to any server. Vaulytica is a static web page with no backend, no database, no analytics, and no telemetry.";

const NON_ADVICE_STATEMENT =
  "Vaulytica is a software tool, not a lawyer. This comparison is a mechanical diff of two rule-engine runs over documents you provided. It is not legal advice, and using Vaulytica does not create an attorney-client relationship with anyone. The decision to act on any change shown here, or not, is yours and your counsel's.";

export async function buildComparisonDocx(cmp: Comparison, clauseDiff?: ClauseDiff): Promise<Blob> {
  const children: (Paragraph | Table)[] = [
    ...renderCover(cmp),
    ...renderExecutiveSummary(cmp),
    ...renderBucket("Resolved", "Findings that fired on the base version and are absent on the revised version — these edits fixed an issue.", cmp.delta.resolved),
    ...renderBucket("Introduced", "Findings absent on the base version that fired on the revised version — these edits created an issue.", cmp.delta.introduced),
    ...renderUnchangedBucket(cmp.delta.unchanged),
    ...renderClauseDeltaAppendix(cmp.delta.unchanged),
    ...(clauseDiff ? renderRedline(clauseDiff) : []),
    ...renderDisclaimer(),
  ];

  const doc = new Document({
    creator: "Vaulytica",
    title: "Vaulytica Comparison Report",
    description: "Deterministic version comparison",
    styles: { default: { document: { run: { font: DEFAULT_FONT, size: BODY_SIZE } } } },
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
// Cover
// ---------------------------------------------------------------------------

function renderCover(cmp: Comparison): Paragraph[] {
  const out: Paragraph[] = [
    para({ text: "Vaulytica Comparison Report", heading: HeadingLevel.TITLE, color: MINT, alignment: AlignmentType.CENTER }),
    spacer(),
    coverField("Base version", cmp.base.name),
    coverField("Base result hash", cmp.base.result_hash),
    coverField("Revised version", cmp.revised.name),
    coverField("Revised result hash", cmp.revised.result_hash),
    coverField("Comparison hash", cmp.result_hash),
    coverField("DKB version", cmp.dkb_mismatch ? `${cmp.base.dkb_version} → ${cmp.revised.dkb_version} (MISMATCH)` : cmp.base.dkb_version),
    coverField("Family", cmp.family_mismatch ? `${cmp.base.playbook_id} vs ${cmp.revised.playbook_id} (pairing confirmed by user)` : cmp.base.playbook_id),
  ];
  if (cmp.dkb_mismatch) {
    out.push(spacer());
    out.push(para({
      text: "Warning: the two runs used different DKB versions, so this comparison is not strictly apples-to-apples — a finding may differ because the underlying authority changed, not because the document did.",
      bold: true,
      color: "A86700",
    }));
  }
  out.push(spacer());
  out.push(para({ text: DETERMINISM_STATEMENT, italics: true }));
  out.push(spacer(2));
  out.push(para({ text: "Vaulytica", color: MINT, bold: true, alignment: AlignmentType.CENTER }));
  out.push(pageBreak());
  return out;
}

function coverField(label: string, value: string): Paragraph {
  return new Paragraph({
    children: [
      new TextRun({ text: `${label}: `, bold: true, font: DEFAULT_FONT, size: BODY_SIZE }),
      new TextRun({ text: value, font: DEFAULT_FONT, size: BODY_SIZE }),
    ],
  });
}

// ---------------------------------------------------------------------------
// Executive summary
// ---------------------------------------------------------------------------

function renderExecutiveSummary(cmp: Comparison): (Paragraph | Table)[] {
  const { resolved, introduced, unchanged } = cmp.delta.counts;
  const headline =
    `This revision resolved ${countPhrase(resolved)}, introduced ${countPhrase(introduced)}, ` +
    `and left ${countPhrase(unchanged)} unchanged. ` +
    `${cmp.delta.carried_clean_count} rule${cmp.delta.carried_clean_count === 1 ? "" : "s"} fired on neither version (no regression).`;

  const verdict =
    introduced.total === 0 && resolved.total === 0
      ? "No change to the risk surface: this revision neither resolved nor introduced any finding."
      : introduced.critical > 0
        ? "Read the Introduced section first — this revision created at least one critical finding."
        : resolved.total > introduced.total
          ? "Net improvement: this revision resolved more findings than it introduced."
          : introduced.total > resolved.total
            ? "Net regression: this revision introduced more findings than it resolved."
            : "Mixed: this revision resolved and introduced an equal number of findings.";

  return [
    h1("Executive Summary"),
    para({ text: verdict, bold: true }),
    spacer(),
    para({ text: headline }),
    spacer(),
    deltaTable(cmp.delta.counts),
    pageBreak(),
  ];
}

function deltaTable(counts: { resolved: SeverityCounts; introduced: SeverityCounts; unchanged: SeverityCounts }): Table {
  const row = (label: string, c: SeverityCounts) =>
    bodyRow([label, String(c.critical), String(c.warning), String(c.info), String(c.total)]);
  return new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    rows: [
      headerRow(["Bucket", "Critical", "Warning", "Info", "Total"]),
      row("Resolved", counts.resolved),
      row("Introduced", counts.introduced),
      row("Unchanged", counts.unchanged),
    ],
  });
}

// ---------------------------------------------------------------------------
// Buckets
// ---------------------------------------------------------------------------

function renderBucket(heading: string, blurb: string, findings: Finding[]): (Paragraph | Table)[] {
  const out: (Paragraph | Table)[] = [h1(`${heading} (${findings.length})`), para({ text: blurb, italics: true })];
  if (findings.length === 0) {
    out.push(para({ text: "None.", italics: true }));
    out.push(pageBreak());
    return out;
  }
  for (const f of findings) out.push(...renderFinding(f));
  out.push(pageBreak());
  return out;
}

function renderUnchangedBucket(unchanged: UnchangedPair[]): (Paragraph | Table)[] {
  const out: (Paragraph | Table)[] = [
    h1(`Unchanged (${unchanged.length})`),
    para({ text: "Findings that fired on both versions — still open after this revision.", italics: true }),
  ];
  if (unchanged.length === 0) {
    out.push(para({ text: "None.", italics: true }));
    out.push(pageBreak());
    return out;
  }
  for (const u of unchanged) {
    out.push(...renderFinding(u.finding));
    if (u.clause_changed) {
      out.push(para({
        text: "The triggering clause text changed between versions, but the finding still fires — see the clause-level delta appendix.",
        italics: true,
        color: "A86700",
      }));
      out.push(spacer());
    }
  }
  out.push(pageBreak());
  return out;
}

function renderFinding(f: Finding): Paragraph[] {
  return [
    para({ text: f.title, bold: true, size: 26 }),
    para({ text: `[${f.severity.toUpperCase()}] ${f.description}`, color: severityColor(f.severity), bold: true }),
    para({
      text: `Clause (${f.excerpt.section_id ?? "doc"}): "${truncate(f.excerpt.text, 360)}"`,
      italics: true,
    }),
    para({ text: f.explanation }),
    spacer(),
  ];
}

// ---------------------------------------------------------------------------
// Clause-level delta appendix (spec-v6 §5 — text diff of two extracted spans)
// ---------------------------------------------------------------------------

function renderClauseDeltaAppendix(unchanged: UnchangedPair[]): (Paragraph | Table)[] {
  const changed = unchanged.filter((u) => u.clause_changed);
  const out: (Paragraph | Table)[] = [
    h1("Clause-level delta"),
    para({
      text: "For findings that fired on both versions, the triggering clause text below moved between the base and revised documents. This is a verbatim comparison of the two extracted spans — no generated language.",
    }),
  ];
  if (changed.length === 0) {
    out.push(para({ text: "No unchanged finding's triggering clause changed text between versions.", italics: true }));
    out.push(pageBreak());
    return out;
  }
  for (const u of changed) {
    out.push(para({ text: `${u.rule_id} — ${u.finding.title}`, bold: true, size: 24 }));
    out.push(new Table({
      width: { size: 100, type: WidthType.PERCENTAGE },
      rows: [
        headerRow(["Base", "Revised"]),
        bodyRow([truncate(u.base_finding.excerpt.text, 600), truncate(u.finding.excerpt.text, 600)]),
      ],
    }));
    out.push(spacer());
  }
  out.push(pageBreak());
  return out;
}

// ---------------------------------------------------------------------------
// Document redline — full clause-level text diff (spec-v8 Part XVIII)
// ---------------------------------------------------------------------------

function clauseLabel(c: Clause): string {
  return c.heading ? `${c.heading} (${c.id})` : c.id;
}

function renderRedline(diff: ClauseDiff): (Paragraph | Table)[] {
  const out: (Paragraph | Table)[] = [
    h1("Document Redline"),
    para({
      text:
        "A clause-level text diff of the two documents — which paragraphs were added, removed, or rewritten between the base and the revised version. This is a verbatim comparison of the documents' own text (deterministic LCS alignment), independent of the findings above. No generated language.",
    }),
    para({
      text:
        `${diff.changed.length} changed · ${diff.added.length} added · ${diff.removed.length} removed · ` +
        `${diff.unchanged_count} unchanged (base ${diff.base_clause_count} clauses → revised ${diff.revised_clause_count}).`,
      bold: true,
    }),
  ];
  if (diff.truncated) {
    out.push(para({
      text: "Note: the documents were large enough that a full alignment was not computed; rewrites are listed as a separate add and remove rather than paired, and clause order is not considered.",
      italics: true,
      color: "A86700",
    }));
  }
  if (diff.changed.length + diff.added.length + diff.removed.length === 0) {
    out.push(para({ text: "No clause-level text changes between the two documents.", italics: true }));
    out.push(pageBreak());
    return out;
  }

  if (diff.changed.length > 0) {
    out.push(h3("Rewritten clauses"));
    for (const pair of diff.changed.slice(0, MAX_REDLINE_ROWS)) {
      out.push(para({ text: clauseLabel(pair.revised), bold: true, size: 24 }));
      out.push(new Table({
        width: { size: 100, type: WidthType.PERCENTAGE },
        rows: [
          headerRow(["Base", "Revised"]),
          bodyRow([truncate(pair.base.text, 600), truncate(pair.revised.text, 600)]),
        ],
      }));
      out.push(spacer());
    }
    pushOverflowNote(out, diff.changed.length, "rewritten clauses");
  }

  if (diff.added.length > 0) {
    out.push(h3("Added clauses"));
    for (const c of diff.added.slice(0, MAX_REDLINE_ROWS)) {
      out.push(para({ text: `+ [${clauseLabel(c)}] ${truncate(c.text, 600)}`, color: "1A7A4C" }));
    }
    pushOverflowNote(out, diff.added.length, "added clauses");
  }

  if (diff.removed.length > 0) {
    out.push(h3("Removed clauses"));
    for (const c of diff.removed.slice(0, MAX_REDLINE_ROWS)) {
      out.push(para({ text: `− [${clauseLabel(c)}] ${truncate(c.text, 600)}`, color: "B00020" }));
    }
    pushOverflowNote(out, diff.removed.length, "removed clauses");
  }

  out.push(pageBreak());
  return out;
}

function pushOverflowNote(out: (Paragraph | Table)[], total: number, label: string): void {
  if (total > MAX_REDLINE_ROWS) {
    out.push(para({
      text: `… and ${total - MAX_REDLINE_ROWS} more ${label} (showing the first ${MAX_REDLINE_ROWS}).`,
      italics: true,
    }));
  }
  out.push(spacer());
}

// ---------------------------------------------------------------------------
// Disclaimer
// ---------------------------------------------------------------------------

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
// Primitives (mirror report/docx.ts)
// ---------------------------------------------------------------------------

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
  return new Paragraph({ heading: opts.heading, alignment: opts.alignment, children: [new TextRun(runOpts)] });
}

function h1(text: string): Paragraph {
  return para({ text, heading: HeadingLevel.HEADING_1, color: MINT, bold: true, size: 32 });
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
          children: [new Paragraph({ children: [new TextRun({ text, bold: true, color: "FFFFFF", font: DEFAULT_FONT, size: BODY_SIZE })] })],
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
          children: [new Paragraph({ children: [new TextRun({ text, font: DEFAULT_FONT, size: BODY_SIZE })] })],
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

function countPhrase(c: SeverityCounts): string {
  if (c.total === 0) return "no findings";
  const parts: string[] = [];
  if (c.critical) parts.push(`${c.critical} critical`);
  if (c.warning) parts.push(`${c.warning} warning${c.warning === 1 ? "" : "s"}`);
  if (c.info) parts.push(`${c.info} info`);
  return `${c.total} finding${c.total === 1 ? "" : "s"} (${parts.join(", ")})`;
}

/** Blob convenience, matching report/json.ts and exports.ts patterns. */
export function comparisonDocxBlob(cmp: Comparison, clauseDiff?: ClauseDiff): Promise<Blob> {
  return buildComparisonDocx(cmp, clauseDiff);
}
