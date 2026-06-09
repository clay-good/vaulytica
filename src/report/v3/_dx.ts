/**
 * Shared DOCX primitives for the v3 report sections.
 *
 * These mirror the small helpers in `src/report/docx.ts` so the v3 sections
 * compose visually with the v2 report (same font, sizes, mint accent, table
 * shading). Kept private to `src/report/v3/` to avoid widening the public
 * `src/report/index.ts` API.
 */

import {
  AlignmentType,
  BorderStyle,
  ExternalHyperlink,
  HeadingLevel,
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
import { breakLongTokens } from "../citations.js";
import { isHttpUrl } from "../../dkb/url-safety.js";

export const MINT = "00A883";
export const DEFAULT_FONT = "Arial";
export const BODY_SIZE = 22; // half-points = 11pt

export type ParaOpts = {
  text: string;
  bold?: boolean;
  italics?: boolean;
  color?: string;
  size?: number;
  heading?: IParagraphOptions["heading"];
  alignment?: IParagraphOptions["alignment"];
};

export function para(opts: ParaOpts): Paragraph {
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

export function h1(text: string): Paragraph {
  return para({ text, heading: HeadingLevel.HEADING_1, color: MINT, bold: true, size: 32 });
}

export function h2(text: string): Paragraph {
  return para({ text, heading: HeadingLevel.HEADING_2, color: MINT, bold: true, size: 28 });
}

export function h3(text: string): Paragraph {
  return para({ text, heading: HeadingLevel.HEADING_3, bold: true, size: 24 });
}

export function spacer(): Paragraph {
  return new Paragraph({ children: [new TextRun({ text: "" })] });
}

export function pageBreak(): Paragraph {
  return new Paragraph({ children: [new PageBreak()] });
}

export function headerRow(cells: string[]): TableRow {
  return new TableRow({
    tableHeader: true,
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

export type CellOpts = {
  fill?: string;
  bold?: boolean;
  color?: string;
  alignment?: IParagraphOptions["alignment"];
};

export function styledCell(text: string, opts: CellOpts = {}): TableCell {
  return new TableCell({
    shading: opts.fill
      ? { type: ShadingType.CLEAR, fill: opts.fill, color: "auto" }
      : undefined,
    borders: {
      top: { style: BorderStyle.SINGLE, size: 4, color: "CCCCCC" },
      bottom: { style: BorderStyle.SINGLE, size: 4, color: "CCCCCC" },
      left: { style: BorderStyle.SINGLE, size: 4, color: "CCCCCC" },
      right: { style: BorderStyle.SINGLE, size: 4, color: "CCCCCC" },
    },
    children: [
      new Paragraph({
        alignment: opts.alignment ?? AlignmentType.LEFT,
        children: [
          new TextRun({
            text,
            bold: opts.bold,
            color: opts.color,
            font: DEFAULT_FONT,
            size: BODY_SIZE,
          }),
        ],
      }),
    ],
  });
}

export function bodyRow(cells: string[]): TableRow {
  return new TableRow({
    children: cells.map((t) => styledCell(t)),
  });
}

/** Build a percentage-width Table from header + body rows. */
export function buildTable(rows: TableRow[]): Table {
  return new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    rows,
  });
}

/** Build a paragraph containing a hyperlink. */
export function hyperlinkParagraph(label: string, url: string, opts: { bold?: boolean; italics?: boolean } = {}): Paragraph {
  // Split the (often long) URL label into wrap-friendly runs so Word can
  // break it at the cell margin rather than overflow the page (spec-v8 §18).
  // The concatenated run text equals `label` exactly — never truncated.
  // Only an http(s) URL becomes an active ExternalHyperlink; an unsafe scheme
  // (javascript:/data:) renders as plain text so a shared DOCX carries no
  // executable link — the output-boundary half of the URL-safety policy.
  const safe = isHttpUrl(url);
  const runs = breakLongTokens(label).map(
    (seg) =>
      new TextRun({
        text: seg,
        style: safe ? "Hyperlink" : undefined,
        color: safe ? "0563C1" : undefined,
        underline: safe ? {} : undefined,
        font: DEFAULT_FONT,
        size: BODY_SIZE,
        bold: opts.bold,
        italics: opts.italics,
      }),
  );
  return new Paragraph({
    children: safe ? [new ExternalHyperlink({ link: url, children: runs })] : runs,
  });
}
