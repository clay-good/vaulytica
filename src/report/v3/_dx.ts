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
} from "docx";
import { breakLongTokens } from "../citations.js";
import { isHttpUrl } from "../../dkb/url-safety.js";
import {
  BODY_SIZE,
  DEFAULT_FONT,
  MINT,
  bodyRow,
  headerRow,
  para,
  type ParaOpts,
} from "../_docx-primitives.js";

// The v3 report modules have imported these from here since they were
// written; the definitions moved out, the door stays where it was.
export { BODY_SIZE, DEFAULT_FONT, MINT, bodyRow, headerRow, para };
export type { ParaOpts };

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

export type CellOpts = {
  fill?: string;
  bold?: boolean;
  color?: string;
  alignment?: IParagraphOptions["alignment"];
};

export function styledCell(text: string, opts: CellOpts = {}): TableCell {
  return new TableCell({
    shading: opts.fill ? { type: ShadingType.CLEAR, fill: opts.fill, color: "auto" } : undefined,
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

/** Build a percentage-width Table from header + body rows. */
export function buildTable(rows: TableRow[]): Table {
  return new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    rows,
  });
}

/** Build a paragraph containing a hyperlink. */
export function hyperlinkParagraph(
  label: string,
  url: string,
  opts: { bold?: boolean; italics?: boolean } = {},
): Paragraph {
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

/**
 * Truncate `text` to `limit` characters with a trailing ellipsis.
 *
 * Never splits a UTF-16 surrogate pair: if the last kept code unit is a lone
 * high surrogate (its low half falls past the cut), drop it — otherwise the
 * packed UTF-8 turns it into a U+FFFD replacement char, corrupting a quoted
 * excerpt exactly at a non-BMP character (emoji, CJK Extension B, …).
 *
 * This lives here, next to the other shared DOCX helpers, because the guard
 * was previously fixed in one place and three stale copies in the v3
 * renderers kept the old splitting behavior.
 */
export function truncate(text: string, limit: number): string {
  if (text.length <= limit) return text;
  let end = limit - 1;
  const lastUnit = text.charCodeAt(end - 1);
  if (lastUnit >= 0xd800 && lastUnit <= 0xdbff) end -= 1;
  return text.slice(0, end) + "…";
}

/** `"1 day"` / `"2 days"` — pluralization-aware count + noun. */
export function plural(n: number, noun: string): string {
  return `${n} ${noun}${n === 1 ? "" : "s"}`;
}
