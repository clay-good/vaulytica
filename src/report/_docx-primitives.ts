/**
 * The DOCX primitives every report builder shares.
 *
 * `v3/_dx.ts` has exported the brand colour, the font, the body size and
 * `para` since it was written — and `docx.ts`, `compare-docx.ts` and
 * `bundle.ts` each declared their own `MINT = "00A883"`, their own
 * `DEFAULT_FONT`, their own `ParaOpts`, and a byte-identical `para`,
 * `headerRow` and `bodyRow` beside them. Four copies of a brand colour is four
 * chances for one report to be a different green from another, and the
 * duplicate-body sweep found the functions the same way it found `findDenial`.
 *
 * A DOCX table header is not formatting the reader can shrug at: the bundle
 * report and the single-document report are the same product, and a heading
 * row styled one way in one and another way in the other is the kind of
 * difference nobody notices until a client does.
 */
import {
  BorderStyle,
  Paragraph,
  ShadingType,
  TableCell,
  TableRow,
  TextRun,
  type IParagraphOptions,
  type IRunOptions,
} from "docx";

/** The brand mint. One definition, so every report is the same green. */
export const MINT = "00A883";
export const DEFAULT_FONT = "Arial";
/** Half-points: 22 = 11pt. */
export const BODY_SIZE = 22;

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

/**
 * A table's heading row: white on mint, bold.
 *
 * `tableHeader` marks the row as one Word REPEATS at the top of each page when
 * the table spans a page break. The bundle's compliance matrix needs that and
 * open-coded the whole row to get it.
 */
export function headerRow(cells: string[], tableHeader = false): TableRow {
  return new TableRow({
    tableHeader,
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

/** A table's body row: hairline borders on every side. */
export function bodyRow(cells: string[]): TableRow {
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
