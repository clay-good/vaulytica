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

/**
 * The document-default run style every DOCX this tool writes starts from.
 *
 * 🚨 `language` is the reason this is a shared constant rather than three
 * inline objects. All three producers — the per-document report, the
 * comparison report and the bundle — set the same font and size and declared
 * **no language at all**, so no `<w:lang/>` reached any produced file.
 *
 * A screen reader needs it. WCAG 2.2 SC 3.1.1 (Language of Page) is **Level
 * A** precisely because, with no language declared, Narrator and VoiceOver
 * read the text through whatever voice the user's system defaults to: an
 * English legal report spoken by a German or French phonetic engine is close
 * to unintelligible. Nothing in the report's appearance reveals it, which is
 * why it survived — a sighted reader sees a perfectly normal document.
 *
 * `en-US` describes the REPORT's own prose, which is American English
 * whatever language the document under review is written in.
 *
 * Written once so the three cannot drift: the same reason `headerRow` below
 * takes no flag and `truncate` has a single owner.
 */
export const DOCUMENT_DEFAULT_RUN = {
  font: DEFAULT_FONT,
  size: BODY_SIZE,
  language: { value: "en-US" },
} as const;

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
 * A table's heading row: white on mint, bold, and MARKED as a heading row.
 *
 * 🚨 `tableHeader` used to default to FALSE, with one caller passing `true`.
 * The `docx` library writes the flag either way, so every table in every
 * report carried `<w:tblHeader w:val="false"/>` — the header row explicitly
 * declared NOT to be a header row, nine times in a single per-document
 * report. Two consequences, both for the reader:
 *
 *   - **A screen reader does not announce the column headers.** Narrator and
 *     VoiceOver read a data cell as "Delaware" rather than "Governing law,
 *     Delaware", because nothing tells them which row holds the headings.
 *   - **Word does not repeat the row across a page break.** A findings index
 *     or an obligations ledger that runs onto a second page shows unlabelled
 *     columns there.
 *
 * BUILD_PROGRESS step 37 recorded this surface as covered, citing the v3
 * compliance matrix's `tableHeader: true` — and that is the one table in the
 * tree that is never rendered (see `report/v3/inputs.ts`: deriving its cells
 * needs a legal judgment, so the section is deliberately not built). The claim
 * described a table nobody receives while all nine that ship said `false`.
 *
 * 🥇 Counting the element was not enough to see it: nine tables produced nine
 * `tblHeader` elements, which reads like success. The VALUE is the finding.
 *
 * There is no parameter now, because a row built by this function is a heading
 * row — that is what the function is for. The flag also makes Word repeat the
 * row when the table spans pages, which every one of these tables wants.
 */
export function headerRow(cells: string[]): TableRow {
  return new TableRow({
    tableHeader: true,
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
