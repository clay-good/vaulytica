/**
 * Compliance-matrix section (spec-v3.md §54).
 *
 * Renders a Word table with one row per applicable regulator and one
 * column per required-clause category. Cells carry status (Pass / Partial /
 * Fail / N/A) with cell shading and a short note. The matrix lives between
 * the executive summary and the findings list — it is the page a compliance
 * officer can paste into a slide deck.
 *
 * Cell shading is set via the `docx` library's table cell shading; the
 * accessibility properties on the table (`tableHeader: true` on the header
 * row) flag the row as a row of column headers for screen readers when the
 * docx is opened in Word with Narrator.
 */

import { Paragraph, Table, TableCell, TableRow, TextRun } from "docx";
import type { ComplianceMatrix, MatrixCell, MatrixStatus } from "./types.js";
import {
  BODY_SIZE,
  DEFAULT_FONT,
  buildTable,
  h1,
  headerRow,
  para,
  pageBreak,
  styledCell,
} from "./_dx.js";

const STATUS_LABEL: Record<MatrixStatus, string> = {
  pass: "Pass",
  partial: "Partial",
  fail: "Fail",
  na: "N/A",
};

const STATUS_FILL: Record<MatrixStatus, string> = {
  pass: "C8E6C9", // green-100
  partial: "FFF59D", // yellow-200
  fail: "FFCDD2", // red-100
  na: "EEEEEE", // grey-200
};

const STATUS_TEXT_COLOR: Record<MatrixStatus, string> = {
  pass: "1B5E20",
  partial: "8D6E00",
  fail: "B71C1C",
  na: "555555",
};

export function renderComplianceMatrix(matrix: ComplianceMatrix): (Paragraph | Table)[] {
  if (matrix.rows.length === 0 || matrix.columns.length === 0) {
    return [
      h1("Compliance Matrix"),
      para({
        text: "The selected playbook does not produce a compliance matrix for this document.",
        italics: true,
      }),
      pageBreak(),
    ];
  }
  const table = buildTable([
    headerRow(["Regulator", ...matrix.columns]),
    ...matrix.rows.map((row) => {
      const cells: TableCell[] = [
        styledCell(row.regulator, { bold: true }),
        ...row.cells.map((c) => renderCell(c)),
      ];
      return new TableRow({ children: cells });
    }),
  ]);
  const caption: Paragraph[] = matrix.dkb_build_date
    ? [
        para({
          text: `Citations as of ${formatDate(matrix.dkb_build_date)} (DKB build date).`,
          italics: true,
        }),
      ]
    : [];
  return [
    h1("Compliance Matrix"),
    para({
      text: "Each cell summarizes the playbook's coverage of one regulator's required-clause category against this document. Click-through rule ids are listed in the cell when applicable.",
    }),
    table,
    ...caption,
    pageBreak(),
  ];
}

function renderCell(cell: MatrixCell): TableCell {
  const lines: string[] = [STATUS_LABEL[cell.status]];
  if (cell.note) lines.push(cell.note);
  if (cell.contributing_rule_ids && cell.contributing_rule_ids.length > 0) {
    lines.push(cell.contributing_rule_ids.join(", "));
  }
  // Build the cell with multiple paragraphs (status, then optional note,
  // then optional rule ids) so the docx library renders the lines stacked
  // inside one cell.
  return new TableCell({
    shading: { type: "clear" as const, fill: STATUS_FILL[cell.status], color: "auto" },
    borders: undefined,
    children: lines.map(
      (line, i) =>
        new Paragraph({
          children: [
            new TextRun({
              text: line,
              bold: i === 0,
              color: i === 0 ? STATUS_TEXT_COLOR[cell.status] : "555555",
              font: DEFAULT_FONT,
              size: BODY_SIZE,
            }),
          ],
        }),
    ),
  });
}

function formatDate(iso: string): string {
  // Render the YYYY-MM-DD portion only; the matrix caption is a sentence,
  // not a timestamp.
  return iso.slice(0, 10);
}
