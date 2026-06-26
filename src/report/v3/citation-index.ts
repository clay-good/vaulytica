/**
 * Citation-depth verification appendix (spec-v3.md §55).
 *
 * One row per unique citation, listing the regulator, the citation string,
 * the stable URL (rendered as a hyperlink so a reader can click through),
 * the DKB version that grounded the citation, and the retrieval timestamp.
 * The appendix is the audit-defense companion to the report — pull any
 * finding's citation and verify it against the regulator's authoritative
 * source.
 */

import type { Paragraph, Table } from "docx";
import {
  h1,
  para,
  pageBreak,
  buildTable,
  headerRow,
  styledCell,
  hyperlinkParagraph,
} from "./_dx.js";
import { TableCell, TableRow } from "docx";
import type { BibliographyEntry } from "../bibliography.js";

export function renderCitationIndex(
  bibliography: BibliographyEntry[],
  dkbVersion: string,
  dkbBuildDate?: string,
): (Paragraph | Table)[] {
  if (bibliography.length === 0) return [];
  const rows: TableRow[] = [headerRow(["#", "Citation", "URL", "DKB", "Retrieved"])];
  for (const b of bibliography) {
    rows.push(
      new TableRow({
        children: [
          styledCell(String(b.index)),
          styledCell(b.source.source),
          new TableCell({
            borders: undefined,
            children: [hyperlinkParagraph(b.source.source_url, b.source.source_url)],
          }),
          styledCell(dkbVersion),
          styledCell(b.source.retrieved_at || "—"),
        ],
      }),
    );
  }
  const caption: Paragraph[] = dkbBuildDate
    ? [
        para({
          text: `Citations as of ${dkbBuildDate.slice(0, 10)} (DKB build date).`,
          italics: true,
        }),
      ]
    : [];
  return [
    h1("Citation Index"),
    para({
      text: "Every citation in this report, with its authoritative URL and the DKB version that grounded it. A reader can pull any citation and verify it directly against the regulator's source.",
    }),
    buildTable(rows),
    ...caption,
    pageBreak(),
  ];
}
