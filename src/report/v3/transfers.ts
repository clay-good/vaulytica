/**
 * Cross-border transfer summary section (spec-v3.md §56).
 *
 * Rendered only when transfer language is detected. Summarizes which
 * mechanisms are used and where each clause lives in the document, with
 * an explicit note when supplementary measures or a TIA are referenced.
 */

import type { Paragraph, Table } from "docx";
import type { TransferMechanismReference, TransferMechanismKind } from "../../extract/v3/types.js";
import { h1, para, pageBreak, buildTable, headerRow, bodyRow, truncate } from "./_dx.js";

const KIND_LABEL: Record<TransferMechanismKind, string> = {
  "scc-module-1": "EU SCC Module 1 (C → C)",
  "scc-module-2": "EU SCC Module 2 (C → P)",
  "scc-module-3": "EU SCC Module 3 (P → P)",
  "scc-module-4": "EU SCC Module 4 (P → C)",
  "scc-unspecified": "EU SCC (module unspecified)",
  "uk-idta": "UK IDTA",
  "uk-addendum": "UK Addendum to EU SCCs",
  "swiss-addendum": "Swiss Addendum",
  "adequacy-decision": "Adequacy decision",
  "binding-corporate-rules": "Binding Corporate Rules",
  "article-49-derogation": "Art. 49 derogation",
  "data-privacy-framework": "EU-US Data Privacy Framework",
  "privacy-shield": "Privacy Shield (invalidated)",
  unknown: "Unknown",
};

export function renderTransfersSummary(refs: TransferMechanismReference[]): (Paragraph | Table)[] {
  if (refs.length === 0) {
    return []; // Section is conditional; emit nothing when no transfer detected.
  }
  // ONE ROW PER DISTINCT MECHANISM-AND-PLACE.
  //
  // The extractor records every occurrence, correctly: `uk-idta-addendum.txt`
  // names the EU SCCs in three separate paragraphs. The TABLE drops the
  // position, so all three render byte-identically — "EU SCC (module
  // unspecified) | inline | EU SCCs", three times — and three identical rows
  // tell a reader nothing the first one did not.
  //
  // 🥇 A section column would not fix it: all three sit in the same section.
  // That is the difference from 9.657.0, where the register's checklist was
  // hiding a real distinguishing field (the kind) and the answer was to print
  // it. Here there is nothing to print, so the answer is to collapse.
  //
  // Deduplicated on what the reader SEES, in first-occurrence order, so the
  // table stays a deterministic projection of the extractor's own order.
  const rendered = refs.map((r) => [
    KIND_LABEL[r.kind] ?? r.kind,
    r.location,
    truncate(r.raw_text, 160),
  ]);
  const distinct = new Map<string, string[]>();
  for (const cells of rendered) {
    const key = cells.join("\u0000");
    if (!distinct.has(key)) distinct.set(key, cells);
  }
  const table = buildTable([
    headerRow(["Mechanism", "Location in document", "Excerpt (truncated)"]),
    ...[...distinct.values()].map((cells) => bodyRow(cells)),
  ]);
  const tiaMentioned = refs.some((r) => /\bTIA\b|transfer\s+impact\s+assessment/i.test(r.raw_text));
  const supplementaryMentioned = refs.some((r) =>
    /supplementary\s+measures|additional\s+safeguards/i.test(r.raw_text),
  );
  return [
    h1("Cross-Border Transfer Summary"),
    para({
      text: "The following transfer mechanisms were detected in this document. The location column reports where the clause lives (inline, annex, attachment, by reference, hyperlink, or recital only).",
    }),
    table,
    para({
      text: `Transfer Impact Assessment referenced: ${tiaMentioned ? "yes" : "no"}.  Supplementary measures referenced: ${supplementaryMentioned ? "yes" : "no"}.`,
      italics: true,
    }),
    pageBreak(),
  ];
}
