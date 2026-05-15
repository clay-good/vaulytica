/**
 * Cross-border transfer summary section (spec-v3.md §56).
 *
 * Rendered only when transfer language is detected. Summarizes which
 * mechanisms are used and where each clause lives in the document, with
 * an explicit note when supplementary measures or a TIA are referenced.
 */

import type { Paragraph, Table } from "docx";
import type { TransferMechanismReference, TransferMechanismKind } from "../../extract/v3/types.js";
import { h1, para, pageBreak, buildTable, headerRow, bodyRow } from "./_dx.js";

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
  unknown: "Unknown",
};

export function renderTransfersSummary(refs: TransferMechanismReference[]): (Paragraph | Table)[] {
  if (refs.length === 0) {
    return []; // Section is conditional; emit nothing when no transfer detected.
  }
  const table = buildTable([
    headerRow(["Mechanism", "Location in document", "Excerpt (truncated)"]),
    ...refs.map((r) =>
      bodyRow([
        KIND_LABEL[r.kind] ?? r.kind,
        r.location,
        truncate(r.raw_text, 160),
      ]),
    ),
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

function truncate(text: string, limit: number): string {
  if (text.length <= limit) return text;
  return text.slice(0, limit - 1) + "…";
}
