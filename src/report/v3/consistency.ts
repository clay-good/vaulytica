/**
 * Two-document consistency appendix (spec-v3.md §59).
 *
 * Lists every consistency-check rule that fired with citations to both
 * documents and the conflicting text from each. Renders only when a
 * {@link ConsistencyRun} is provided (i.e., the user dropped two or more
 * documents at once).
 */

import type { Paragraph, Table } from "docx";
import type { ConsistencyRun, ConsistencyFinding } from "../../engine/consistency/types.js";
import { h1, h2, h3, para, pageBreak, buildTable, headerRow, bodyRow } from "./_dx.js";

export function renderConsistencyAppendix(run: ConsistencyRun): (Paragraph | Table)[] {
  if (run.findings.length === 0) {
    return [
      h1("Two-Document Consistency"),
      para({
        text: `Documents in this bundle: ${run.documents.map((d) => `${d.doc_id} (${d.kind})`).join(", ")}.`,
      }),
      para({
        text: "No cross-document conflicts were detected by the consistency rules.",
        italics: true,
      }),
      pageBreak(),
    ];
  }

  const out: (Paragraph | Table)[] = [
    h1("Two-Document Consistency"),
    para({
      text: `Documents in this bundle: ${run.documents.map((d) => `${d.doc_id} (${d.kind})`).join(", ")}.`,
    }),
    para({
      text: `${run.findings.length} cross-document finding${run.findings.length === 1 ? "" : "s"}. Each lists the affected documents and the conflicting text from each.`,
    }),
    buildTable([
      headerRow(["#", "Rule", "Severity", "Title"]),
      ...run.findings.map((f, i) =>
        bodyRow([String(i + 1), f.rule_id, f.severity.toUpperCase(), truncate(f.title, 120)]),
      ),
    ]),
  ];

  for (const f of run.findings) {
    out.push(...renderConsistencyFinding(f));
  }

  out.push(para({ text: `Consistency result hash: ${run.result_hash}`, italics: true }));
  out.push(pageBreak());
  return out;
}

function renderConsistencyFinding(f: ConsistencyFinding): Paragraph[] {
  const paragraphs: Paragraph[] = [
    h2(`${f.rule_id} — ${f.title}`),
    para({ text: `[${f.severity.toUpperCase()}] ${f.description}`, bold: true }),
    para({ text: f.explanation }),
  ];
  if (f.recommendation) {
    paragraphs.push(para({ text: `Recommendation: ${f.recommendation}`, bold: true }));
  }
  paragraphs.push(h3("Conflicting excerpts"));
  for (const e of f.excerpts) {
    paragraphs.push(
      para({
        text: `${e.doc_id} (${e.source_file_name}): "${truncate(e.text, 480)}"`,
        italics: true,
      }),
    );
  }
  return paragraphs;
}

function truncate(text: string, limit: number): string {
  if (text.length <= limit) return text;
  return text.slice(0, limit - 1) + "…";
}
