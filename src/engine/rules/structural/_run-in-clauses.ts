import type { RuleContext } from "../../finding.js";
import { forEachParagraph } from "../../../extract/walk.js";

/**
 * Top-level numbers of RUN-IN clauses — paragraphs that open on "N." and a
 * capitalised word ("3. Training Restriction. Vendor shall not …").
 *
 * The section outline holds headings only. A document that styles one clause
 * as a heading ("2. Definitions.") and runs the rest into their paragraphs
 * shows a lone section 2, and the numbering checks reported sections 1 and 3
 * "missing" from a document that has them. Pasted text has no numbered
 * headings, so it never reached this; a DOCX did.
 */
export function runInClauseNumbers(ctx: RuleContext): Set<number> {
  const out = new Set<number>();
  forEachParagraph(ctx.tree, (p) => {
    const m = /^\s*(\d{1,3})\.\s+[A-Z]/.exec(p.text);
    if (m) out.add(Number(m[1]));
  });
  return out;
}
