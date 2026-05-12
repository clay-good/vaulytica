import type { Rule, RuleContext, Finding } from "../../finding.js";
import { findStatuteCitation, makeFinding } from "../../finding.js";
import { forEachParagraph } from "../../../extract/walk.js";

const SIG_LINE = /^(?:By|Name|Title|Date)\s*:?\s*/im;

/**
 * STRUCT-003 — Signature block present (critical).
 *
 * Scans the bottom 15% of the document for the canonical
 * `By: ___ Name: ___ Title: ___ Date: ___` pattern.
 */
export const rule: Rule = {
  id: "STRUCT-003",
  version: "1.0.0",
  name: "Signature block present",
  category: "structural",
  default_severity: "critical",
  description:
    "Verifies the document contains a signature block in the final 15%. Cites UETA § 7 and ESIGN 15 U.S.C. § 7001 for legal background.",
  dkb_citations: ["stat-ueta-section-7", "stat-15-usc-7001"],

  check(ctx: RuleContext): Finding | null {
    const paragraphs: { start: number; text: string; sectionId: string }[] = [];
    forEachParagraph(ctx.tree, (p) => {
      paragraphs.push({ start: p.start, text: p.text, sectionId: p.section.id });
    });
    if (paragraphs.length === 0) return null;
    const cutoff = Math.floor(paragraphs.length * 0.85);
    const tail = paragraphs.slice(cutoff);
    const hasBlock = tail.some((p) => SIG_LINE.test(p.text));
    if (hasBlock) return null;

    const last = paragraphs[paragraphs.length - 1]!;
    const citations = [
      findStatuteCitation(ctx.dkb, "stat-ueta-section-7"),
      findStatuteCitation(ctx.dkb, "stat-15-usc-7001"),
    ].filter((s): s is NonNullable<typeof s> => Boolean(s));

    return makeFinding({
      rule,
      title: "No signature block detected",
      description: "The end of this Agreement does not contain the standard signature pattern.",
      excerptText: last.text.slice(0, 160),
      explanation:
        "A contract without identifiable signatures may be unenforceable or invalid. Electronic signatures are permitted under ESIGN and state UETA equivalents, but the document must still record the parties' consent to be bound — typically via a 'By / Name / Title / Date' block.",
      recommendation:
        "Add a signature block for each party with lines for By, Name, Title, and Date. Electronic-signature platforms like DocuSign produce this automatically.",
      position: { section_id: last.sectionId, start: last.start, end: last.start + last.text.length },
      source_citations: citations,
    });
  },
};
