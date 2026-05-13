import type { Rule, RuleContext, Finding } from "../../finding.js";
import { findStatuteCitation, makeFinding } from "../../finding.js";
import { forEachParagraph, forEachSection } from "../../../extract/walk.js";

const SIG_LINE = /^\s*(?:By|Name|Title|Date|Signed|Print(?:ed)?\s+Name)\s*:?\s*/im;
const SIG_TOKEN = /\b(?:By|Name|Title|Date|Signature|Signed|Authorized\s+Signatory)\b\s*:?/i;
const EXHIBIT_HEADING = /\b(?:exhibit|schedule|attachment|appendix|annex|annexure)\b/i;

/**
 * STRUCT-003 — Signature block present (critical).
 *
 * Looks for a canonical `By: ___ Name: ___ Title: ___ Date: ___`
 * pattern anywhere in the document, with two complementary searches:
 *
 *   1. Inside the "execution / signatures / signature page" sections
 *      if any such section heading exists.
 *   2. Otherwise in the last 40% of body paragraphs *that are not part
 *      of an exhibit/schedule/attachment/appendix/annex section*. Real
 *      contracts routinely have exhibits after the signature page, so
 *      the previous "last 15% of paragraphs" heuristic produced a
 *      critical false positive on every well-formed contract with
 *      attached schedules.
 *
 * Two qualifying lines (e.g., `By:` AND `Name:`, or `By:` AND `Date:`)
 * are required to fire a "present" verdict, so a stray "Name:" inside
 * a notice clause doesn't satisfy the check.
 */
export const rule: Rule = {
  id: "STRUCT-003",
  version: "1.0.0",
  name: "Signature block present",
  category: "structural",
  default_severity: "critical",
  description:
    "Verifies the document contains a signature block (with exhibits / schedules after it tolerated). Cites UETA § 7 and ESIGN 15 U.S.C. § 7001 for legal background.",
  dkb_citations: ["stat-ueta-section-7", "stat-15-usc-7001"],

  check(ctx: RuleContext): Finding | null {
    type P = { start: number; text: string; sectionId: string; inExhibit: boolean };
    const paragraphs: P[] = [];
    const exhibitSectionIds = new Set<string>();
    forEachSection(ctx.tree, (s) => {
      if (EXHIBIT_HEADING.test(s.heading)) exhibitSectionIds.add(s.id);
    });
    forEachParagraph(ctx.tree, (p) => {
      paragraphs.push({
        start: p.start,
        text: p.text,
        sectionId: p.section.id,
        inExhibit: exhibitSectionIds.has(p.section.id),
      });
    });
    if (paragraphs.length === 0) return null;

    const countSigSignals = (slice: P[]): number => {
      let signals = 0;
      for (const p of slice) {
        const text = p.text;
        // Count distinct sig tokens in the paragraph; a single
        // paragraph can carry the full table row "By: ___ Name: ___".
        const m = text.match(/\b(By|Name|Title|Date|Signature|Signed|Authorized\s+Signatory)\b/gi);
        if (!m) continue;
        const distinct = new Set(m.map((t) => t.toLowerCase().replace(/\s+/g, " ")));
        if (SIG_LINE.test(text) || SIG_TOKEN.test(text)) signals += distinct.size;
      }
      return signals;
    };

    // Strategy 1: a dedicated execution / signatures section anywhere
    // in the document. If found and it has ≥2 signature tokens, pass.
    const execSectionParas = paragraphs.filter((p) =>
      isInExecutionSection(ctx, p.sectionId),
    );
    if (execSectionParas.length > 0 && countSigSignals(execSectionParas) >= 2) return null;

    // Strategy 2: last 40% of non-exhibit paragraphs. Allow exhibits
    // to live after the signature page — that's normal contract shape.
    const body = paragraphs.filter((p) => !p.inExhibit);
    if (body.length > 0) {
      const cutoff = Math.floor(body.length * 0.6);
      const tail = body.slice(cutoff);
      if (countSigSignals(tail) >= 2) return null;
    }

    // Strategy 3: anywhere in the document, ≥2 tokens within a 12-paragraph
    // window. Covers compact / unconventional layouts.
    for (let i = 0; i < paragraphs.length; i++) {
      const window = paragraphs.slice(i, i + 12);
      if (countSigSignals(window) >= 2) return null;
    }

    const last = (paragraphs.filter((p) => !p.inExhibit).slice(-1)[0] ?? paragraphs[paragraphs.length - 1])!;
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

const EXECUTION_HEADING = /\b(?:in\s+witness\s+whereof|signatures?|execution|signature\s+page)\b/i;

function isInExecutionSection(ctx: RuleContext, sectionId: string): boolean {
  let inSection = false;
  forEachSection(ctx.tree, (s) => {
    if (s.id === sectionId && EXECUTION_HEADING.test(s.heading)) inSection = true;
  });
  return inSection;
}
