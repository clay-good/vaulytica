import type { Rule, RuleContext, Finding } from "../../finding.js";
import { makeFinding } from "../../finding.js";

/**
 * STRUCT-002 — Effective date present and parseable (warning).
 *
 * Searches for a named-anchor `Effective Date` reference, an absolute
 * date in the first 25% of the document, or a defined term `Effective
 * Date` in the definitions map. Fires if none is present.
 */
export const rule: Rule = {
  id: "STRUCT-002",
  version: "1.0.0",
  name: "Effective date present and parseable",
  category: "structural",
  default_severity: "warning",
  description:
    "Verifies the contract has an identifiable Effective Date — by named anchor, by a top-of-document absolute date, or by defined term.",
  dkb_citations: [],

  check(ctx: RuleContext): Finding | null {
    const hasAnchor = ctx.extracted.dates.some(
      (d) => d.type === "named-anchor" && /Effective Date/i.test(d.anchor ?? ""),
    );
    if (hasAnchor) return null;

    const defined = ctx.extracted.definitions.entries.find(
      (e) => e.term.toLowerCase() === "effective date",
    );
    if (defined) return null;

    const firstAbsolute = ctx.extracted.dates.find((d) => d.type === "absolute" && d.iso);
    if (firstAbsolute && firstAbsolute.position.start < documentLength(ctx) * 0.25) {
      return null;
    }

    const firstSectionId = ctx.tree.sections[0]?.id ?? "";
    return makeFinding({
      rule,
      title: "No Effective Date found",
      description: "No Effective Date is named, defined, or stated near the top of this Agreement.",
      excerptText: "(no Effective Date reference matched)",
      explanation:
        "Most contracts identify a starting point that other date references rely on. Without it, relative terms like 'within 30 days after the Effective Date' have no anchor.",
      recommendation:
        "Add an Effective Date — either in the preamble ('dated as of [date]'), as a defined term, or as an explicit 'Effective Date: [date]' line.",
      position: { section_id: firstSectionId, start: 0, end: 0 },
      source_citations: [],
    });
  },
};

function documentLength(ctx: RuleContext): number {
  let max = 0;
  for (const s of ctx.tree.sections) {
    for (const p of s.paragraphs) {
      const last = p.runs[p.runs.length - 1];
      if (last && last.end > max) max = last.end;
    }
  }
  return max || 1;
}
