import type { Rule, RuleContext, Finding } from "../../finding.js";
import { makeFinding } from "../../finding.js";

/**
 * STRUCT-005 — Defined-but-never-used terms (info).
 *
 * Lists each defined term that does not appear outside its own definition.
 * Drafting-quality signal: defined terms left unused often mark
 * boilerplate copied from another template that was never adapted.
 */
export const rule: Rule = {
  id: "STRUCT-005",
  version: "1.1.0",
  name: "Defined-but-never-used terms",
  category: "structural",
  default_severity: "info",
  description: "Reports defined terms that are never referenced after their definition.",
  dkb_citations: [],

  check(ctx: RuleContext): Finding | null {
    const unused = ctx.extracted.definitions.unused_terms;
    if (unused.length === 0) return null;
    const first = ctx.extracted.definitions.entries.find((e) => unused.includes(e.term));
    const position = first?.defined_at ?? { section_id: "", start: 0, end: 0 };
    return makeFinding({
      rule,
      title: `Defined terms with no uses: ${unused.length}`,
      description: `The following defined terms are never used outside their definition: ${unused.join(", ")}.`,
      // The EXCERPT is evidence: it has to be text the document contains, and
      // the position points into the paragraph that defines the first unused
      // term. A comma-joined list of every unused term is a summary, and it
      // sent a reader to a span that does not say it. The list stays in the
      // description, where it belongs. (STRUCT-006 already reads this way.)
      excerptText: first?.term ?? unused[0]!,
      explanation:
        "Defined terms that are not used downstream may be inherited from a template and obsolete. They clutter the contract and can confuse readers; either delete them or use them where intended.",
      recommendation:
        "Review each unused term and either delete it or wire it into the relevant clause.",
      position,
      source_citations: [],
    });
  },
};
