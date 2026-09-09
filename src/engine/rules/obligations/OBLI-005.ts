import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit } from "../_helpers.js";

// "must not <verb>" is a covenant negation the extractor captures but this filter
// did not classify — a "Employee must not disclose" restriction was dropped.
// Bare "cannot" is deliberately NOT added: it reads too broadly, sweeping in
// savings clauses ("rights that cannot be waived") and conditionals ("if the
// importer cannot comply") that are not restrictive covenants. ("is not
// permitted to" needed BOTH halves — the extractor had to capture the form
// before this filter could classify it, which is why widening the filter alone
// would not have surfaced it. Both landed in 9.599.0.)
const NEG =
  /\b(shall\s+not|may\s+not|must\s+not|(?:is|are)\s+not\s+permitted\s+to|(?:is|are)\s+prohibited\s+from|will\s+not)\b/i;

/** OBLI-005 — Negative covenants list (info). */
export const rule: Rule = {
  id: "OBLI-005",
  version: "1.1.0",
  name: "Negative covenants list",
  category: "obligations",
  default_severity: "info",
  description:
    "Surfaces all 'shall not' / 'may not' / 'must not' / 'is prohibited from' obligations.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const negs = ctx.extracted.obligations.filter((o) => NEG.test(o.raw_text));
    if (negs.length === 0) return null;
    return emit(ctx, rule, {
      title: `Negative covenants: ${negs.length}`,
      description: negs
        .slice(0, 4)
        .map((n) => n.raw_text.slice(0, 120))
        .join(" | "),
      excerpt: negs[0]!.raw_text,
      explanation:
        "Negative covenants restrict what a party may do. Surfacing them collectively makes it easier to check they are intended and consistent with the overall deal.",
      position: negs[0]!.position,
    });
  },
};
