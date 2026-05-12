import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit } from "../_helpers.js";

const NEG = /\b(shall\s+not|may\s+not|is\s+prohibited\s+from|will\s+not)\b/i;

/** OBLI-005 — Negative covenants list (info). */
export const rule: Rule = {
  id: "OBLI-005",
  version: "1.0.0",
  name: "Negative covenants list",
  category: "obligations",
  default_severity: "info",
  description: "Surfaces all 'shall not' / 'may not' / 'is prohibited from' obligations.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const negs = ctx.extracted.obligations.filter((o) => NEG.test(o.raw_text));
    if (negs.length === 0) return null;
    return emit(ctx, rule, {
      title: `Negative covenants: ${negs.length}`,
      description: negs.slice(0, 4).map((n) => n.raw_text.slice(0, 120)).join(" | "),
      excerpt: negs[0]!.raw_text,
      explanation:
        "Negative covenants restrict what a party may do. Surfacing them collectively makes it easier to check they are intended and consistent with the overall deal.",
      position: negs[0]!.position,
    });
  },
};
