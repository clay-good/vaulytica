import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, topPosition } from "../_helpers.js";

/** FIN-003 — Currency consistency (warning). */
export const rule: Rule = {
  id: "FIN-003",
  version: "1.0.0",
  name: "Currency consistency",
  category: "financial",
  default_severity: "warning",
  description: "Flags when more than one currency is referenced in the document.",
  dkb_citations: ["stat-ucc-2-304"],
  check(ctx: RuleContext): Finding | null {
    const currencies = new Set(ctx.extracted.amounts.map((a) => a.currency));
    if (currencies.size < 2) return null;
    return emit(ctx, rule, {
      title: `Multiple currencies referenced: ${[...currencies].sort().join(", ")}`,
      description: "The document references amounts in more than one currency.",
      excerpt: [...currencies].sort().join(", "),
      explanation:
        "Multi-currency contracts need a conversion rule or a clear allocation of currency risk. The mere presence of two currencies is not wrong but should be reviewed.",
      position: topPosition(ctx),
    });
  },
};
