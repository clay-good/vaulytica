import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, topPosition } from "../_helpers.js";

/** CHOICE-001 — Governing law clause present (warning). */
export const rule: Rule = {
  id: "CHOICE-001",
  version: "1.0.0",
  name: "Governing law clause present",
  category: "choice-and-venue",
  default_severity: "warning",
  description: "Detects governing-law clause and the chosen jurisdiction.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const govLaw = ctx.extracted.jurisdictions.find((j) => j.clause_kind === "governing-law");
    if (govLaw) return null;
    return emit(ctx, rule, {
      title: "No governing-law clause detected",
      description: "Vaulytica did not find a governing-law clause.",
      excerpt: "(no governing-law clause)",
      explanation:
        "A governing-law clause picks the legal system that interprets the contract. Without it, courts apply conflict-of-laws rules, which may produce unexpected results.",
      position: topPosition(ctx),
    });
  },
};
