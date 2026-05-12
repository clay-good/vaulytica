import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit } from "../_helpers.js";

/** CHOICE-002 — Governing law unspecified or ambiguous (warning). */
export const rule: Rule = {
  id: "CHOICE-002",
  version: "1.0.0",
  name: "Governing law unspecified state",
  category: "choice-and-venue",
  default_severity: "warning",
  description: "Flags governing-law clauses where the jurisdiction is missing or ambiguous.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const gov = ctx.extracted.jurisdictions.find((j) => j.clause_kind === "governing-law");
    if (!gov) return null;
    if (gov.raw_text && gov.raw_text.length >= 3) return null;
    return emit(ctx, rule, {
      title: "Governing-law clause does not name a specific jurisdiction",
      description: `Extracted raw: '${gov.raw_text}'.`,
      excerpt: gov.raw_text || "(empty)",
      explanation:
        "A governing-law clause that does not specify a state or country is functionally absent.",
      position: gov.position,
    });
  },
};
