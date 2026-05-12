import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch, topPosition } from "../_helpers.js";

/** TERM-005 — Effect of termination clause present (warning). */
export const rule: Rule = {
  id: "TERM-005",
  version: "1.0.0",
  name: "Effect of termination clause",
  category: "termination",
  default_severity: "warning",
  description: "Verifies the contract explains what happens upon termination.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    if (firstParagraphMatch(ctx, /\b(?:effect|consequences)\s+of\s+termination\b|\bupon\s+termination[\s\S]{0,200}\b(?:cease|return|destroy|transition)\b/i)) return null;
    return emit(ctx, rule, {
      title: "No effect-of-termination clause detected",
      description: "The contract does not state what happens upon termination.",
      excerpt: "(no effect-of-termination clause)",
      explanation:
        "An effect-of-termination clause spells out the rights and obligations that survive, the return or destruction of materials, and the wind-down rules.",
      position: topPosition(ctx),
    });
  },
};
