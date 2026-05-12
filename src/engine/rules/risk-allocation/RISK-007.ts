import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

/** RISK-007 — Consequential damages waiver present (info). */
export const rule: Rule = {
  id: "RISK-007",
  version: "1.0.0",
  name: "Consequential damages waiver present",
  category: "risk-allocation",
  default_severity: "info",
  description: "Detects waivers of consequential / special / incidental / punitive damages.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(
      ctx,
      /\b(?:no\s+(?:special|incidental|consequential|punitive)|(?:not\s+be\s+liable\s+for|liable\s+for|exclude(?:s|d)?\s+(?:any|all)?|waive(?:s|d)?\s+(?:any|all)?)\s+(?:[^.]*?\b)?(?:special|incidental|consequential|punitive)|(?:special|incidental|consequential|punitive)(?:[,\s]+(?:and\s+|or\s+)?(?:special|incidental|consequential|punitive)){1,3})[^.]*?\bdamages?\b/i,
    );
    if (!hit) return null;
    return emit(ctx, rule, {
      title: "Consequential damages waiver present",
      description: hit.match[0],
      excerpt: hit.text.slice(0, 240),
      explanation:
        "A waiver of consequential, special, incidental, and punitive damages is standard in commercial contracts. The waiver should be mutual unless deliberately asymmetric.",
      position: hit.position,
    });
  },
};
