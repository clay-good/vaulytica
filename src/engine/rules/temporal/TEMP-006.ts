import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

/** TEMP-006 — Survival clause present (info). */
export const rule: Rule = {
  id: "TEMP-006",
  version: "1.0.0",
  name: "Survival clause present",
  category: "temporal",
  default_severity: "info",
  description: "Detects 'survives termination' clauses.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(ctx, /\b(?:survive|survives|surviving)\b[\s\S]{0,40}\btermination\b/i);
    if (!hit) return null;
    return emit(ctx, rule, {
      title: "Survival clause present",
      description: "Provisions are stated to survive termination.",
      excerpt: hit.text.slice(0, 240),
      explanation:
        "A survival clause names the obligations that outlast termination — typically confidentiality, indemnity, payment obligations accrued before termination, and choice of law.",
      position: hit.position,
    });
  },
};
