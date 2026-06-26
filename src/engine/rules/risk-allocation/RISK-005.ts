import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch, topPosition } from "../_helpers.js";

/** RISK-005 — Limitation of liability present (warning). */
export const rule: Rule = {
  id: "RISK-005",
  version: "1.0.0",
  name: "Limitation of liability present",
  category: "risk-allocation",
  default_severity: "warning",
  description: "Detects a limitation-of-liability clause; fires when absent.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    if (firstParagraphMatch(ctx, /\blimitation\s+of\s+liability\b|\baggregate\s+liability\b/i))
      return null;
    return emit(ctx, rule, {
      title: "No limitation-of-liability clause detected",
      description: "Vaulytica did not find a limitation-of-liability clause.",
      excerpt: "(no LoL clause)",
      explanation:
        "Without a limitation-of-liability clause, exposure is bounded only by what the parties can prove in damages. Most commercial contracts cap liability.",
      position: topPosition(ctx),
    });
  },
};
