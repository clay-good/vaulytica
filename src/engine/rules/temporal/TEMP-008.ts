import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";
import { CURE_PERIOD, curePeriodDays } from "./_cure.js";

/** TEMP-008 — Cure period present (info). */
export const rule: Rule = {
  id: "TEMP-008",
  version: "1.2.0",
  name: "Cure period present",
  category: "temporal",
  default_severity: "info",
  description: "Detects cure periods for material breach and surfaces their length.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(ctx, CURE_PERIOD);
    if (!hit) return null;
    const days = curePeriodDays(hit.match);
    return emit(ctx, rule, {
      title: `Cure period: ${days} days`,
      description: `Material breach cure period of ${days} days is stated.`,
      excerpt: hit.match[0],
      explanation:
        "Most contracts give the breaching party a window to cure before termination for cause is permitted. The customary length is 30 days.",
      position: hit.position,
    });
  },
};
