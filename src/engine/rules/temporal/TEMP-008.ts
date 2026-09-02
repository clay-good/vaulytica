import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";
import { CURE_PERIOD, curePeriodDays, isUnusualCurePeriod } from "./_cure.js";

/** TEMP-008 — Cure period present (info). */
export const rule: Rule = {
  id: "TEMP-008",
  version: "1.3.0",
  name: "Cure period present",
  category: "temporal",
  default_severity: "info",
  description: "Detects cure periods for material breach and surfaces their length.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(ctx, CURE_PERIOD);
    if (!hit) return null;
    const days = curePeriodDays(hit.match);
    // TEMP-009 reports the same match, the same number, and the same severity
    // when the length is outside the customary band, so this presence note is
    // its own headline restated. Defer to the sibling that carries the
    // judgment.
    if (isUnusualCurePeriod(days)) return null;
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
