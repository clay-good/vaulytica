import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch, topPosition } from "../_helpers.js";

/** TERM-002 — Termination for cause present (warning). */
export const rule: Rule = {
  id: "TERM-002",
  version: "1.0.0",
  name: "Termination for cause present",
  category: "termination",
  default_severity: "warning",
  description: "Verifies the contract has a termination-for-cause path.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    if (
      firstParagraphMatch(
        ctx,
        // `\b` before "material" so "immaterial breach" — which DISCLAIMS a
        // termination right — does not satisfy the for-cause path and suppress
        // this "no for-cause clause" warning. No trailing boundary, so the
        // common plural "material breaches" still matches.
        /\bterminate\b[\s\S]{0,80}\bfor\s+cause\b|\bmaterial(?:ly)?\s+breach/i,
      )
    )
      return null;
    return emit(ctx, rule, {
      title: "No termination-for-cause clause detected",
      description: "The contract does not state a path to terminate for material breach.",
      excerpt: "(no for-cause termination)",
      explanation:
        "Without a for-cause termination path, parties must rely on common-law material-breach doctrines, which are jurisdiction-dependent.",
      position: topPosition(ctx),
    });
  },
};
