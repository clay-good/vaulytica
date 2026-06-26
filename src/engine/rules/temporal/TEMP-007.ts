import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

const EXPECTED = [
  ["confidentiality", /confidential/i],
  ["indemnity", /indemnif/i],
  ["payment", /payment|fees?\s+accrued/i],
  ["governing law", /governing\s+law/i],
] as const;

/** TEMP-007 — Survival list completeness (info). */
export const rule: Rule = {
  id: "TEMP-007",
  version: "1.0.0",
  name: "Survival list completeness",
  category: "temporal",
  default_severity: "info",
  description: "Cross-checks the survival list against the typical surviving categories.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const survival = firstParagraphMatch(
      ctx,
      /\b(?:survive|survives|surviving)\b[\s\S]{0,400}\btermination\b/i,
    );
    if (!survival) return null;
    const missing = EXPECTED.filter(([, re]) => !re.test(survival.text)).map(([name]) => name);
    if (missing.length === 0) return null;
    return emit(ctx, rule, {
      title: `Survival list may be missing categories: ${missing.join(", ")}`,
      description: `Survival clause does not appear to include: ${missing.join(", ")}.`,
      excerpt: survival.text.slice(0, 240),
      explanation:
        "Typical surviving obligations include confidentiality, indemnity, accrued payment obligations, and governing law. Missing any of these is common and worth confirming.",
      position: survival.position,
    });
  },
};
