import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch, topPosition } from "../_helpers.js";

/** RISK-001 — Indemnification clause present (warning). */
export const rule: Rule = {
  id: "RISK-001",
  version: "1.0.0",
  name: "Indemnification clause present",
  category: "risk-allocation",
  default_severity: "warning",
  description: "Detects indemnification language; fires when absent.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(ctx, /\bindemnif(?:y|ication|ies)\b|\bhold\s+harmless\b/i);
    if (hit) return null;
    return emit(ctx, rule, {
      title: "No indemnification clause detected",
      description: "Neither 'indemnify' nor 'hold harmless' appears in the document.",
      excerpt: "(no indemnification language)",
      explanation:
        "Most commercial contracts allocate risk through an indemnification clause. The absence leaves the parties to default tort and contract law for any third-party claims.",
      position: topPosition(ctx),
    });
  },
};
