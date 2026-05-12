import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

/** RISK-012 — IP indemnity scope (info). */
export const rule: Rule = {
  id: "RISK-012",
  version: "1.0.0",
  name: "IP indemnity scope",
  category: "risk-allocation",
  default_severity: "info",
  description: "Detects IP indemnification and surfaces its scope.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(
      ctx,
      /\b(?:ip|intellectual\s+property)\s+indemnif|\binfring(?:e|ement)\b[\s\S]{0,80}\bindemnif/i,
    );
    if (!hit) return null;
    return emit(ctx, rule, {
      title: "IP indemnity present",
      description: hit.match[0],
      excerpt: hit.text.slice(0, 280),
      explanation:
        "IP indemnity protects against third-party infringement claims. Standard scope is third-party claims only; broader scope shifts more risk to the indemnifying party.",
      position: hit.position,
    });
  },
};
