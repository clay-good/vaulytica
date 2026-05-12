import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

/** RISK-014 — Confidentiality term length (info). */
export const rule: Rule = {
  id: "RISK-014",
  version: "1.0.0",
  name: "Confidentiality term length",
  category: "risk-allocation",
  default_severity: "info",
  description: "Surfaces the post-termination confidentiality term length.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(
      ctx,
      /confidentiality[\s\S]{0,200}?(?:survive|continue|remain\s+in\s+effect)[\s\S]{0,40}?(?:for|until)\s+(\w+\s+\(\d+\)|\d+)\s+(year|years|month|months)/i,
    );
    if (!hit) return null;
    return emit(ctx, rule, {
      title: "Confidentiality term length stated",
      description: hit.match[0],
      excerpt: hit.text.slice(0, 240),
      explanation:
        "Typical post-termination confidentiality terms run 3–5 years for general information, with a perpetual duty for trade secrets. Verify the term matches the sensitivity of the information.",
      position: hit.position,
    });
  },
};
