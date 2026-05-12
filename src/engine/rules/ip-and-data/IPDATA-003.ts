import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

/** IPDATA-003 — License grant scope (info). */
export const rule: Rule = {
  id: "IPDATA-003",
  version: "1.0.0",
  name: "License grant scope",
  category: "ip-and-data",
  default_severity: "info",
  description: "Surfaces the scope of an IP license grant (exclusive / transferable / territory / term).",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(
      ctx,
      /\bgrants?\s+(?:to\s+\w+\s+)?a\s+(?:non[- ]exclusive|exclusive|royalty[- ]free|perpetual|worldwide|sublicensable)[\s\S]{0,200}\blicense\b/i,
    );
    if (!hit) return null;
    return emit(ctx, rule, {
      title: "License grant scope stated",
      description: hit.match[0].slice(0, 240),
      excerpt: hit.text.slice(0, 280),
      explanation:
        "Verify the four classic license dimensions: exclusive vs. non-exclusive, transferable vs. non-transferable, geographic territory, and term.",
      position: hit.position,
    });
  },
};
