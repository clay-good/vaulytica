import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

/** IPDATA-002 — Pre-existing IP carve-out clarity (warning). */
export const rule: Rule = {
  id: "IPDATA-002",
  version: "1.0.0",
  name: "Pre-existing IP carve-out",
  category: "ip-and-data",
  default_severity: "warning",
  description: "Verifies that pre-existing IP is carved out of any assignment.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(
      ctx,
      /\b(?:hereby\s+)?assigns?\b[\s\S]{0,200}intellectual\s+property|\b(?:works?\s+made\s+for\s+hire)\b/i,
    );
    if (!hit) return null;
    if (/\b(?:pre[- ]?existing|background|prior)\s+(?:IP|intellectual\s+property)\b/i.test(hit.text)) return null;
    return emit(ctx, rule, {
      title: "Pre-existing IP carve-out not stated",
      description: "An IP assignment is present but pre-existing IP is not expressly carved out.",
      excerpt: hit.text.slice(0, 280),
      explanation:
        "Without an explicit carve-out, a broad assignment can sweep in the assigning party's pre-existing IP. Modern drafting carves out 'Background IP' or 'Pre-existing IP' to scope the assignment.",
      position: hit.position,
    });
  },
};
