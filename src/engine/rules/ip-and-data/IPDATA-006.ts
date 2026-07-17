import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch, isPresenceDisclaimed } from "../_helpers.js";

/** IPDATA-006 — Source code escrow (info). */
export const rule: Rule = {
  id: "IPDATA-006",
  version: "1.0.0",
  name: "Source code escrow",
  category: "ip-and-data",
  default_severity: "info",
  description: "Detects source-code escrow language; surfaces the trigger conditions.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(ctx, /\bsource\s+code\s+escrow\b/i);
    if (!hit) return null;
    if (isPresenceDisclaimed(hit.text, hit.match.index)) return null;
    return emit(ctx, rule, {
      title: "Source code escrow clause present",
      description: hit.match[0],
      excerpt: hit.text.slice(0, 240),
      explanation:
        "Source-code escrow gives the customer access if the vendor fails (bankruptcy, discontinuation). Verify trigger conditions are clear and the escrow agent is named.",
      position: hit.position,
    });
  },
};
