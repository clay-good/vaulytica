import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch, isPresenceDisclaimed } from "../_helpers.js";

/** IPDATA-006 — Source code escrow (info). */
export const rule: Rule = {
  id: "IPDATA-006",
  version: "1.1.0",
  name: "Source code escrow",
  category: "ip-and-data",
  default_severity: "info",
  description: "Detects source-code escrow language; surfaces the trigger conditions.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    // "software escrow" and "technology escrow" are the same arrangement under
    // different names, and the object also leads ("escrow of the source code"),
    // all of which the "source code escrow"-only anchor missed. The reversed
    // branch requires "source code" nearby so an unrelated "held in escrow" (a
    // purchase-price escrow) is not read as a source-code escrow.
    const hit = firstParagraphMatch(
      ctx,
      /\b(?:source[- ]code|software|technology)\s+escrow\b|\bescrow\b[^.;\n]{0,40}\bsource\s+code\b/i,
    );
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
