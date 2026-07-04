import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch, topPosition } from "../_helpers.js";

/** IPDATA-001 — IP ownership clause present (warning). */
export const rule: Rule = {
  id: "IPDATA-001",
  version: "1.1.0",
  name: "IP ownership clause present",
  category: "ip-and-data",
  default_severity: "warning",
  description: "Detects IP-ownership / assignment / work-for-hire language; fires when absent.",
  dkb_citations: ["stat-17-usc-101", "stat-17-usc-201"],
  check(ctx: RuleContext): Finding | null {
    // The assignment alternation requires an IP object within the clause
    // (fix-rule-detection-fidelity): a bare `hereby assigns` anywhere —
    // receivables, a lease, a security interest — used to silently satisfy
    // this presence check. Recognized IP objects: inventions, works (of
    // authorship), work product, copyrights, patents, trademarks, trade
    // secrets, deliverables, intellectual property, moral rights, IP.
    if (
      firstParagraphMatch(
        ctx,
        /\b(?:work(?:s)?\s+made\s+for\s+hire|intellectual\s+property|IP\s+ownership|hereby\s+assigns[^.]{0,120}?\b(?:inventions?|work\s+product|works?\s+of\s+authorship|copyrights?|patents?|trademarks?|trade\s+secrets?|deliverables?|intellectual\s+property|moral\s+rights?|IP)\b)/i,
      )
    )
      return null;
    return emit(ctx, rule, {
      title: "No IP-ownership clause detected",
      description: "The contract does not allocate ownership of intellectual property.",
      excerpt: "(no IP-ownership clause)",
      explanation:
        "Without an IP-ownership clause, default copyright and patent rules apply: under 17 U.S.C. § 201, copyright vests in the author/employee unless work-for-hire or assignment applies.",
      position: topPosition(ctx),
    });
  },
};
