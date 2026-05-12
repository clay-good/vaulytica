import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch, topPosition } from "../_helpers.js";

/** IPDATA-001 — IP ownership clause present (warning). */
export const rule: Rule = {
  id: "IPDATA-001",
  version: "1.0.0",
  name: "IP ownership clause present",
  category: "ip-and-data",
  default_severity: "warning",
  description: "Detects IP-ownership / assignment / work-for-hire language; fires when absent.",
  dkb_citations: ["stat-17-usc-101", "stat-17-usc-201"],
  check(ctx: RuleContext): Finding | null {
    if (firstParagraphMatch(ctx, /\b(?:work(?:s)?\s+made\s+for\s+hire|intellectual\s+property|IP\s+ownership|hereby\s+assigns)\b/i)) return null;
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
