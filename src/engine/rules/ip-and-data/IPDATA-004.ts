import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch, topPosition } from "../_helpers.js";

/** IPDATA-004 — Data ownership distinction from IP (info). */
export const rule: Rule = {
  id: "IPDATA-004",
  version: "1.0.0",
  name: "Data ownership distinguished from IP",
  category: "ip-and-data",
  default_severity: "info",
  description: "For data-heavy contracts, flags missing distinction between IP and data ownership.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const dataMention = firstParagraphMatch(
      ctx,
      /\b(?:customer\s+data|usage\s+data|service\s+data)\b/i,
    );
    if (!dataMention) return null;
    if (
      firstParagraphMatch(
        ctx,
        // "service" must be an accepted prefix here too — otherwise an explicit
        // "Vendor owns the Service Data" fails the suppression and the rule
        // falsely reports ownership as unaddressed (Service Data is one of the
        // three trigger terms above).
        /\b(?:customer\s+data|usage\s+data|service\s+data)\s+ownership\b|owns?\s+(?:the\s+)?(?:customer\s+|usage\s+|service\s+)?data\b/i,
      )
    )
      return null;
    return emit(ctx, rule, {
      title: "Data ownership not separately addressed",
      description: "The contract references data but does not separately allocate data ownership.",
      excerpt: dataMention.text.slice(0, 240),
      explanation:
        "IP and data ownership are different. For SaaS, the customer typically owns its data; the vendor typically owns usage analytics. Address each explicitly.",
      position: dataMention.position ?? topPosition(ctx),
    });
  },
};
