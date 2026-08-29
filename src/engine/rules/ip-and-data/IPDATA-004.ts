import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch, topPosition } from "../_helpers.js";

/** IPDATA-004 — Data ownership distinction from IP (info). */
export const rule: Rule = {
  id: "IPDATA-004",
  version: "1.3.0",
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
        // "Customer owns all right, title, and interest in and to Customer
        // Data" is the single most common way a contract allocates data
        // ownership, and the "owns … data" branch could not read it: after
        // "owns all" comes "right", not "data". A rule about data ownership
        // was reporting ownership as unaddressed on the standard drafting.
        // Ownership is also allocated by RETENTION — "You retain all rights in
        // the data you upload", "Customer retains ownership of its data" — which
        // the "owns … data" forms above miss. Ownership stated with the DATA
        // object first — "Customer Data shall belong to / is owned by / is the
        // property of the Customer" — and the "owns ALL Customer Data" form
        // (an intervening "all"/"its") are recognized too.
        /\b(?:customer\s+data|usage\s+data|service\s+data)\s+ownership\b|owns?\s+(?:all\s+|the\s+|its\s+)*(?:customer\s+|usage\s+|service\s+)?data\b|retains?\s+(?:all\s+)?(?:rights?|ownership|title)\s+(?:in|to|of)\s+[^.]{0,30}?\bdata\b|(?:owns?|retains?|shall\s+(?:own|retain))\s+(?:all\s+)?right,?\s+title,?\s+and\s+interest\s+(?:in|to)\b[^.]{0,40}?\b(?:customer|usage|service)\s+data\b|(?:customer|usage|service)\s+data\b[^.]{0,40}?\b(?:belongs?\s+to|owned\s+by|(?:is|are|shall\s+be)\s+(?:the\s+)?(?:sole\s+|exclusive\s+)*property\s+of)\b/i,
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
