import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

/** TEMP-010 — Specific dates near or after expiry (info). */
export const rule: Rule = {
  id: "TEMP-010",
  version: "1.0.0",
  name: "Specific dates after expiry",
  category: "temporal",
  default_severity: "info",
  description: "Flags absolute dates that fall after a stated expiration date.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const expiry = firstParagraphMatch(
      ctx,
      /\b(?:expires?|expiration\s+date)\b[\s\S]{0,40}?(\d{4}-\d{2}-\d{2})/i,
    );
    if (!expiry) return null;
    const expiryDate = expiry.match[1]!;
    const later = ctx.extracted.dates.find(
      (d) => d.type === "absolute" && d.iso && d.iso > expiryDate && d.raw_text !== expiryDate,
    );
    if (!later) return null;
    return emit(ctx, rule, {
      title: `Date ${later.iso} appears after expiration ${expiryDate}`,
      description: `Reference to ${later.iso} occurs in a contract that expires ${expiryDate}.`,
      excerpt: later.raw_text,
      explanation:
        "A date later than the expiration of the contract may signal a survival clause, a forward-looking commitment, or a drafting error.",
      position: later.position,
    });
  },
};
