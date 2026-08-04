import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

/** TEMP-010 — Specific dates near or after expiry (info). */
export const rule: Rule = {
  id: "TEMP-010",
  version: "1.1.0",
  name: "Specific dates after expiry",
  category: "temporal",
  default_severity: "info",
  description: "Flags absolute dates that fall after a stated expiration date.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    // The expiration date was matched with an ISO-only regex, so the rule never
    // fired on the "December 31, 2026" / "31 December 2026" / "12/31/2026" forms
    // real contracts actually use — it worked only on ISO dates, which are rare.
    // Anchor on the "expires / expiration date" keyword, then take the
    // expiration date from the extracted-date stream (which already resolves
    // every supported format to ISO) by finding the absolute date that sits
    // just after the keyword in the same paragraph.
    const anchor = firstParagraphMatch(ctx, /\b(?:expires?|expiration\s+date)\b/i);
    if (!anchor) return null;
    const afterKeyword = anchor.text.slice(anchor.match.index);
    const expiryRef = ctx.extracted.dates.find((d) => {
      if (d.type !== "absolute" || !d.iso) return false;
      const at = afterKeyword.indexOf(d.raw_text);
      return at >= 0 && at < 60;
    });
    if (!expiryRef?.iso) return null;
    const expiryDate = expiryRef.iso;
    const later = ctx.extracted.dates.find(
      (d) =>
        d.type === "absolute" && d.iso && d.iso > expiryDate && d.raw_text !== expiryRef.raw_text,
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
