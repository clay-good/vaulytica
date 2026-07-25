import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch, topPosition } from "../_helpers.js";

/**
 * A limitation of liability is the CAP, not the heading. Matching only the
 * labels "limitation of liability" / "aggregate liability" missed the clause
 * itself: "EACH PARTY'S TOTAL CUMULATIVE LIABILITY ARISING OUT OF OR RELATED
 * TO THIS AGREEMENT … SHALL NOT EXCEED THE FEES PAID BY CUSTOMER TO PROVIDER
 * IN THE TWELVE (12) MONTHS PRECEDING THE EVENT GIVING RISE TO THE CLAIM" is a
 * textbook cap that uses neither label, and the rule reported "Vaulytica did
 * not find a limitation-of-liability clause".
 *
 * Both capping forms are sentence-scoped, so the word "liability" in one
 * clause cannot borrow "shall not exceed" from another.
 */
// The "in no event" cap is handled in BOTH orders, and "under no
// circumstances" is its equally common synonym — "Under no circumstances shall
// the Supplier's liability exceed the purchase price". The final branch adds
// the "shall not be liable for more than $X / in excess of X" cap phrasing,
// which states the ceiling without the word "exceed". These are dollar/fees
// CAPS; a bare consequential-damages exclusion ("shall not be liable for lost
// profits") is deliberately not a cap and still fires.
const LIMITATION_OF_LIABILITY =
  /\blimitation\s+of\s+liability\b|\baggregate\s+liability\b|\bliabilit(?:y|ies)\b[^.]{0,200}?\b(?:shall|will)\s+not\s+exceed\b|\bliabilit(?:y|ies)\b[^.]{0,160}?\b(?:capped|limited)\s+(?:at|to)\b|\b(?:in\s+no\s+event|under\s+no\s+circumstances)\b[^.]{0,140}?\bliabilit(?:y|ies)\b[^.]{0,80}?\bexceed\b|\bliabilit(?:y|ies)\b[^.]{0,80}?\b(?:in\s+no\s+event|under\s+no\s+circumstances)\b[^.]{0,40}?\bexceed\b|\b(?:shall|will)\s+not\s+be\s+liable\s+for\s+(?:an\s+amount\s+)?(?:more\s+than|in\s+excess\s+of)\b/i;

/** RISK-005 — Limitation of liability present (warning). */
export const rule: Rule = {
  id: "RISK-005",
  version: "1.2.0",
  name: "Limitation of liability present",
  category: "risk-allocation",
  default_severity: "warning",
  description: "Detects a limitation-of-liability clause; fires when absent.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    if (firstParagraphMatch(ctx, LIMITATION_OF_LIABILITY)) return null;
    return emit(ctx, rule, {
      title: "No limitation-of-liability clause detected",
      description: "Vaulytica did not find a limitation-of-liability clause.",
      excerpt: "(no LoL clause)",
      explanation:
        "Without a limitation-of-liability clause, exposure is bounded only by what the parties can prove in damages. Most commercial contracts cap liability.",
      position: topPosition(ctx),
    });
  },
};
