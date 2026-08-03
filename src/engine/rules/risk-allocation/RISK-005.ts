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
// the Supplier's liability exceed the purchase price". Further cap phrasings:
//   - "liability … shall/will be no more than / no greater than X";
//   - an in-no-event cap stated on aggregate/total/cumulative/maximum DAMAGES
//     rather than "liability" (the aggregating adjective keeps a stray
//     "liquidated damages" / "consequential damages" mention out);
//   - a negated "be liable" ceiling that states the amount WITHOUT "exceed" —
//     "shall not be liable … more than / in excess of / exceeding", and its
//     "neither party shall be liable … exceeding" form. The negation ("not" /
//     "neither party") is REQUIRED, so a liability FLOOR / basket ("Provider
//     shall be liable for amounts exceeding $10,000") is not misread as a cap.
// These are dollar/fees CAPS; a bare consequential-damages exclusion ("shall
// not be liable for lost profits") is deliberately not a cap and still fires.
const LIMITATION_OF_LIABILITY =
  /\blimitation\s+of\s+liability\b|\baggregate\s+liability\b|\bliabilit(?:y|ies)\b[^.]{0,200}?\b(?:shall|will)\s+not\s+exceed\b|\bliabilit(?:y|ies)\b[^.]{0,200}?\b(?:shall|will)\s+be\s+no\s+(?:more|greater)\s+than\b|\bliabilit(?:y|ies)\b[^.]{0,160}?\b(?:capped|limited)\s+(?:at|to)\b|\b(?:in\s+no\s+event|under\s+no\s+circumstances)\b[^.]{0,140}?\bliabilit(?:y|ies)\b[^.]{0,80}?\bexceed\b|\b(?:in\s+no\s+event|under\s+no\s+circumstances)\b[^.]{0,120}?\b(?:aggregate|total|cumulative|maximum)\s+damages\b[^.]{0,60}?\bexceed\b|\bliabilit(?:y|ies)\b[^.]{0,80}?\b(?:in\s+no\s+event|under\s+no\s+circumstances)\b[^.]{0,40}?\bexceed\b|\b(?:neither\s+(?:party|of\s+the\s+parties)\s+(?:shall|will)\s+be|(?:shall|will)\s+not\s+be)\s+liable\b[^.]{0,70}?\b(?:more\s+than|in\s+excess\s+of|exceeding)\b/i;

/** RISK-005 — Limitation of liability present (warning). */
export const rule: Rule = {
  id: "RISK-005",
  version: "1.3.0",
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
