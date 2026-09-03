import type { Rule, RuleContext, Finding } from "../../finding.js";
import { amendsParentAgreement, emit, firstParagraphMatch, topPosition } from "../_helpers.js";
import { CONSEQ_WAIVER } from "./RISK-007.js";

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
// The bare-label branches ("limitation of liability" / "aggregate liability")
// carry a negative lookbehind so an explicit DISCLAIMER of any cap — "there
// shall be NO limitation of liability", "WITHOUT any limitation of liability",
// "NO aggregate liability cap" — is not misread as a cap being present. That is
// the worst case for the reviewing party (unbounded exposure), and it must
// fire, not stay silent. A genuine cap heading, a carve-out ("this limitation
// of liability does not apply to …"), and "the limitation of liability set
// forth herein" all lack the negator and still match.
const LIMITATION_OF_LIABILITY =
  /(?<!\b(?:no|without)\s(?:any\s)?)\blimitation\s+of\s+liability\b|(?<!\b(?:no|without)\s(?:any\s)?)\baggregate\s+liability\b|\bliabilit(?:y|ies)\b[^.]{0,200}?\b(?:shall|will)\s+not\s+exceed\b|\bliabilit(?:y|ies)\b[^.]{0,200}?\b(?:shall|will)\s+be\s+no\s+(?:more|greater)\s+than\b|\bliabilit(?:y|ies)\b[^.]{0,160}?\b(?<!\bnot\s)(?:capped|limited)\s+(?:at|to)\b|\b(?:in\s+no\s+event|under\s+no\s+circumstances)\b[^.]{0,140}?\bliabilit(?:y|ies)\b[^.]{0,80}?\bexceed\b|\b(?:in\s+no\s+event|under\s+no\s+circumstances)\b[^.]{0,120}?\b(?:aggregate|total|cumulative|maximum)\s+damages\b[^.]{0,60}?\bexceed\b|\bliabilit(?:y|ies)\b[^.]{0,80}?\b(?:in\s+no\s+event|under\s+no\s+circumstances)\b[^.]{0,40}?\bexceed\b|\b(?:neither\s+(?:party|of\s+the\s+parties)\s+(?:shall|will)\s+be|(?:shall|will)\s+not\s+be)\s+liable\b[^.]{0,70}?\b(?:more\s+than|in\s+excess\s+of|exceeding)\b|\b(?:in\s+no\s+event|under\s+no\s+circumstances)\b[^.]{0,120}?\bliable\b[^.]{0,80}?\b(?:more\s+than|in\s+excess\s+of|exceeding)\b|\b(?:maximum|total|cumulative|aggregate)\s+liabilit(?:y|ies)\b[^.]{0,120}?\b(?:is|are|shall\s+be|will\s+be)\s+(?<!\bnot\s)(?:limited\s+to|capped\s+at|no\s+(?:more|greater)\s+than|[$€£¥₹₩₽]|the\s+(?:purchase\s+price|fees?|premium|amounts?|total|greater|lesser|aggregate))\b/i;

/** RISK-005 — Limitation of liability present (warning). */
export const rule: Rule = {
  id: "RISK-005",
  version: "1.8.0",
  name: "Limitation of liability present",
  category: "risk-allocation",
  default_severity: "warning",
  description: "Detects a limitation-of-liability clause; fires when absent.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    // An amendment does not restate what the parent agreement already
    // says. Its ratification clause — "Except as expressly modified by
    // this Amendment, the Lease remains in full force and effect" — is
    // the drafting convention for saying exactly that, and reporting
    // this clause as absent has no answer short of restating the parent
    // inside its own amendment.
    if (amendsParentAgreement(ctx)) return null;
    if (firstParagraphMatch(ctx, LIMITATION_OF_LIABILITY)) return null;
    // A consequential-damages WAIVER is a limitation of liability, and this
    // rule's own recommendation says so: it asks for "a cap …, A
    // CONSEQUENTIAL-DAMAGES WAIVER, and the carve-outs". A master purchase
    // agreement whose section 9.4 waives consequential, incidental, indirect,
    // special, and punitive damages, with carve-outs, was told that Vaulytica
    // "did not find a limitation-of-liability clause" — while RISK-007
    // reported the waiver in the same run. Two findings, one document,
    // opposite claims.
    //
    // What that document actually lacks is the CAP, so the finding now says
    // that instead of asserting an absence that is not there. The waiver
    // pattern is IMPORTED from RISK-007 rather than copied, so the two rules
    // cannot drift into disagreeing about what a waiver is.
    const waiver = firstParagraphMatch(ctx, CONSEQ_WAIVER);
    if (waiver) {
      return emit(ctx, rule, {
        title: "Liability limited by waiver only; no cap stated",
        description:
          "A consequential-damages waiver is present, but no clause caps the aggregate liability either party can incur.",
        excerpt: waiver.text.slice(0, 240),
        explanation:
          "A waiver of indirect and consequential damages bounds the KIND of loss recoverable; it does not bound the AMOUNT. Direct damages remain open-ended, and on a supply or services contract those are usually the larger exposure.",
        recommendation:
          "Add an aggregate cap tied to something knowable — the fees paid in a stated period, or a figure — and state the carve-outs that sit outside it.",
        position: waiver.position,
      });
    }
    return emit(ctx, rule, {
      title: "No limitation-of-liability clause detected",
      description: "Vaulytica did not find a limitation-of-liability clause.",
      excerpt: "(no LoL clause)",
      explanation:
        "Without a limitation-of-liability clause, exposure is bounded only by what the parties can prove in damages. Most commercial contracts cap liability.",
      recommendation:
        "Add a limitation-of-liability clause: a cap tied to something knowable (the fees paid in a stated period, or a figure), a consequential-damages waiver, and the carve-outs that are not capped — usually confidentiality, indemnity, fraud, and wilful misconduct.",
      position: topPosition(ctx),
    });
  },
};
