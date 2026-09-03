import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstUnnegatedParagraphMatch } from "../_helpers.js";

const DISPUTE_SIBLING = String.raw`(?:action|suit|proceeding|hearing|investigation|claim)s?`;
/**
 * The arbitration token inside a proper NAME, not a clause.
 *
 * "administered by the American Arbitration Association", "under the AAA
 * Commercial Arbitration Rules" — the word names an institution or a rule set.
 * A franchise agreement whose dispute clause sends the parties to MEDIATION
 * administered by the American Arbitration Association and then to court was
 * reported as having an arbitration clause with the seat not specified, which
 * is a drafting fix for a clause it does not contain.
 *
 * Tested against the text that FOLLOWS the match, so a paragraph that names
 * the institution AND agrees to arbitrate still fires on its other token —
 * "shall be submitted to binding arbitration … administered by the American
 * Arbitration Association" has two, and only the second is suppressed.
 */
const INSTITUTION_NAME_TAIL =
  /^\s+(?:Association|Institute|Centre|Center|Chamber|Forum|Society|Council|Board|Rules)\b/;

// 1.4.0 — the list item is as often the ADJECTIVE as the noun. A D&O policy
// defines its trigger as '"Claim" means a written demand …; a civil, criminal,
// administrative, regulatory, or ARBITRAL PROCEEDING; a formal regulatory
// investigation …' — where "arbitral" modifies the sibling noun rather than
// standing beside it, so the comma-adjacency both branches required is never
// there. The policy was reported as having an arbitration clause "with the
// seat not specified", which is a drafting fix for a clause it does not
// contain. Still confined to a definitional sentence, so a real arbitration
// clause that speaks of "the arbitral proceeding" is untouched.
const ENUMERATED_IN_DEFINITION = new RegExp(
  String.raw`\b(?:means|(?:shall|will)\s+mean)\b[^.]{0,300}?(?:${DISPUTE_SIBLING}\s*,\s*(?:or\s+)?arbitration\b|\barbitration\s*,\s*(?:or\s+)?${DISPUTE_SIBLING}|\barbitral\s+${DISPUTE_SIBLING})`,
  "i",
);

/** CHOICE-006 — Arbitration clause present (info). */
export const rule: Rule = {
  id: "CHOICE-006",
  version: "1.4.0",
  name: "Arbitration clause present",
  category: "choice-and-venue",
  default_severity: "info",
  description: "Detects an arbitration clause and surfaces its scope.",
  dkb_citations: ["stat-9-usc-2"],
  check(ctx: RuleContext): Finding | null {
    // International clauses often lead with "arbitral tribunal" or refer to
    // "arbitrators" without the word "arbitration". "arbitral" is a separate stem
    // from "arbitrat…", and "arbitrary" (a different word) is excluded by
    // requiring the "-al"/"-or" suffix, not a bare "arbitr".
    const hit = firstUnnegatedParagraphMatch(
      ctx,
      /\barbitrat(?:e|ed|ing|ion|ors?)\b|\barbitral\b/i,
      undefined,
      (paragraph, index) =>
        // Tested from the PARAGRAPH START, not from the enclosing sentence. A
        // multi-limb definition separates its limbs with SEMICOLONS — '"Claim"
        // means a written demand …; a civil, criminal, administrative,
        // regulatory, or arbitral proceeding; a formal regulatory
        // investigation …' — and `enclosingSentence` treats a semicolon as a
        // boundary, so it returned " a civil, criminal, administrative,
        // regulatory, or arbitral proceeding;" and the "means" the guard is
        // anchored on was never in the window. The `[^.]{0,300}` bound inside
        // the pattern is what still stops it reaching into a previous
        // SENTENCE.
        ENUMERATED_IN_DEFINITION.test(paragraph.slice(0, index + 40)) ||
        INSTITUTION_NAME_TAIL.test(paragraph.slice(index + "arbitration".length, index + 40)),
    );
    if (!hit) return null;
    // A definition that ENUMERATES dispute forums mentions arbitration without
    // agreeing to it: '"Proceeding" means any threatened, pending, or completed
    // action, suit, arbitration, alternative dispute resolution proceeding,
    // administrative hearing, or investigation'. Every indemnification
    // agreement, D&O policy, and litigation-hold notice carries that list, and
    // each was reported as having an arbitration clause "with the seat not
    // specified" — a drafting fix that makes no sense for a definition.
    //
    // Suppressed only when the arbitration token is comma-adjacent to a
    // sibling dispute noun inside a definitional sentence. A paragraph that
    // both defines "Dispute" and sends disputes to arbitration is untouched,
    // because there the token is not a list item.
    const seat = ctx.extracted.jurisdictions.find((j) => j.clause_kind === "arbitration-seat");
    return emit(ctx, rule, {
      title: "Arbitration clause present",
      description: seat
        ? `Seat: ${seat.raw_text}`
        : "Arbitration clause present; seat not specified.",
      excerpt: hit.text.slice(0, 240),
      explanation:
        "Arbitration is binding under the Federal Arbitration Act (9 U.S.C. § 2). The seat, governing rules (AAA, JAMS, ICC), and language are the key parameters.",
      position: hit.position,
    });
  },
};
