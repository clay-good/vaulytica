import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, enclosingSentence, firstUnnegatedParagraphMatch } from "../_helpers.js";

const DISPUTE_SIBLING = String.raw`(?:action|suit|proceeding|hearing|investigation|claim)s?`;
const ENUMERATED_IN_DEFINITION = new RegExp(
  String.raw`\b(?:means|shall\s+mean)\b[^.]{0,300}?(?:${DISPUTE_SIBLING}\s*,\s*(?:or\s+)?arbitration\b|\barbitration\s*,\s*(?:or\s+)?${DISPUTE_SIBLING})`,
  "i",
);

/** CHOICE-006 — Arbitration clause present (info). */
export const rule: Rule = {
  id: "CHOICE-006",
  version: "1.2.0",
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
      (paragraph, index) => ENUMERATED_IN_DEFINITION.test(enclosingSentence(paragraph, index)),
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
