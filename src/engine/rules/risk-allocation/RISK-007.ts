import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch, enclosingSentence } from "../_helpers.js";

// The excluded damage TYPES. "indirect" and "exemplary" were absent — yet the
// canonical waiver enumerates "indirect, incidental, special, consequential,
// exemplary, and punitive damages", so a waiver written with either synonym
// alone ("liable for any indirect damages", "exemplary damages") was missed.
const DMG = "(?:indirect|special|incidental|consequential|punitive|exemplary)";
// The negation that turns "liable for <type> damages" from an affirmative
// statement ("each party REMAINS liable for consequential damages" — the
// opposite of a waiver) into a waiver. "in no event" / "under no circumstances"
// are the dominant LoL openers and were only caught when the clause happened to
// enumerate two or more types; a single-type "in no event shall either party be
// liable for any consequential damages" slipped through. `not (be) liable for`
// is retained.
const NO_LIABILITY =
  "(?:not\\s+(?:be\\s+)?liable\\s+for|(?:in\\s+no\\s+event|under\\s+no\\s+circumstances)[^.]*?\\bliable\\s+for|exclude(?:s|d)?\\s+(?:any|all)?|waive(?:s|d)?\\s+(?:any|all)?)";
const CONSEQ_WAIVER = new RegExp(
  `\\b(?:no\\s+${DMG}|${NO_LIABILITY}\\s+(?:[^.]*?\\b)?${DMG}|${DMG}(?:[,\\s]+(?:and\\s+|or\\s+)?${DMG}){1,3})[^.]*?\\bdamages?\\b`,
  "i",
);

/** RISK-007 — Consequential damages waiver present (info). */
export const rule: Rule = {
  id: "RISK-007",
  version: "1.2.0",
  name: "Consequential damages waiver present",
  category: "risk-allocation",
  default_severity: "info",
  description: "Detects waivers of consequential / special / incidental / punitive damages.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(ctx, CONSEQ_WAIVER);
    if (!hit) return null;
    // The enumeration branch fires on any list of ≥2 damage types before
    // "damages" — which also matches an affirmative INDEMNITY that *assumes*
    // those damages ("Tenant shall indemnify Landlord for all direct, indirect
    // and consequential damages") — the opposite of a waiver. Suppress when an
    // indemnity verb governs the enumeration and the same sentence carries no
    // waiver / exclusion signal.
    const sentence = enclosingSentence(hit.text, hit.match.index);
    const hasWaiverSignal =
      /\b(?:waiv|exclud|disclaim|no\s+liability|not\s+(?:be\s+)?liable|in\s+no\s+event|under\s+no\s+circumstances|shall\s+not\b|neither\b[^.]*?\bliable)/i.test(
        sentence,
      );
    if (/\bindemnif/i.test(sentence) && !hasWaiverSignal) return null;
    return emit(ctx, rule, {
      title: "Consequential damages waiver present",
      description: hit.match[0],
      excerpt: hit.text.slice(0, 240),
      explanation:
        "A waiver of consequential, special, incidental, and punitive damages is standard in commercial contracts. The waiver should be mutual unless deliberately asymmetric.",
      position: hit.position,
    });
  },
};
