import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit } from "../_helpers.js";
import { US_STATE_PATTERN } from "../../../extract/jurisdictions.js";

/**
 * A domestic venue. This used to be a partial list of eleven commercial
 * states, so every state it omitted — a venue in Boise, Idaho or Nashville,
 * Tennessee — fell through to the foreign-venue finding and was told to
 * confirm a treaty path for enforcing a US judgment. The rule's own subject
 * is "non-US venues", so the test has to know every US state.
 */
const US_VENUE = new RegExp(
  String.raw`\b(?:state|federal|United\s+States|U\.S\.|D\.?C\.?|${US_STATE_PATTERN})\b`,
  "i",
);

// England, Scotland, and Wales are constituent parts of the United Kingdom —
// "the courts of England" is standard drafting and carries the UK's own
// New York / Hague convention status, so the bare names must not fall
// through to the no-treaty warning.
const NY_CONVENTION_PARTIES =
  /\b(?:United\s+States|Canada|Mexico|United\s+Kingdom|Germany|France|Japan|Australia|Singapore|Hong\s+Kong|China|India|Brazil|Spain|Italy|Netherlands|Switzerland|South\s+Korea|Sweden|Ireland|Israel|UAE|Norway|Belgium|Austria|Denmark|Finland|Portugal|Poland|England(?:\s+and\s+Wales)?|Scotland|Wales)\b/i;

/** CHOICE-005 — Foreign venue without enforceability treaty (warning). */
export const rule: Rule = {
  id: "CHOICE-005",
  version: "1.1.0",
  name: "Foreign venue without enforceability treaty",
  category: "choice-and-venue",
  default_severity: "warning",
  description: "Flags non-US venues outside the New York / Hague convention common list.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const venue = ctx.extracted.jurisdictions.find((j) => j.clause_kind === "venue");
    if (!venue) return null;
    if (US_VENUE.test(venue.raw_text)) return null;
    if (NY_CONVENTION_PARTIES.test(venue.raw_text)) return null;
    return emit(ctx, rule, {
      title: `Foreign venue without standard enforceability treaty: ${venue.raw_text}`,
      description: `Venue: ${venue.raw_text}.`,
      excerpt: venue.raw_text,
      explanation:
        "Enforcing a US judgment in a jurisdiction outside the New York or Hague convention can be expensive and uncertain. Confirm a clear path to enforcement exists.",
      position: venue.position,
    });
  },
};
