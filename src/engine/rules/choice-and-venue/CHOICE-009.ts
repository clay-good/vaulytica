import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit } from "../_helpers.js";

/**
 * CHOICE-009 — Governing law differs from venue jurisdiction
 * (info, choice-and-venue).
 *
 * When the contract picks one state's substantive law but a
 * different state's forum (e.g., "governed by the laws of Delaware,
 * exclusive venue in the courts of California"), the result is a
 * court applying foreign law. This is a legitimate drafting choice
 * — it's common in M&A to pick Delaware law plus a NY or DE forum —
 * but it's usually deliberate, and a mismatch in a non-M&A
 * commercial contract is a common drafting accident worth flagging.
 *
 * Uses the jurisdictions extractor's normalized `jurisdiction_id`
 * when available (e.g. `us-de`, `us-ca`); when neither side has a
 * normalized id but raw text differs textually, the rule still
 * fires.
 */
export const rule: Rule = {
  id: "CHOICE-009",
  version: "1.0.0",
  name: "Governing law differs from venue jurisdiction",
  category: "choice-and-venue",
  default_severity: "info",
  description:
    "Surfaces contracts where the choice-of-law jurisdiction is different from the venue / forum jurisdiction.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const gov = ctx.extracted.jurisdictions.find((j) => j.clause_kind === "governing-law");
    const venue = ctx.extracted.jurisdictions.find((j) => j.clause_kind === "venue");
    if (!gov || !venue) return null;

    // Prefer normalized ids when both are present.
    const govId = gov.jurisdiction_id;
    const venueId = venue.jurisdiction_id;
    const same =
      govId && venueId ? govId === venueId : normalize(gov.raw_text) === normalize(venue.raw_text);
    if (same) return null;

    return emit(ctx, rule, {
      title: "Governing law differs from venue jurisdiction",
      description: `Governing law: \`${gov.raw_text}\` — venue: \`${venue.raw_text}\`.`,
      excerpt: `${gov.raw_text} / ${venue.raw_text}`,
      explanation:
        "Picking one jurisdiction's law and another's forum means a court applies foreign law — adding legal-research cost, raising the risk of jurisdiction-specific surprises (e.g., consumer-protection statutes the chosen-law state didn't anticipate), and sometimes triggering choice-of-law analysis the parties didn't expect. The pairing is legitimate (Delaware law + NY/DE forum is common in M&A) but a mismatch in routine commercial contracts is often unintentional.",
      recommendation:
        "Confirm the pairing is deliberate. If not, align them — typically by changing venue to the chosen-law state. If the mismatch is intentional, note the reason in counsel's notes for future reference.",
      position: gov.position,
    });
  },
};

function normalize(s: string): string {
  return s.trim().toLowerCase().replace(/\s+/g, " ");
}
