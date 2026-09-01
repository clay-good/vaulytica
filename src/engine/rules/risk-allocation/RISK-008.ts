import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

/** Every party named as protected by a consequential-damages waiver in `text`. */
const WAIVER_BENEFICIARY =
  /\b(Provider|Vendor|Company|Supplier|Contractor|Licensor|Customer|Client|Licensee|Subscriber|Buyer|Purchaser|Seller)\s+(?:will|shall)\s+not\s+be\s+liable[\s\S]{0,200}?\b(?:consequential|special|incidental|punitive)\s+damages?\b/gi;

function countWaiverBeneficiaries(text: string): number {
  const seen = new Set<string>();
  for (const m of text.matchAll(WAIVER_BENEFICIARY)) {
    if (m[1]) seen.add(m[1].toLowerCase());
  }
  return seen.size;
}

/** RISK-008 — Consequential damages waiver mutuality (warning). */
export const rule: Rule = {
  id: "RISK-008",
  version: "1.2.0",
  name: "Consequential damages waiver mutuality",
  category: "risk-allocation",
  default_severity: "warning",
  description: "Flags when only one party benefits from the consequential-damages waiver.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(
      ctx,
      /\b(?:neither\s+party|neither\s+\w+\s+nor\s+\w+)\s+(?:will|shall)\s+be\s+liable[\s\S]{0,200}\b(?:consequential|special|incidental|punitive)\s+damages?\b/i,
    );
    if (hit) return null;
    // v1.0.0 detected the one-sided waiver only when Provider/Vendor/Company was
    // the protected party, so a waiver protecting only the Supplier / Licensor /
    // Seller (etc.) slipped through entirely. Match the same party vocabulary the
    // beneficiary counter uses; the >=2-beneficiary guard below still clears a
    // genuinely mutual "X … and Y shall not be liable" clause.
    const oneSided = firstParagraphMatch(
      ctx,
      /\b(?:Provider|Vendor|Company|Supplier|Contractor|Licensor|Customer|Client|Licensee|Subscriber|Buyer|Purchaser|Seller)\s+(?:will|shall)\s+not\s+be\s+liable[\s\S]{0,200}\b(?:consequential|special|incidental|punitive)\s+damages?\b/i,
    );
    if (!oneSided) return null;
    // A mutual waiver is just as often drafted as two symmetric grants
    // ("Company shall not be liable … and Customer shall not be liable …") as
    // with the word "neither". Claiming "only one party is protected" over a
    // clause that names two is contradicted by the excerpt printed beneath it.
    if (countWaiverBeneficiaries(oneSided.text) >= 2) return null;
    return emit(ctx, rule, {
      title: "Consequential-damages waiver appears one-sided",
      description: "Only one party is named as protected from consequential damages.",
      excerpt: oneSided.text.slice(0, 280),
      explanation:
        "Consequential-damages waivers are usually mutual. A one-sided version shifts risk significantly toward the unprotected party.",
      recommendation:
        "Make the consequential-damages waiver mutual, or state why it is not. A one-sided waiver leaves the drafting party able to recover a category of loss it has excluded for the other, which is the first thing a reviewer on the other side will strike.",
      position: oneSided.position,
    });
  },
};
