import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";
import { truncate } from "../../text.js";

/** Every party granted a termination-for-convenience right in `text`. */
const CONVENIENCE_GRANT =
  /\b(Provider|Vendor|Customer|Company|Employer|Client|Licensee|Licensor|Subscriber|Supplier|Contractor)\s+may\s+(?:also\s+|likewise\s+)?terminate[\s\S]{0,160}?\bfor\s+convenience\b/gi;

function countConvenienceGrantees(text: string): number {
  const seen = new Set<string>();
  for (const m of text.matchAll(CONVENIENCE_GRANT)) {
    if (m[1]) seen.add(m[1].toLowerCase());
  }
  return seen.size;
}

/** TERM-003 — Termination asymmetry (warning). */
export const rule: Rule = {
  id: "TERM-003",
  version: "1.3.0",
  name: "Termination asymmetry",
  category: "termination",
  default_severity: "warning",
  description: "Flags when only one party can terminate for convenience.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    // v1.0.0's one-sided trigger listed only Provider/Vendor/Customer/Company/
    // Employer, so a lone "Licensor / Supplier / Contractor / Licensee may
    // terminate for convenience" never fired even though the beneficiary counter
    // (CONVENIENCE_GRANT) already knew those labels. Match the same vocabulary;
    // the >=2-grantee guard still clears a reciprocal two-sentence grant.
    const oneSided = firstParagraphMatch(
      ctx,
      /\b(?:Provider|Vendor|Customer|Company|Employer|Client|Licensee|Licensor|Subscriber|Supplier|Contractor)\s+may\s+terminate[\s\S]{0,160}\bfor\s+convenience\b/i,
    );
    // The mutual escape may not cross a SENTENCE. A termination article
    // routinely opens "Either party may terminate this Agreement if the other
    // materially breaches it and fails to cure within thirty (30) days after
    // written notice" and then grants ONE party a convenience right in the next
    // sentence; at 160 characters across the period the escape swallowed both
    // and reported a reciprocal right nobody granted. It is spelling-sensitive
    // in the worst way — the same clause written "30 days" instead of "thirty
    // (30) days" is seven characters shorter and slips inside the window, so
    // the same document was read two ways depending on how it typed a number.
    // A reciprocal convenience right is stated in ONE sentence.
    // `\.(?=\d)` is the repo's idiom for a decimal point inside a figure.
    const mutual = firstParagraphMatch(
      ctx,
      /\beither\s+party\s+may\s+terminate(?:[^.]|\.(?=\d)){0,160}\bfor\s+convenience\b/i,
    );
    if (!oneSided || mutual) return null;
    // A reciprocal right is often granted as two symmetric sentences ("Company
    // may terminate for convenience … Customer may likewise terminate for
    // convenience …") rather than with "either party". Reporting that as
    // one-sided was contradicted by this rule's own description, which prints
    // the matched text naming both parties.
    if (countConvenienceGrantees(oneSided.text) >= 2) return null;
    return emit(ctx, rule, {
      title: "Only one party may terminate for convenience",
      description: oneSided.match[0].slice(0, 200),
      excerpt: truncate(oneSided.text, 240),
      explanation:
        "An asymmetric termination-for-convenience right is sometimes intentional (e.g., paid-up vendors), but the asymmetry should be deliberate.",
      recommendation:
        "Make the convenience right mutual, or state why only one party has it. A one-way right is normal in a services contract the customer can exit; where it runs the other way, the counterparty is committed for the term and the drafter is not.",
      position: oneSided.position,
    });
  },
};
