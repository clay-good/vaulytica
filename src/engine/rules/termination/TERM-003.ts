import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

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
  version: "1.0.0",
  name: "Termination asymmetry",
  category: "termination",
  default_severity: "warning",
  description: "Flags when only one party can terminate for convenience.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const oneSided = firstParagraphMatch(
      ctx,
      /\b(?:Provider|Vendor|Customer|Company|Employer)\s+may\s+terminate[\s\S]{0,160}\bfor\s+convenience\b/i,
    );
    const mutual = firstParagraphMatch(
      ctx,
      /\beither\s+party\s+may\s+terminate[\s\S]{0,160}\bfor\s+convenience\b/i,
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
      excerpt: oneSided.text.slice(0, 240),
      explanation:
        "An asymmetric termination-for-convenience right is sometimes intentional (e.g., paid-up vendors), but the asymmetry should be deliberate.",
      position: oneSided.position,
    });
  },
};
