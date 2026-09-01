import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch } from "../_helpers.js";

/** DARK-001 — Unilateral modification right (warning). */
export const rule: Rule = {
  id: "DARK-001",
  version: "1.2.0",
  name: "Unilateral modification right",
  category: "dark-patterns",
  default_severity: "warning",
  description: "Detects clauses giving one party the right to modify terms at any time.",
  dkb_citations: ["stat-ftc-deception-statement"],
  check(ctx: RuleContext): Finding | null {
    // Consumer terms-of-service phrase this as "We may update these Terms at any
    // time", "We reserve the right to revise the Terms in our sole discretion" —
    // the party is "we/us", the verb is as often "update/revise/alter" as
    // "modify", and "reserve" is written for the plural subject. The old,
    // narrower list missed the dominant consumer form. The trailing "when"
    // (at any time / from time to time / sole discretion / without notice) is
    // still required, so a mutual "may be amended by written consent" — which
    // names no unilateral timing — does not match.
    const PARTY =
      "(?:Provider|Vendor|Company|Supplier|Contractor|Licensor|Service\\s+Provider|Platform|Site|Operator|We|Us)";
    const VERB = "(?:modify|amend|change|update|revise|alter|adjust)";
    const VERBED = "(?:modified|amended|changed|updated|revised|altered|adjusted)";
    const TERMS = "(?:terms|Agreement|Terms|Policy|Policies)";
    const WHEN =
      "(?:at\\s+any\\s+time|from\\s+time\\s+to\\s+time|in\\s+(?:its|our|their|his|her)\\s+(?:sole\\s+)?discretion|without\\s+(?:prior\\s+)?notice)";
    const hit = firstParagraphMatch(
      ctx,
      new RegExp(
        `\\b${PARTY}\\s+may\\s+${VERB}\\s+(?:these|this|the|its|our)\\s+${TERMS}\\b[^.]{0,40}?${WHEN}` +
          `|(?:this|these|the)\\s+${TERMS}\\s+may\\s+be\\s+${VERBED}\\s+by\\s+${PARTY}\\b[^.]{0,20}?${WHEN}` +
          `|\\b${PARTY}\\s+reserves?\\s+the\\s+right\\s+to\\s+${VERB}\\s+(?:these|this|the|its|our)\\s+${TERMS}\\b`,
        "i",
      ),
    );
    if (!hit) return null;
    if (/\b(?:right\s+to\s+terminate|customer\s+may\s+terminate)\b/i.test(hit.text)) return null;
    return emit(ctx, rule, {
      title: "Unilateral right to modify terms",
      description: hit.match[0],
      excerpt: hit.text.slice(0, 280),
      explanation:
        "A unilateral modification right without a corresponding customer termination right shifts re-pricing and re-negotiation power to the drafter.",
      recommendation:
        "Bound the modification right: notice before a change takes effect (30 days is the norm), no retroactive application to a period already paid for, and a right to terminate without penalty if the change is adverse. A bare right to amend at will is what makes the rest of the contract provisional.",
      position: hit.position,
    });
  },
};
