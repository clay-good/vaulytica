import type { Rule, RuleContext, Finding } from "../../finding.js";
import { emit, firstParagraphMatch, topPosition } from "../_helpers.js";

/**
 * A termination-for-cause path. The rule wanted the exact phrase "for cause"
 * or "material breach", but a for-cause clause is far more often written as
 * the mechanism — terminate on a breach that is not cured within a notice
 * period:
 *
 *   "terminate this EULA immediately upon written notice if End User breaches
 *    any term of this EULA and fails to cure such breach within 30 days"
 *   "if non-compliance is not cured within thirty (30) days, terminate the
 *    portion of the MSA concerning the processing of personal data"
 *
 * Both were reported as having no for-cause path. `\bmaterial(?:ly)?\s+breach`
 * stays as its own alternative — the leading `\b` already excludes
 * "immaterial breach" (no word boundary sits inside "immaterial"). The new
 * one pairs a termination verb with an uncured breach/default/non-compliance,
 * in either order, within one sentence (`[^.]`) so it cannot stitch a
 * termination verb to an unrelated later clause.
 */
// The defaulting event is a "breach"/"default" OR the failure that constitutes
// one — "fails to pay rent", "fails to perform" — the standard lease/loan
// default trigger.
// The defaulting event's verb takes the noun form too — a lease terminates
// on "Tenant's FAILURE to pay rent", not only "if Tenant fails to pay" — so
// the trigger admits fail / fails / failure / failing.
const BREACH = String.raw`\b(?:(?:breach|default|non-?compliance|non-?performance|violation)\w*|fail(?:s|ure|ing)?\s+to\s+(?:pay|perform|comply|observe|satisfy|make\b[^.]{0,20}?payment))`;
// Uncured: also the present-tense "does not cure" (a lease writes "and does not
// cure within ten days"), not just the past-tense "not cured".
const UNCURED = String.raw`\b(?:(?:does\s+|has\s+|is\s+|are\s+)?not\s+(?:been\s+)?cured?|fails?\s+to\s+cure|uncured|not\s+(?:been\s+)?remedied|fails?\s+to\s+remedy|remains?\s+uncured)\b`;
const FOR_CAUSE = new RegExp(
  String.raw`\bterminat\w+\b[^.]{0,120}\bfor\s+cause\b` +
    "|" +
    String.raw`\bmaterial(?:ly)?\s+breach` +
    "|" +
    String.raw`\bterminat\w+\b[^.]{0,140}${BREACH}[^.]{0,80}${UNCURED}` +
    "|" +
    String.raw`${BREACH}[^.]{0,120}${UNCURED}[^.]{0,120}\bterminat` +
    // Immediate termination on a MATERIAL breach/default/failure, with no cure
    // period — "terminate … in the event of a material default", "terminate …
    // if the Customer breaches any material term", "terminate for … failure to
    // perform any material obligation". The exact-phrase branch above only
    // knew the noun "material breach", so these read as having no for-cause
    // path. Both require a termination verb AND a material defaulting event in
    // the same sentence, so a convenience termination or a bare "material
    // terms" mention does not satisfy it.
    "|" +
    String.raw`\bterminat\w+\b[^.]{0,140}\bmaterial(?:ly)?\b[^.]{0,80}${BREACH}` +
    "|" +
    String.raw`\bterminat\w+\b[^.]{0,140}${BREACH}[^.]{0,80}\bmaterial\b` +
    // The STRICT for-cause form: immediate termination on ANY breach, with no
    // materiality qualifier and no cure period — "the Licensor may terminate
    // this EULA immediately if the Licensee breaches any of its terms". A
    // conditional connector (if / upon / for / in the event of) between the
    // termination verb and the breach — within one sentence — marks it as a
    // for-cause CONDITION, not an incidental mention.
    "|" +
    String.raw`\bterminat\w+\b[^.]{0,60}?\b(?:if|upon|for|in\s+the\s+event\s+(?:of|that))\b[^.]{0,50}?${BREACH}`,
  "i",
);

/** TERM-002 — Termination for cause present (warning). */
export const rule: Rule = {
  id: "TERM-002",
  version: "1.3.0",
  name: "Termination for cause present",
  category: "termination",
  default_severity: "warning",
  description: "Verifies the contract has a termination-for-cause path.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    if (firstParagraphMatch(ctx, FOR_CAUSE)) return null;
    return emit(ctx, rule, {
      title: "No termination-for-cause clause detected",
      description: "The contract does not state a path to terminate for material breach.",
      excerpt: "(no for-cause termination)",
      explanation:
        "Without a for-cause termination path, parties must rely on common-law material-breach doctrines, which are jurisdiction-dependent.",
      position: topPosition(ctx),
    });
  },
};
