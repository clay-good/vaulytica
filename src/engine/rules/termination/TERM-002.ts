import type { Rule, RuleContext, Finding } from "../../finding.js";
import { amendsParentAgreement, emit, firstParagraphMatch, topPosition } from "../_helpers.js";

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
const BREACH = String.raw`\b(?:(?:breach|default|non-?compliance|non-?performance|violation)\w*|fail(?:s|ure|ing)?\s+to\s+(?:pay|perform|comply|observe|satisfy|maintain|provide|obtain|deliver|furnish|keep|meet|cure|remedy|make\b[^.]{0,20}?payment))`;
// Uncured: also the present-tense "does not cure" (a lease writes "and does not
// cure within ten days"), not just the past-tense "not cured".
const UNCURED = String.raw`\b(?:(?:does\s+|has\s+|is\s+|are\s+)?not\s+(?:been\s+)?cured?|fails?\s+to\s+cure|uncured|not\s+(?:been\s+)?remedied|fails?\s+to\s+remedy|remains?\s+uncured)\b`;
// The termination VERB, in the consumer register as well as the commercial
// one. A card agreement, a rewards program, and an API terms page do not
// "terminate this Agreement" — they "close the Account", "end your
// membership", "cancel your subscription". Every branch below keyed on
// `terminat\w+` alone, so a document whose Default section says "we may close
// the Account and require you to pay the full balance immediately" was
// reported as stating no path to terminate for material breach.
const TERMINATE = String.raw`\b(?:terminat\w+|clos(?:e|es|ed|ing)\s+(?:the\s+|your\s+)?(?:account|membership)|end(?:s|ed|ing)?\s+(?:the\s+|this\s+|your\s+)?(?:membership|internship|engagement|agreement|relationship|arrangement)|cancel(?:s|led|ling|ed|ing)?\s+(?:the\s+|your\s+)?(?:account|membership|subscription))`;

const FOR_CAUSE = new RegExp(
  // Termination on ENUMERATED cause grounds. A regulated-services agreement
  // does not write "material breach"; it names the grounds — "Hospital may
  // terminate immediately upon: (a) suspension, revocation, or restriction of
  // Medical Director's license or DEA registration; … (d) failure to maintain
  // the insurance required by Section 10". Every branch below wanted the noun
  // "breach"/"default" or the phrase "for cause", so a medical director
  // agreement with a full Termination section was told it states no path to
  // terminate for material breach.
  //
  // The enumeration is what distinguishes this from a convenience clause:
  // "terminate immediately upon written notice" carries no list.
  String.raw`${TERMINATE}[^.]{0,60}\b(?:immediately|forthwith|at\s+once)\b[^.]{0,60}?\bupon\b[^.:]{0,30}?:` +
    "|" +
    String.raw`${TERMINATE}[^.]{0,80}\bupon\s+the\s+occurrence\s+of\s+any\s+of\s+the\s+following\b` +
    "|" +
    String.raw`${TERMINATE}[^.]{0,120}\bfor\s+cause\b` +
    "|" +
    String.raw`\bmaterial(?:ly)?\s+breach` +
    "|" +
    String.raw`${TERMINATE}[^.]{0,140}${BREACH}[^.]{0,80}${UNCURED}` +
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
    String.raw`${TERMINATE}[^.]{0,140}\bmaterial(?:ly)?\b[^.]{0,80}${BREACH}` +
    "|" +
    String.raw`${TERMINATE}[^.]{0,140}${BREACH}[^.]{0,80}\bmaterial\b` +
    // The STRICT for-cause form: immediate termination on ANY breach, with no
    // materiality qualifier and no cure period — "the Licensor may terminate
    // this EULA immediately if the Licensee breaches any of its terms". A
    // conditional connector (if / upon / for / in the event of) between the
    // termination verb and the breach — within one sentence — marks it as a
    // for-cause CONDITION, not an incidental mention.
    "|" +
    String.raw`${TERMINATE}[^.]{0,60}?\b(?:if|upon|for|in\s+the\s+event\s+(?:of|that))\b[^.]{0,50}?${BREACH}` +
    // The same condition written FIRST — "If you are in default, we may close
    // the Account", "In the event of a breach by Tenant, Landlord may
    // terminate". Every conditional branch above reads left to right from the
    // termination verb, so the fronted condition — as ordinary as the trailing
    // one — was reported as no for-cause path at all.
    "|" +
    // "ON a default, Lessor may terminate any or all Schedules" is the
    // remedies sentence of every equipment lease and secured-lending document,
    // and the connector set had only if / upon / in the event of. The article
    // is required after "on" so an ordinary "on delivery" / "on notice" cannot
    // open the branch.
    String.raw`\b(?:if|upon|in\s+the\s+event\s+(?:of|that)|on\s+(?:a|an|any|the))\b[^.]{0,80}?${BREACH}[^.]{0,120}?${TERMINATE}` +
    // The "Event of Default" idiom splits the for-cause path across sentences: a
    // Default section defines "Event of Default" (a rent/obligation failure not
    // cured within a notice period), and a separate Remedies section says "Upon
    // an Event of Default, the Landlord may terminate". The branches above want
    // the breach and the termination verb in ONE sentence, so a lease/loan whose
    // for-cause path is written this standard way was reported as having none.
    // "Event of Default" is itself the term of art for the defaulting event, so
    // pairing it with a termination verb in one sentence is an unambiguous
    // for-cause path (a mere mention of the phrase without "terminate" is not).
    "|" +
    String.raw`${TERMINATE}[^.]{0,80}\bEvent\s+of\s+Default\b` +
    "|" +
    String.raw`\bEvent\s+of\s+Default\b[^.]{0,80}${TERMINATE}` +
    // The ENUMERATED termination-grounds list puts the for-cause ground far from
    // the "terminated" verb: "This Agreement may be terminated … (a) by mutual
    // consent; (b) if the Closing has not occurred by …; or (c) by either party
    // if the other has breached … and such breach is not cured within thirty
    // (30) days." The (a)/(b) clauses push the breach past the 140-char window
    // above, and the breach-to-uncured span itself exceeds 80. Still one
    // sentence (the list is semicolon-separated), so `[^.]` keeps it from
    // stitching across a period; the wider windows reach the enumerated ground.
    "|" +
    String.raw`${TERMINATE}[^.]{0,280}?${BREACH}[^.]{0,150}?${UNCURED}`,
  "i",
);

/** TERM-002 — Termination for cause present (warning). */
export const rule: Rule = {
  id: "TERM-002",
  version: "1.10.0",
  name: "Termination for cause present",
  category: "termination",
  default_severity: "warning",
  description: "Verifies the contract has a termination-for-cause path.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    // An amendment does not restate what the parent agreement already
    // says. Its ratification clause — "Except as expressly modified by
    // this Amendment, the Lease remains in full force and effect" — is
    // the drafting convention for saying exactly that, and reporting
    // this clause as absent has no answer short of restating the parent
    // inside its own amendment.
    if (amendsParentAgreement(ctx)) return null;
    if (firstParagraphMatch(ctx, FOR_CAUSE)) return null;
    return emit(ctx, rule, {
      title: "No termination-for-cause clause detected",
      description: "The contract does not state a path to terminate for material breach.",
      excerpt: "(no for-cause termination)",
      explanation:
        "Without a for-cause termination path, parties must rely on common-law material-breach doctrines, which are jurisdiction-dependent.",
      recommendation:
        "Add a termination-for-cause clause: what counts as a material breach, the cure period (30 days is the norm), who may terminate, and whether insolvency or a change of control is an immediate-termination event.",
      position: topPosition(ctx),
    });
  },
};
