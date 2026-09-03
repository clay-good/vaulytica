import type { Rule, RuleContext, Finding } from "../../finding.js";
import {
  emit,
  enclosingSentence,
  excerptWindow,
  firstParagraphMatch,
  MODAL_QUALIFIER,
} from "../_helpers.js";

/**
 * RISK-016 — Insurance requirement without coverage minimum
 * (warning, risk-allocation).
 *
 * Fires when an insurance clause requires the counterparty to
 * `maintain insurance` / `carry insurance` / `procure coverage`
 * without specifying a coverage minimum (a per-occurrence amount,
 * an aggregate amount, or a named limit). A bare "shall maintain
 * insurance" clause is essentially unenforceable — it gives the
 * indemnitee no recourse if the counterparty maintains a $1,000
 * homeowners policy in lieu of commercial GL.
 */
export const rule: Rule = {
  id: "RISK-016",
  version: "1.7.0",
  name: "Insurance requirement without coverage minimum",
  category: "risk-allocation",
  default_severity: "warning",
  description:
    "Fires when the contract requires insurance but does not specify a per-occurrence or aggregate coverage minimum.",
  dkb_citations: [],
  check(ctx: RuleContext): Finding | null {
    const hit = firstParagraphMatch(
      ctx,
      // The requirement is also written with an "is/are required-to" modal, an
      // "purchase / secure" verb, or in the PASSIVE ("Insurance shall be
      // maintained by …") — all the same bare insurance mandate, previously
      // matched only in the active shall-maintain voice. "provide / have" are
      // deliberately omitted so "shall provide insurance CERTIFICATES" and
      // "shall have insurance PROCEEDS applied" are not misread as the mandate.
      new RegExp(
        `\\b(?:(?:shall|must|will|agrees?\\s+to|(?:is|are)\\s+(?:required|obligated)\\s+to)${MODAL_QUALIFIER}(?:maintain|carry|procure|obtain|purchase|secure|keep\\s+in\\s+force)\\s+[^.]{0,80}\\binsurance\\b|insurance\\s+(?:shall|must|will)\\s+be\\s+(?:maintained|carried|procured|obtained|purchased|secured|kept\\s+in\\s+force))`,
        "i",
      ),
    );
    if (!hit) return null;
    // HEALTH insurance maintained FOR A PERSON is not a commercial coverage
    // requirement and never carries a per-occurrence limit. A marital
    // settlement agreement's "Wife shall maintain health and dental insurance
    // for the Children through her employer while it is available at
    // reasonable cost" was reported as an insurance requirement with no
    // coverage minimum — a minimum no such clause has ever stated. The same
    // sentence shape appears in every employment and physician agreement.
    if (
      /\b(?:health|dental|vision|medical|hospitali[sz]ation|disability|life)\s+(?:and\s+\w+\s+)?insurance\b/i.test(
        hit.match[0],
      ) &&
      !/\b(?:liability|professional|commercial|general|umbrella|excess|property|casualty|cyber|errors\s+and\s+omissions|workers['’]?\s+compensation)\s+insurance\b/i.test(
        hit.match[0],
      )
    )
      return null;

    // PROPERTY and HAZARD insurance state their minimum as a STANDARD rather
    // than a number — "hazard insurance for at least its full replacement
    // cost" is the minimum every secured lender requires and every SBA loan
    // agreement carries, and there is no dollar figure in it to find.
    // Check the same paragraph for a coverage minimum. The minimum
    // can be expressed as `$1,000,000`, `$1M`, `one million dollars`,
    // `at least $X`, `not less than $X`, or `$X per occurrence`.
    const COVERAGE_MIN =
      /(?:[$€£¥₹₩₽]|\b(?:USD|EUR|GBP|CHF|CAD|AUD|JPY)\s*)\s*[\d,]+(?:\.\d+)?\s*(?:k|m|mm|million|thousand)?|(?:at\s+least|not\s+less\s+than|minimum\s+of)\s+(?:[$€£¥₹₩₽]|\b(?:USD|EUR|GBP|CHF|CAD|AUD|JPY)\s*)?\s*[\d,]+|(?:one|two|three|four|five|six|seven|eight|nine|ten)\s+million\s+dollars?|per\s+occurrence|aggregate\s+(?:of|limit)|combined\s+single\s+limit|(?:full\s+)?replacement\s+(?:cost|value)|actual\s+cash\s+value/i;
    // Scope the GENERAL coverage-minimum check (which includes a bare dollar
    // figure) to the insurance clause's own sentence — otherwise an unrelated
    // dollar elsewhere in the paragraph (e.g. the contract fee) suppressed the
    // warning. But the limit is very often stated in the NEXT sentence ("shall
    // maintain CGL insurance. Such insurance shall have limits of not less than
    // $1,000,000 per occurrence"), so a second, paragraph-wide check accepts
    // only INSURANCE-ANCHORED minimums — per-occurrence / aggregate / combined
    // single limit / "limits|coverage … $X" / "not less than $X" / "X million
    // dollars" — none of which a bare contract fee matches.
    const COVERAGE_MIN_ANYWHERE =
      /\bper\s+occurrence\b|\bcombined\s+single\s+limit\b|\baggregate\s+(?:limit|of)\b|\bin\s+the\s+aggregate\b|\b(?:limits?|coverage)\b[^.]{0,40}?(?:[$€£¥₹₩₽]|\b(?:USD|EUR|GBP|CHF|CAD|AUD|JPY)\s*)\s*[\d,]+|\b(?:not\s+less\s+than|at\s+least|minimum\s+of)\s+(?:[$€£¥₹₩₽]|\b(?:USD|EUR|GBP|CHF|CAD|AUD|JPY)\s*)\s*[\d,]+|\b(?:one|two|three|four|five|six|seven|eight|nine|ten)\s+million\s+dollars?\b/i;
    // The minimum can live in ANOTHER SECTION, and the clause point at it. A
    // venue rental requires the caterer to "carry THE INSURANCE DESCRIBED IN
    // SECTION 5", and Section 5 states $1,000,000 per occurrence and
    // $2,000,000 aggregate — so the requirement has its minimum, one
    // cross-reference away, and the finding asked the drafter to add a figure
    // the document already gives. Scoped to the clause's own sentence, so a
    // paragraph that merely mentions another section elsewhere is untouched.
    const MINIMUM_BY_CROSS_REFERENCE =
      /\b(?:insurance|coverages?|limits?|policies)\b[^.]{0,40}?\b(?:described|set\s+forth|required|specified|listed|provided\s+for)\s+(?:in|under|by)\s+(?:this\s+)?(?:Section|Article|Exhibit|Schedule|Annexure|Annex|Appendix|Paragraph|Clause|§§?)/i;
    const sentence = enclosingSentence(hit.text, hit.match.index);
    if (
      COVERAGE_MIN.test(sentence) ||
      MINIMUM_BY_CROSS_REFERENCE.test(sentence) ||
      COVERAGE_MIN_ANYWHERE.test(hit.text)
    )
      return null;

    return emit(ctx, rule, {
      title: "Insurance requirement without coverage minimum",
      description: hit.match[0],
      excerpt: excerptWindow(hit.text, hit.match.index, 30, 280),
      explanation:
        "A bare `shall maintain insurance` clause is essentially unenforceable: the indemnitee has no way to test whether the counterparty's coverage is adequate, and a $1,000 homeowner policy formally satisfies the clause. Standard commercial drafting names a per-occurrence limit (typically $1M), an aggregate limit (typically $2M), and the coverage type (CGL, professional liability, cyber, etc.).",
      recommendation:
        "Specify (1) the coverage types required (CGL, professional liability, errors & omissions, cyber, workers' comp, auto), (2) the per-occurrence limit, (3) the aggregate limit, and (4) the certificate-of-insurance / additional-insured cooperation obligations.",
      position: hit.position,
    });
  },
};
