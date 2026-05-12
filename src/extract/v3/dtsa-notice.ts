/**
 * v3 whistleblower / DTSA notice detector — placeholder.
 *
 * Spec: spec-v3.md §26.
 *
 * Will detect the presence and substantive completeness of the 18 U.S.C. § 1833(b)(3)
 * notice. Substantive completeness means the notice covers:
 *   - disclosure-to-government-or-attorney immunity (§ 1833(b)(1))
 *   - under-seal-court-filing exception (§ 1833(b)(2))
 *   - contractors and consultants in addition to employees
 *
 * Failure to include this notice means the disclosing party cannot recover exemplary
 * damages or attorneys' fees under DTSA against the receiving party — a real loss of
 * statutory remedies that v3 calls out with that exact consequence.
 *
 * Implementation lands in spec-v3.md Step 30.
 */
export {};
