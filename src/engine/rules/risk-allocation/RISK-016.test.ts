import { describe, expect, it } from "vitest";
import { rule as RISK_016 } from "./RISK-016.js";
import { buildContext } from "../../_test-fixtures.js";

describe("RISK-016 — insurance requirement without coverage minimum", () => {
  it("fires when insurance is required without any coverage amount", () => {
    const ctx = buildContext([
      "Insurance",
      "Contractor shall maintain commercial general liability insurance during the term of this Agreement.",
    ]);
    const f = RISK_016.check(ctx);
    expect(f?.severity).toBe("warning");
    expect(f?.title).toMatch(/without coverage minimum/i);
  });

  it("fires on `must carry insurance` without amount", () => {
    const ctx = buildContext([
      "Insurance",
      "Vendor must carry professional liability insurance during the engagement.",
    ]);
    expect(RISK_016.check(ctx)).not.toBeNull();
  });

  it("is silent when a per-occurrence minimum is specified", () => {
    const ctx = buildContext([
      "Insurance",
      "Contractor shall maintain commercial general liability insurance with limits of $1,000,000 per occurrence and $2,000,000 aggregate.",
    ]);
    expect(RISK_016.check(ctx)).toBeNull();
  });

  it("is silent when `not less than $X` framing is used", () => {
    const ctx = buildContext([
      "Insurance",
      "Vendor shall maintain professional liability insurance of not less than $1,000,000 per claim.",
    ]);
    expect(RISK_016.check(ctx)).toBeNull();
  });

  it("is silent when `at least $X million` framing is used", () => {
    const ctx = buildContext([
      "Insurance",
      "Contractor shall procure insurance at least $5,000,000 in aggregate coverage.",
    ]);
    expect(RISK_016.check(ctx)).toBeNull();
  });

  it("is silent when no insurance clause exists", () => {
    const ctx = buildContext([
      "Term",
      "This Agreement is effective for two years from the Effective Date.",
    ]);
    expect(RISK_016.check(ctx)).toBeNull();
  });

  // v1.1.0 — the mandate is also written with an "is required to" modal, a
  // "purchase / secure" verb, or in the passive voice, all previously missed.
  it("fires on the required-to / purchase / passive forms without a minimum", () => {
    for (const body of [
      "Vendor is required to carry professional liability insurance during the engagement.",
      "Tenant shall purchase fire and casualty insurance for the premises.",
      "Insurance shall be maintained by the Contractor throughout the term.",
    ]) {
      const f = RISK_016.check(buildContext(["Insurance", body]));
      expect(f, body).not.toBeNull();
      expect(f?.severity).toBe("warning");
    }
  });

  it("does not misread an insurance-CERTIFICATE or insurance-PROCEEDS clause as the mandate", () => {
    expect(
      RISK_016.check(
        buildContext([
          "Insurance",
          "Contractor shall provide insurance certificates to Owner annually.",
        ]),
      ),
    ).toBeNull();
    expect(
      RISK_016.check(
        buildContext([
          "Casualty",
          "The Owner shall have insurance proceeds applied to restoration.",
        ]),
      ),
    ).toBeNull();
  });

  it("is silent when the coverage minimum is stated in a following sentence (v1.2.0)", () => {
    for (const clause of [
      "Contractor shall maintain commercial general liability insurance. Such insurance shall have limits of not less than $1,000,000 per occurrence and $2,000,000 in the aggregate.",
      "Vendor shall maintain professional liability insurance. Coverage shall be at least $5,000,000.",
      "Vendor shall maintain insurance. The policy shall provide coverage of one million dollars.",
    ]) {
      expect(RISK_016.check(buildContext(["Insurance", clause])), clause).toBeNull();
    }
  });

  it("still fires when a later sentence names only an unrelated fee, not a coverage minimum (v1.2.0)", () => {
    expect(
      RISK_016.check(
        buildContext([
          "Insurance",
          "Contractor shall maintain commercial general liability insurance. The total contract fee is $500,000.",
        ]),
      ),
    ).not.toBeNull();
  });
});

/**
 * HEALTH insurance maintained for a PERSON is not a commercial coverage
 * requirement and never states a per-occurrence limit. A marital settlement
 * agreement was reported for stating no coverage minimum on a clause that
 * could not have one.
 */
describe("RISK-016 v1.3.0 — personal health coverage is not a coverage requirement", () => {
  const doc = (...paras: string[]) => buildContext(["Insurance", ...paras]);

  it.each([
    "Wife shall maintain health and dental insurance for the Children through her employer while it is available at reasonable cost.",
    "The Company shall maintain medical insurance for Executive on the same terms as other senior executives.",
    "Employer shall maintain disability insurance for the Employee during the term.",
  ])("is silent on: %s", (sentence) => {
    expect(RISK_016.check(doc(sentence))).toBeNull();
  });

  it("still fires on a commercial policy with no stated minimum", () => {
    expect(
      RISK_016.check(
        doc(
          "Contractor shall maintain commercial general liability insurance throughout the term.",
        ),
      ),
    ).not.toBeNull();
  });

  /** A clause naming BOTH is a commercial requirement and still reports. */
  it("still fires where a liability policy sits beside a health policy", () => {
    expect(
      RISK_016.check(
        doc(
          "Provider shall maintain professional liability insurance and health insurance for its personnel throughout the term.",
        ),
      ),
    ).not.toBeNull();
  });
});

/**
 * The minimum can live in ANOTHER SECTION (v1.5.0).
 *
 * A venue rental requires the caterer to "carry THE INSURANCE DESCRIBED IN
 * SECTION 5", and Section 5 states $1,000,000 per occurrence and $2,000,000 in
 * the aggregate. The requirement has its minimum, one cross-reference away,
 * and the finding asked the drafter to add a figure the document already
 * gives.
 */
describe("RISK-016 — a coverage minimum stated by cross-reference", () => {
  it.each([
    [
      "a section",
      "The caterer shall carry the insurance described in Section 5 and shall name Venue as an additional insured.",
    ],
    [
      "an exhibit",
      "Contractor shall maintain the insurance coverages set forth in Exhibit B throughout the term.",
    ],
    [
      "a required-by form",
      "Vendor shall procure the insurance required by Section 9.3 before commencing work.",
    ],
  ])("is silent where the clause points at %s", (_label, clause) => {
    expect(RISK_016.check(buildContext(["Venue Rental Agreement", clause]))).toBeNull();
  });

  // The same locator written with the SIGN — the list ran Section / Article /
  // Exhibit / Schedule / Annex and stopped, so "described in § 5" was read as
  // pointing nowhere.
  it("is silent where the clause points at a section written with the sign", () => {
    expect(
      RISK_016.check(
        buildContext([
          "Venue Rental Agreement",
          "Caterer shall carry the insurance described in § 5 and name Owner as an additional insured.",
        ]),
      ),
    ).toBeNull();
  });

  // Load-bearing: an insurance mandate that points nowhere and states nothing
  // still reports.
  it("still reports a mandate with no minimum and no cross-reference", () => {
    expect(
      RISK_016.check(
        buildContext([
          "Property Management Agreement",
          "Owner shall maintain property and commercial general liability insurance covering the Property, naming Manager as an additional insured.",
        ]),
      ),
    ).not.toBeNull();
  });
});
