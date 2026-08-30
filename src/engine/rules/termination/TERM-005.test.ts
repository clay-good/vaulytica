/**
 * TERM-005 reported "The contract does not state what happens upon
 * termination" about clauses that state it. The detector required the bare
 * phrase "upon termination" and a consequence AFTER it, which missed the two
 * forms the corpus writes: the compound trigger ("Upon expiration **or**
 * termination of this BAA, Business Associate shall … return … or destroy all
 * PHI") and the consequence stated before it ("Processing shall cease upon
 * termination of the MSA"). Regenerating the corpus removed 23 of these and
 * added nothing.
 */
import { describe, expect, it } from "vitest";
import { rule as TERM_005 } from "./TERM-005.js";
import { buildContext } from "../../_test-fixtures.js";

const doc = (...paras: string[]) => buildContext(["Term and Termination", ...paras]);

describe("TERM-005 — effect of termination", () => {
  it("reads a compound trigger", () => {
    expect(
      TERM_005.check(
        doc(
          "Upon expiration or termination of this BAA, Business Associate shall within thirty (30) days return to Covered Entity or destroy all PHI received from Covered Entity.",
        ),
      ),
    ).toBeNull();
  });

  it("reads a consequence stated before its trigger", () => {
    expect(TERM_005.check(doc("Processing shall cease upon termination of the MSA."))).toBeNull();
  });

  it("reads a modern data clause that returns data by export", () => {
    expect(
      TERM_005.check(
        doc(
          "Upon expiration or termination of the subscription for any reason, Customer shall have thirty (30) days to export all Customer Data from the Service in a machine-readable format.",
        ),
      ),
    ).toBeNull();
  });

  it("still fires when the contract says nothing about what follows termination", () => {
    expect(
      TERM_005.check(
        doc(
          "Either party may terminate this Agreement for convenience upon thirty (30) days written notice to the other party.",
        ),
      ),
    ).not.toBeNull();
  });

  it("does not borrow a consequence from a different sentence", () => {
    expect(
      TERM_005.check(
        doc(
          "Either party may terminate this Agreement upon notice. Vendor shall return any equipment loaned during onboarding within the first month of the Term.",
        ),
      ),
    ).not.toBeNull();
  });
});

describe("the 'upon such termination' construction/services consequence (v1.6.0)", () => {
  it("reads a completion-and-liability consequence introduced by 'Upon such termination'", () => {
    // The demonstrative "such" (pointing back at the termination-for-cause just
    // described) blocked the trigger, and "complete"/"be liable for" are not
    // CONSEQUENCE verbs, so a clear effect clause was reported as absent.
    expect(
      TERM_005.check(
        doc(
          "The Owner may terminate this Agreement for cause if the Contractor materially breaches and fails to cure within fourteen (14) days after written notice.",
          "Upon such termination, the Owner may complete the Work by whatever method it deems expedient, and the Contractor shall be liable for any costs exceeding the unpaid balance of the Contract Price.",
        ),
      ),
    ).toBeNull();
  });

  it("still fires on a bare 'upon such termination' cross-reference with no stated consequence", () => {
    expect(
      TERM_005.check(
        doc(
          "The Owner may terminate this Agreement for cause. The definitions in Section 1 apply upon such termination of this Agreement.",
        ),
      ),
    ).not.toBeNull();
  });
});

describe("the pay-through-termination-date wind-down (v1.1.0)", () => {
  it("reads pay-for-work-performed as an effect of termination", () => {
    const ctx = buildContext([
      "Term and Termination",
      "Customer may terminate this SOW for convenience on thirty (30) days written notice, in which case Customer shall pay for all Services performed and Deliverables completed or in progress through the termination date.",
    ]);
    expect(TERM_005.check(ctx)).toBeNull();
  });

  it("a failure-to-pay termination trigger is not an effect clause", () => {
    const ctx = buildContext([
      "Termination",
      "Either party may terminate this Agreement if the other party fails to pay any amount when due and does not cure within ten (10) days.",
    ]);
    expect(TERM_005.check(ctx)).not.toBeNull();
  });
});

describe("the conditional-termination consequence (v1.2.0)", () => {
  it("reads 'If Buyer terminates …, the deposit shall be returned' as an effect clause", () => {
    const ctx = buildContext([
      "Termination",
      "Either party may terminate this Agreement by written notice if the Closing has not occurred by November 30, 2026. If Buyer terminates for Seller's material breach, the earnest deposit shall be returned to Buyer.",
    ]);
    expect(TERM_005.check(ctx)).toBeNull();
  });
});

describe("the lease surrender consequence (v1.3.0)", () => {
  it("reads 'Upon expiration or termination, Tenant shall surrender the Premises'", () => {
    const ctx = buildContext([
      "Surrender",
      "Upon expiration or termination of this Lease, Tenant shall surrender the Premises in the condition required by this Lease, ordinary wear and tear excepted.",
    ]);
    expect(TERM_005.check(ctx)).toBeNull();
  });

  it("reads 'Tenant shall surrender possession upon termination'", () => {
    const ctx = buildContext([
      "Surrender",
      "Tenant shall surrender possession of the Premises to Landlord upon the termination of this Lease.",
    ]);
    expect(TERM_005.check(ctx)).toBeNull();
  });
});

describe("the survival clause is an effect of termination (v1.4.0)", () => {
  it("reads 'Sections 3-7 shall survive termination of this Agreement'", () => {
    const ctx = buildContext([
      "Survival",
      "Sections 3, 4, and 7 shall survive termination of this Agreement.",
    ]);
    expect(TERM_005.check(ctx)).toBeNull();
  });

  it("reads 'the confidentiality obligations survive the expiration or termination'", () => {
    const ctx = buildContext([
      "Term",
      "The confidentiality obligations survive the expiration or termination of this Agreement for three (3) years.",
    ]);
    expect(TERM_005.check(ctx)).toBeNull();
  });

  it("does not read a non-termination 'survive' as an effect clause", () => {
    const ctx = buildContext([
      "Term",
      "Either party may terminate this Agreement for convenience. The brand is expected to survive the market downturn for years to come.",
    ]);
    expect(TERM_005.check(ctx)).not.toBeNull();
  });

  it("reads the trigger-first order 'Upon termination, … Sections 4, 8 and 10 survive' (v1.4.1)", () => {
    const ctx = buildContext([
      "Termination",
      "Upon termination, your right to use the Service ends and Sections 4, 8, and 10 survive.",
    ]);
    expect(TERM_005.check(ctx)).toBeNull();
  });
});

describe("the purchase-agreement 'terminate this Agreement … refund' form (v1.4.2)", () => {
  it("reads 'may terminate this Agreement, in which case the Earnest Money is refunded'", () => {
    const ctx = buildContext([
      "Due Diligence",
      "The Buyer may terminate this Agreement before the end of the Due Diligence Period, in which case the Earnest Money is refunded.",
    ]);
    expect(TERM_005.check(ctx)).toBeNull();
  });

  it("reads 'may terminate this Agreement and receive a refund'", () => {
    const ctx = buildContext([
      "Casualty",
      "If the Property is materially damaged before Closing, the Buyer may terminate this Agreement and receive a refund of the Earnest Money.",
    ]);
    expect(TERM_005.check(ctx)).toBeNull();
  });

  it("does not read 'terminate any employee who fails to return property' as a wind-down", () => {
    const ctx = buildContext([
      "Conduct",
      "The Company may terminate any employee who fails to return company property after a warning.",
    ]);
    expect(TERM_005.check(ctx)).not.toBeNull();
  });

  it("reads an accrued-obligations / savings statement as effect-of-termination (v1.5.0)", () => {
    expect(
      TERM_005.check(
        buildContext([
          "Effect",
          "Termination shall not relieve either party of obligations accrued prior to the effective date of termination.",
        ]),
      ),
    ).toBeNull();
    expect(
      TERM_005.check(
        buildContext([
          "Effect",
          "Any termination of this Agreement shall be without prejudice to any other rights or remedies.",
        ]),
      ),
    ).toBeNull();
  });

  it("reads an 'upon the effective date of termination … destroy' wind-down (v1.5.0)", () => {
    expect(
      TERM_005.check(
        buildContext([
          "Effect",
          "Upon the effective date of termination, Licensee shall destroy all copies of the Software.",
        ]),
      ),
    ).toBeNull();
  });
});

describe("TERM-005 — the plainest consequence of all (v1.12.0)", () => {
  /**
   * "On termination, the Tolling Period ENDS and any applicable limitations
   * period RESUMES running." That is a textbook effect-of-termination clause,
   * and the recognized-consequence list held return / destroy / surrender /
   * survive but not "ends".
   */
  it("reads a consequence stated as ending or resuming", () => {
    for (const clause of [
      "On termination, the Tolling Period ends and any applicable limitations period resumes running, with the Tolling Period excluded from its computation.",
      "Upon termination of this Agreement, the license granted in Section 2 lapses and Licensee's rights expire.",
      "Upon expiration or termination, all obligations of the parties become void except those in Section 9.",
    ]) {
      expect(TERM_005.check(buildContext(["Term", clause])), clause).toBeNull();
    }
  });

  it("does not read a term definition as an effect-of-termination clause", () => {
    // The new branch is admitted only AFTER the trigger. "This Agreement ends
    // upon expiration of the Initial Term" defines a term; it does not state
    // what termination does.
    expect(
      TERM_005.check(
        buildContext([
          "Term",
          "This Agreement ends upon expiration of the Initial Term unless renewed.",
        ]),
      ),
    ).not.toBeNull();
  });
});

describe("TERM-005 — the active voice of release", () => {
  // "On termination, Factor shall release its security interest and file a
  // termination statement within ten days" is the wind-down clause of every
  // secured facility, and the consequence list held only the passive "is
  // released".
  it("reads 'shall release its security interest' as a consequence", () => {
    const ctx = buildContext([
      "8. Term and Termination",
      "On termination, Client shall pay all obligations then outstanding, and Factor shall release its security interest and file a termination statement within ten (10) days after Client's obligations are paid in full.",
    ]);
    expect(TERM_005.check(ctx)).toBeNull();
  });

  it("does not read a settlement's mutual release as a termination effect", () => {
    const ctx = buildContext([
      "5. Release",
      "The parties exchange mutual releases of all claims arising before the date of this Agreement.",
    ]);
    expect(TERM_005.check(ctx)).not.toBeNull();
  });
});

describe("TERM-005 — the consequence is that TITLE VESTS", () => {
  // A ground lease's effect-of-termination clause is the reversion: "On
  // expiration or earlier termination of this Lease, title to the
  // Improvements VESTS IN Landlord automatically … and Tenant shall DELIVER
  // the Improvements in good condition." Neither verb was in the consequence
  // list, so the clause that is the whole economic point of the lease read as
  // no effect-of-termination clause at all.
  it.each([
    "On expiration or earlier termination of this Lease, title to the Improvements vests in Landlord automatically, without payment.",
    "Upon termination, Tenant shall deliver the Improvements to Landlord in good condition and repair.",
    "On termination of this Lease, all rights granted revert to Licensor.",
  ])("is silent on %s", (clause) => {
    expect(TERM_005.check(buildContext(["Termination", clause]))).toBeNull();
  });

  it("does not read a delivery obligation with no termination trigger as one", () => {
    expect(
      TERM_005.check(
        buildContext([
          "Possession",
          "Landlord shall deliver possession of the Land free of occupants on the Commencement Date.",
        ]),
      ),
    ).not.toBeNull();
  });
});

describe("TERM-005 — transfer as a wind-down consequence", () => {
  // "On expiration or termination, Supplier shall, at Customer's request and
  // expense, continue to supply the Products for up to twelve (12) months,
  // TRANSFER the manufacturing process and all Customer-owned tooling and
  // materials, and cooperate in the qualification of an alternative supplier."
  it("reads a transition obligation stated as a transfer", () => {
    expect(
      TERM_005.check(
        buildContext([
          "Termination",
          "On expiration or termination, Supplier shall, at Customer's request and expense, continue to supply the Products for up to twelve (12) months, transfer the manufacturing process and all Customer-owned tooling and materials, and cooperate in the qualification of an alternative supplier.",
        ]),
      ),
    ).toBeNull();
  });
});

describe("TERM-005 — the preposition is AFTER as often as ON", () => {
  it("reads a data-return clause stated as 'within N days after termination'", () => {
    expect(
      TERM_005.check(
        buildContext([
          "Return and Destruction",
          "Within thirty (30) days after expiration or termination, Recipient shall destroy all copies of the Shared Data and shall certify the destruction in writing.",
        ]),
      ),
    ).toBeNull();
  });
});

/**
 * Two ways a plainly-stated effect went unread.
 */
describe("TERM-005 v1.17.0 — the inflected verb and the subsection number", () => {
  it("reads a consequence in the third person", () => {
    expect(
      TERM_005.check(doc("On the end of the internship, the Intern returns Company property.")),
    ).toBeNull();
  });

  it("reads across a subsection number in the survival list", () => {
    expect(
      TERM_005.check(
        doc(
          "On the end of the internship for any reason, Sections 4, 5, 7.3, and 8 continue in effect, the Intern returns Company property, and the Company completes any academic evaluation.",
        ),
      ),
    ).toBeNull();
  });

  /**
   * The widened window admits a period only when a DIGIT follows it, so a real
   * sentence end still bounds it: a trigger in one sentence cannot reach a
   * consequence in the next.
   */
  it("does not borrow a consequence from the next sentence", () => {
    expect(
      TERM_005.check(
        doc(
          "Upon termination the parties shall confer in good faith. The schedule is then agreed between them.",
        ),
      ),
    ).not.toBeNull();
  });
});
