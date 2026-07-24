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
});
