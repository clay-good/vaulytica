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
