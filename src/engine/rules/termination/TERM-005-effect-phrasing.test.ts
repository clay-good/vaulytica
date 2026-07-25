import { describe, expect, it } from "vitest";
import { rule as TERM_005 } from "./TERM-005.js";
import { buildContext } from "../../_test-fixtures.js";

// Guard: an effect-of-termination clause must be recognized however phrased, so
// TERM-005 does not warn "no effect-of-termination clause" on a doc that has one.
describe("TERM-005 effect-of-termination phrasing", () => {
  for (const clause of [
    "Upon termination, Customer's access to the Service will be disabled.",
    "Following termination, the parties shall have no further obligations.",
    "Upon termination, any prepaid fees shall be forfeited.",
    "Upon termination, outstanding amounts become immediately due and payable.",
    "Upon expiration or termination, Tenant shall surrender the Premises.",
  ]) {
    it(`recognizes: ${clause.slice(0, 46)}`, () => {
      expect(TERM_005.check(buildContext(["Termination", clause]))).toBeNull();
    });
  }

  it("still warns when the contract states no termination effect", () => {
    expect(
      TERM_005.check(
        buildContext(["Term", "Either party may terminate this Agreement for convenience on 30 days notice."]),
      ),
    ).not.toBeNull();
  });

  it("a plain payment term does not read as a termination effect", () => {
    expect(
      TERM_005.check(buildContext(["Fees", "Invoices are due and payable Net 30."])),
    ).not.toBeNull();
  });
});
