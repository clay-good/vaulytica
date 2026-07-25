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

  it("recognizes an entity dissolution wind-down clause", () => {
    expect(
      TERM_005.check(
        buildContext([
          "Dissolution",
          "Upon dissolution, the Partnership's assets shall be applied first to creditors, then to the Partners in accordance with their capital accounts.",
        ]),
      ),
    ).toBeNull();
  });

  it("still warns on a bare dissolution trigger with no wind-down", () => {
    expect(
      TERM_005.check(
        buildContext([
          "Dissolution",
          "The Company shall dissolve upon the written consent of the Members.",
        ]),
      ),
    ).not.toBeNull();
  });

  it("recognizes a construction terminate-for-default remedy", () => {
    expect(
      TERM_005.check(
        buildContext([
          "Default",
          "If the Contractor fails to cure, the Owner may terminate this Agreement for default and complete the Work by other means, and the Contractor shall be liable for the resulting costs.",
        ]),
      ),
    ).toBeNull();
  });

  it("does not read a firing-for-cause clause as a termination effect", () => {
    expect(
      TERM_005.check(
        buildContext([
          "HR",
          "The Company may terminate any employee for cause who fails to complete required training.",
        ]),
      ),
    ).not.toBeNull();
  });

  it("still warns when the contract states no termination effect", () => {
    expect(
      TERM_005.check(
        buildContext([
          "Term",
          "Either party may terminate this Agreement for convenience on 30 days notice.",
        ]),
      ),
    ).not.toBeNull();
  });

  it("a plain payment term does not read as a termination effect", () => {
    expect(
      TERM_005.check(buildContext(["Fees", "Invoices are due and payable Net 30."])),
    ).not.toBeNull();
  });
});
