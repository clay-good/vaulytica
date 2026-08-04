import { describe, expect, it } from "vitest";
import { rule as TERM_007 } from "./TERM-007.js";
import { buildContext } from "../../_test-fixtures.js";

const fires = (body: string) => TERM_007.check(buildContext(["Termination", body])) !== null;

describe("TERM-007 — post-termination obligations", () => {
  it("fires on the canonical 'upon termination ... return Confidential Information'", () => {
    expect(
      fires("Upon termination, the Receiving Party shall return all Confidential Information."),
    ).toBe(true);
  });

  // v1.1.0 — the obligation leads with more than "upon termination", and every
  // match requires a data object.
  it("fires on on / following / after / on-expiration-or-termination data-return obligations", () => {
    for (const body of [
      "On termination, each party shall destroy all copies of the other party's data.",
      "Following termination of this Agreement, Vendor shall delete all Customer Data.",
      "On expiration or termination, Recipient shall return or destroy all Confidential Information.",
      "Upon termination of the MSA, Processor shall return or destroy the personal data.",
    ]) {
      expect(fires(body), body).toBe(true);
    }
  });

  it("does not fire on a heading with no data-return obligation, or an unrelated 'return to work'", () => {
    expect(fires("Section 8: Return of Data on Termination is addressed in the annex.")).toBe(
      false,
    );
    expect(
      fires("After termination of employment, the employee may return to work as a consultant."),
    ).toBe(false);
    expect(fires("Upon termination, the parties shall issue a joint press release.")).toBe(false);
  });

  it("is silent when the return obligation is disclaimed", () => {
    expect(
      fires("Upon termination, Vendor has no obligation to return or destroy any Customer Data."),
    ).toBe(false);
  });
});
