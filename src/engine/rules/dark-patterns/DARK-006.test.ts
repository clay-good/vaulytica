import { describe, expect, it } from "vitest";
import { rule as DARK_006 } from "./DARK-006.js";
import { buildContext } from "../../_test-fixtures.js";

describe("DARK-006 — asymmetric pre-suit notice / cure window", () => {
  it("fires when only the Customer is required to give pre-suit notice", () => {
    const ctx = buildContext([
      "Dispute Resolution",
      "Customer shall provide Vendor at least 30 days written notice of any claim before initiating suit.",
    ]);
    const f = DARK_006.check(ctx);
    expect(f?.severity).toBe("warning");
    expect(f?.title).toMatch(/asymmetric pre-suit/i);
  });

  it("fires when only the Employee is required to give cure-period notice before arbitration", () => {
    const ctx = buildContext([
      "Disputes",
      "Employee must give Employer written notice at least 60 days prior to initiating any arbitration.",
    ]);
    expect(DARK_006.check(ctx)).not.toBeNull();
  });

  it("is silent when both parties have the same notice gate", () => {
    const ctx = buildContext([
      "Disputes",
      "Each party shall provide the other 30 days written notice before initiating any claim or suit.",
    ]);
    expect(DARK_006.check(ctx)).toBeNull();
  });

  it("is silent when the clause has no pre-suit-notice language", () => {
    const ctx = buildContext([
      "Disputes",
      "Any dispute shall be finally settled by binding arbitration under the AAA Commercial Rules.",
    ]);
    expect(DARK_006.check(ctx)).toBeNull();
  });
});
