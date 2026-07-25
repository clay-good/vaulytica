import { describe, expect, it } from "vitest";
import { rule as RISK_015 } from "./RISK-015.js";
import { buildContext } from "../../_test-fixtures.js";

const INDEMNITY =
  "The Vendor shall indemnify and hold the Customer harmless from all third-party claims.";

// Each doc has an indemnity clause AND a liability cap. RISK-015 must stay
// silent — firing "no aggregate cap" on a capped contract is a false positive.
const CAP_CLAUSES: string[] = [
  "The Vendor's total liability under this Agreement shall not exceed $1,000,000.",
  "In no event shall either party's liability exceed the fees paid in the prior twelve months.",
  "Liability is capped at $500,000.",
  "The aggregate liability of the Vendor shall not exceed the Contract Price.",
  "The Vendor's maximum liability shall not exceed $2,000,000.",
  "Total liability shall be limited to the amounts paid in the prior 12 months.",
  "Under no circumstances shall the Vendor's liability exceed $1,000,000.",
  "The indemnification obligations shall not exceed the Escrow Amount.",
  "Each party's liability is subject to an aggregate cap of $5,000,000.",
  "The Vendor's liability shall in no event exceed the fees paid hereunder.",
];

describe("RISK-015 cap-present FP guard", () => {
  for (const cap of CAP_CLAUSES) {
    it(`stays silent with cap: ${cap.slice(0, 48)}`, () => {
      const ctx = buildContext(["Indemnification", INDEMNITY], ["Limitation of Liability", cap]);
      const f = RISK_015.check(ctx);
      expect(f, `FALSE NO-CAP: ${cap}`).toBeNull();
    });
  }

  it("still fires when 'in no event ... exceed' caps something other than liability", () => {
    const ctx = buildContext(
      ["Indemnification", INDEMNITY],
      ["Term", "In no event shall the term of this Agreement exceed five years."],
    );
    expect(RISK_015.check(ctx)).not.toBeNull();
  });
});
