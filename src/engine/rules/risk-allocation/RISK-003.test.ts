import { describe, expect, it } from "vitest";
import { rule as RISK_003 } from "./RISK-003.js";
import { buildContext } from "../../_test-fixtures.js";

const doc = (...paras: string[]) => buildContext(["Indemnification", ...paras]);

describe("RISK-003 — indemnity cap present", () => {
  it("surfaces a cap on the 'indemnif-' verb forms", () => {
    expect(
      RISK_003.check(doc("Such indemnification shall not exceed the fees paid in the prior year.")),
    ).not.toBeNull();
  });

  it("surfaces a cap on the 'indemnit-' noun / agent forms (v1.2.0)", () => {
    // The noun "indemnity" (the usual section title), "Indemnitor".
    expect(
      RISK_003.check(
        doc("The Indemnity obligations of each party shall in no event exceed the Escrow Amount."),
      ),
    ).not.toBeNull();
    expect(
      RISK_003.check(
        doc("The Indemnitor's liability is limited to the amounts paid under this Agreement."),
      ),
    ).not.toBeNull();
  });

  it("does not fire on an uncapped indemnity", () => {
    expect(
      RISK_003.check(doc("The Vendor shall indemnify Customer against all third-party claims.")),
    ).toBeNull();
  });
});

/**
 * "NOT limited to" is the OPPOSITE of a cap (v1.3.0).
 *
 * A construction indemnity closes its insurance section "the insurance is in
 * addition to and not in satisfaction of the indemnity, and THE INDEMNITY IS
 * NOT LIMITED TO the amount of insurance" — and the `limited to` branch
 * carried no negation guard, so the same run reported both "Indemnity cap
 * stated" and "Indemnification without aggregate cap" about a document whose
 * next section is headed NO CAP.
 */
describe("RISK-003 — a cap phrase that inverts under negation", () => {
  it.each([
    [
      "not limited to",
      "The insurance is in addition to the indemnity, and the indemnity is not limited to the amount of insurance.",
    ],
    ["never capped at", "The Indemnitor's obligation is never capped at the policy limits."],
  ])("is silent on %s", (_label, clause) => {
    expect(RISK_003.check(buildContext(["Indemnity Agreement", clause]))).toBeNull();
  });

  // Load-bearing: "shall NOT EXCEED" is a cap and must keep matching, and so
  // must the unnegated forms.
  it.each([
    [
      "not exceed",
      "The Indemnitor's indemnification obligations shall not exceed $2,000,000 in the aggregate.",
    ],
    [
      "limited to",
      "The indemnity is limited to the amount of the insurance proceeds actually received.",
    ],
    ["capped at", "The indemnity is capped at the Contract Sum."],
  ])("still reports %s", (_label, clause) => {
    expect(RISK_003.check(buildContext(["Indemnity Agreement", clause]))).not.toBeNull();
  });
});
