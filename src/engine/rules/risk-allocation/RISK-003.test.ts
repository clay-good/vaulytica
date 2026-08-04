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
