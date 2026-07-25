import { describe, expect, it } from "vitest";
import { rule as RISK_015 } from "./RISK-015.js";
import { buildContext } from "../../_test-fixtures.js";

// Guard: a statutory ENTITY indemnification of a governance role "to the fullest
// extent permitted by the Act" is uncapped by design (DGCL § 145 and its LLC /
// partnership analogues), so RISK-015 must not demand an aggregate cap on it.
// A COMMERCIAL indemnity of a counterparty "to the fullest extent permitted by
// law" carries no governance role and still requires its cap.
describe("RISK-015 statutory governance indemnity", () => {
  for (const clause of [
    "The Company shall indemnify the Manager and each Member to the fullest extent permitted by the Act against any losses.",
    "The Partnership shall indemnify each Partner to the fullest extent permitted by the Delaware Revised Uniform Partnership Act.",
    "The Company shall indemnify its Directors and Officers to the fullest extent permitted by law.",
  ]) {
    it(`exempts: ${clause.slice(0, 46)}`, () => {
      expect(RISK_015.check(buildContext(["Indemnification", clause]))).toBeNull();
    });
  }

  it("still warns on a commercial indemnity to the fullest extent permitted by law", () => {
    expect(
      RISK_015.check(
        buildContext([
          "Indemnification",
          "The Vendor shall indemnify the Customer to the fullest extent permitted by law against all third-party claims.",
        ]),
      ),
    ).not.toBeNull();
  });
});
