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

describe("RISK-015 — the cap noun and its verb are not adjacent", () => {
  // "EACH PARTY'S TOTAL LIABILITY UNDER THESE API TERMS IS LIMITED TO …" is
  // the dominant cap sentence, and the first branch required "liability … is
  // limited" with nothing between. A contract with an explicit total-liability
  // cap in the same section as its indemnity was reported as uncapped.
  it("reads a cap that names the agreement between the noun and the verb", () => {
    const ctx = buildContext([
      "13. Indemnification and Limitation of Liability",
      "You shall indemnify, defend, and hold harmless Halcyon from any third-party claim arising out of your application. EACH PARTY'S TOTAL LIABILITY UNDER THESE API TERMS IS LIMITED TO THE FEES YOU PAID IN THE PRIOR TWELVE MONTHS.",
    ]);
    expect(RISK_015.check(ctx)).toBeNull();
  });

  it("reads 'aggregate liability arising out of this Agreement shall be capped at'", () => {
    const ctx = buildContext([
      "9. Risk",
      "Vendor shall indemnify Customer against any third-party claim. Vendor's aggregate liability arising out of or relating to this Agreement shall be capped at $500,000.",
    ]);
    expect(RISK_015.check(ctx)).toBeNull();
  });

  it("still fires on an indemnity with no cap anywhere", () => {
    const ctx = buildContext([
      "13. Indemnification",
      "Subtenant shall indemnify, defend, and hold harmless Sublandlord from and against all claims arising out of Subtenant's use of the Subleased Premises.",
    ]);
    expect(RISK_015.check(ctx)).not.toBeNull();
  });
});

describe("RISK-015 — the carve-out written as its own sentence", () => {
  // "These limits do not apply to a party's indemnity obligations under
  // Section 10." is the ordinary drafting of a limitation-of-liability
  // section. The carve-out pattern read only connector-led forms ("except
  // for …", "other than …") and only the verb stem `indemnif`, which does not
  // match the noun "indemnity" — so a cap that plainly excepts the indemnity
  // read as a cap that covers it.
  it("reads 'These limits do not apply to … indemnity obligations'", () => {
    const f = RISK_015.check(
      buildContext([
        "11. Limitation of Liability",
        "Supplier shall indemnify Distributor against product-liability claims. Each party's aggregate liability arising out of this Agreement is limited to the amounts paid in the twelve months before the claim. These limits do not apply to a party's indemnity obligations under Section 10.",
      ]),
    );
    expect(f?.title).toBe("Indemnification carved out of liability cap");
  });

  it("stays silent when the cap covers the indemnity", () => {
    expect(
      RISK_015.check(
        buildContext([
          "11. Limitation of Liability",
          "Supplier shall indemnify Distributor against product-liability claims. Each party's aggregate liability arising out of this Agreement, including its indemnity obligations, is limited to the amounts paid in the twelve months before the claim.",
        ]),
      ),
    ).toBeNull();
  });
});
