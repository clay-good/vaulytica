import { describe, expect, it } from "vitest";
import { rule as RISK_017 } from "./RISK-017.js";
import { buildContext } from "../../_test-fixtures.js";

describe("RISK-017 — one-way attorneys'-fees", () => {
  it("fires on 'Customer shall reimburse Vendor's reasonable attorneys' fees'", () => {
    const ctx = buildContext([
      "14.3 Fees",
      "Customer shall reimburse Vendor's reasonable attorneys' fees and costs incurred in enforcing this Agreement.",
    ]);
    const f = RISK_017.check(ctx);
    expect(f).not.toBeNull();
    expect(f?.severity).toBe("warning");
  });

  it("fires when fees run only to the Licensor", () => {
    const ctx = buildContext([
      "Fees",
      "In any action arising out of this Agreement, Licensor shall be entitled to recover its reasonable attorneys' fees and costs from Licensee.",
    ]);
    expect(RISK_017.check(ctx)).not.toBeNull();
  });

  it("silent on the canonical 'prevailing party' formulation", () => {
    const ctx = buildContext([
      "Fees",
      "The prevailing party in any action arising out of this Agreement shall be entitled to recover its reasonable attorneys' fees and costs.",
    ]);
    expect(RISK_017.check(ctx)).toBeNull();
  });

  it("silent on 'each party shall bear its own attorneys' fees'", () => {
    const ctx = buildContext([
      "Fees",
      "Each party shall bear its own attorneys' fees and costs incurred in connection with this Agreement.",
    ]);
    expect(RISK_017.check(ctx)).toBeNull();
  });

  it("silent when the document has no fee-shifting language at all", () => {
    const ctx = buildContext(["Body", "Provider shall provide the Services."]);
    expect(RISK_017.check(ctx)).toBeNull();
  });
});
