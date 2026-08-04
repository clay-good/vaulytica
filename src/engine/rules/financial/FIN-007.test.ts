import { describe, expect, it } from "vitest";
import { rule as FIN_007 } from "./FIN-007.js";
import { buildContext } from "../../_test-fixtures.js";

const fires = (body: string) => FIN_007.check(buildContext(["Pricing", body])) !== null;

describe("FIN-007 — most-favored-nation clause present", () => {
  it("fires on the existing MFN forms", () => {
    expect(fires("The Agreement includes an MFN clause on pricing.")).toBe(true);
    expect(fires("Customer receives most-favored-nation pricing.")).toBe(true);
  });

  // v1.1.0 — British "favoured" and the "most favorable terms / pricing" form.
  it("fires on the British spelling and 'most favorable terms/pricing'", () => {
    expect(fires("Buyer is entitled to most favoured nation treatment.")).toBe(true);
    expect(
      fires("Vendor guarantees Customer the most favorable pricing offered to any customer."),
    ).toBe(true);
    expect(fires("Customer shall receive the most favorable terms available.")).toBe(true);
  });

  it("does not fire on a bare 'favorable outcome'", () => {
    expect(fires("We look forward to a favorable outcome for both parties.")).toBe(false);
  });
});
