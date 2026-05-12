import { describe, expect, it } from "vitest";
import { rule as TERM_009 } from "./TERM-009.js";
import { buildContext } from "../../_test-fixtures.js";

describe("TERM-009 — asymmetric termination-for-convenience", () => {
  it("fires when Vendor can terminate at any time and Customer needs material breach", () => {
    const ctx = buildContext([
      "Termination",
      "Vendor may terminate this Agreement at any time upon written notice.",
      "Customer may only terminate this Agreement for material breach following a 30-day cure period.",
    ]);
    const f = TERM_009.check(ctx);
    expect(f?.severity).toBe("warning");
    expect(f?.title).toMatch(/asymmetric/i);
  });

  it("fires when Employer can terminate for convenience and Employee needs cure period", () => {
    const ctx = buildContext([
      "Termination",
      "Employer may terminate for any reason in its sole discretion.",
      "Employee shall terminate this Agreement only after providing 60 days written notice of any material breach.",
    ]);
    expect(TERM_009.check(ctx)).not.toBeNull();
  });

  it("is silent when both parties have the same termination right", () => {
    const ctx = buildContext([
      "Termination",
      "Either party may terminate this Agreement at any time upon 30 days notice.",
    ]);
    expect(TERM_009.check(ctx)).toBeNull();
  });

  it("is silent when only one termination clause exists (no asymmetry)", () => {
    const ctx = buildContext([
      "Termination",
      "Vendor may terminate this Agreement at any time upon 30 days notice.",
    ]);
    expect(TERM_009.check(ctx)).toBeNull();
  });
});
