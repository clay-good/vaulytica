import { describe, expect, it } from "vitest";
import { rule as DARK_004 } from "./DARK-004.js";
import { buildContext } from "../../_test-fixtures.js";

describe("DARK-004 — mandatory arbitration + class waiver (consumer)", () => {
  it("fires on mandatory arbitration + a class-action waiver in a consumer contract", () => {
    const ctx = buildContext([
      "Terms of Service",
      "All disputes shall be resolved by binding arbitration.",
      "You agree to a class action waiver and will not participate in any class proceeding.",
    ]);
    expect(DARK_004.check(ctx)?.severity).toBe("warning");
  });

  // Regression: OPTIONAL/non-binding arbitration + a clause that has NO waiver
  // must not fire — the rule is about MANDATORY arbitration paired with a waiver.
  it("is silent on optional arbitration with no class-action waiver", () => {
    const ctx = buildContext([
      "Terms of Service",
      "Either party may, at its own option, elect non-binding arbitration for any dispute, but neither party is required to do so and either may proceed to court instead.",
      "This Agreement contains no class action waiver; you retain the right to participate in class actions against the Company.",
    ]);
    expect(DARK_004.check(ctx)).toBeNull();
  });

  it("is silent outside a consumer-facing context", () => {
    const ctx = buildContext([
      "Master Services Agreement",
      "All disputes shall be resolved by binding arbitration.",
      "The parties agree to a class action waiver.",
    ]);
    expect(DARK_004.check(ctx)).toBeNull();
  });
});
