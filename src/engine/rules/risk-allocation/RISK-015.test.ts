import { describe, expect, it } from "vitest";
import { rule as RISK_015 } from "./RISK-015.js";
import { buildContext } from "../../_test-fixtures.js";

describe("RISK-015 — indemnification without aggregate cap", () => {
  it("fires when indemnity present and no cap anywhere", () => {
    const ctx = buildContext([
      "Indemnification",
      "Vendor shall indemnify Customer against any third-party claim arising from the Service.",
    ]);
    const f = RISK_015.check(ctx);
    expect(f?.severity).toBe("warning");
    expect(f?.title).toMatch(/without aggregate cap/i);
  });

  it("fires when cap exists but explicitly carves out indemnification", () => {
    const ctx = buildContext([
      "Indemnification",
      "Vendor shall indemnify Customer against any third-party claim arising from the Service.",
      "Liability shall be limited to twelve months of fees paid, except for indemnification obligations.",
    ]);
    const f = RISK_015.check(ctx);
    expect(f).not.toBeNull();
    expect(f?.title).toMatch(/carved out of liability cap/i);
  });

  it("is silent when indemnity is subject to a general cap (no carve-out)", () => {
    const ctx = buildContext([
      "Indemnification",
      "Vendor shall indemnify Customer against any third-party claim arising from the Service.",
      "Aggregate liability shall not exceed twelve months of fees paid under this Agreement.",
    ]);
    expect(RISK_015.check(ctx)).toBeNull();
  });

  it("is silent when no indemnification language is present", () => {
    const ctx = buildContext([
      "Limitation of Liability",
      "Aggregate liability shall not exceed the fees paid in the preceding twelve months.",
    ]);
    expect(RISK_015.check(ctx)).toBeNull();
  });

  it("fires on `hold harmless` framing without a cap", () => {
    const ctx = buildContext([
      "Indemnity",
      "Customer agrees to defend and indemnify and hold Vendor harmless from any claim arising from Customer's use of the Service.",
    ]);
    expect(RISK_015.check(ctx)).not.toBeNull();
  });
});
