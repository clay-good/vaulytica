import { describe, expect, it } from "vitest";
import { rule as TEMP_011 } from "./TEMP-011.js";
import { buildContext } from "../../_test-fixtures.js";

describe("TEMP-011 — auto-renewal notice window < 30 days", () => {
  it("fires on a 15-day window", () => {
    const ctx = buildContext([
      "Renewal",
      "This Agreement shall automatically renew unless either party provides 15 days prior written notice.",
    ]);
    const f = TEMP_011.check(ctx);
    expect(f?.severity).toBe("warning");
    expect(f?.title).toMatch(/under 30 days/i);
  });

  it("fires on a 7-day window via `N-day` form", () => {
    const ctx = buildContext([
      "Renewal",
      "Renews automatically for successive one-year terms; non-renewal requires 7-day written notice.",
    ]);
    expect(TEMP_011.check(ctx)).not.toBeNull();
  });

  it("is silent on a 30-day window (boundary)", () => {
    const ctx = buildContext([
      "Renewal",
      "This Agreement automatically renews unless either party provides 30 days prior written notice.",
    ]);
    expect(TEMP_011.check(ctx)).toBeNull();
  });

  it("is silent on a 60-day window", () => {
    const ctx = buildContext([
      "Renewal",
      "Renews automatically; non-renewal notice must be given at least 60 days before the renewal date.",
    ]);
    expect(TEMP_011.check(ctx)).toBeNull();
  });

  it("is silent when no auto-renewal language is present", () => {
    const ctx = buildContext([
      "Term",
      "Termination requires 14 days notice before the end of the initial term.",
    ]);
    expect(TEMP_011.check(ctx)).toBeNull();
  });
});
