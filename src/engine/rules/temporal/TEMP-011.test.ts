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

  it("reads the hyphenated 'auto-renew(s)' spelling (v1.2.0)", () => {
    expect(
      TEMP_011.check(
        buildContext([
          "Renewal",
          "Your subscription will auto-renew unless you provide 15 days written notice.",
        ]),
      )?.title,
    ).toContain("15");
    expect(
      TEMP_011.check(
        buildContext(["Renewal", "The plan auto-renews unless cancelled with 7 days notice."]),
      )?.title,
    ).toContain("7");
  });

  // A REMINDER the provider sends is not a window the customer must meet.
  // "We will send you an email reminder at least 7 days before an annual
  // renewal" is the pro-consumer half of an auto-renewal clause — what ROSCA
  // and the state statutes ASK for — and it was read as a seven-day
  // cancellation window.
  it("silent on the provider's own advance reminder (v1.4.0)", () => {
    const ctx = buildContext([
      "Renewal",
      "Your subscription will automatically renew at the end of each billing period unless you cancel before the renewal date. We will send you an email reminder at least 7 days before an annual renewal.",
    ]);
    expect(TEMP_011.check(ctx)).toBeNull();
  });

  // The section HEADING matches the auto-renewal trigger and carries no
  // window, so stopping at the first match read the heading and never reached
  // the clause beneath it.
  it("reaches the clause beneath a heading that matches the trigger (v1.4.0)", () => {
    const ctx = buildContext([
      "",
      "3. Automatic Renewal.",
      "The Term renews automatically for successive one-year periods unless either party gives 10 days written notice of non-renewal.",
    ]);
    expect(TEMP_011.check(ctx)).not.toBeNull();
  });
});
