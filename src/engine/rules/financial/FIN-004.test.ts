import { describe, expect, it } from "vitest";
import { rule as FIN_004 } from "./FIN-004.js";
import { buildContext } from "../../_test-fixtures.js";

describe("FIN-004 — late-payment interest-rate sanity (period-honest)", () => {
  it("fires on a stated periodic late-payment rate at or above 12%", () => {
    const ctx = buildContext([
      "Late Payment",
      "Overdue amounts shall bear interest at 15% per annum until paid.",
    ]);
    const f = FIN_004.check(ctx);
    expect(f?.severity).toBe("warning");
    expect(f?.title).toMatch(/15/);
  });

  // Regression: a one-time flat fee is NOT an interest rate; flagging it as
  // usury was a confident false accusation (the same class FIN-009 fixed).
  it("does NOT fire on a one-time flat late fee (no stated period)", () => {
    const ctx = buildContext([
      "Late Payment",
      "A one-time late payment fee of 15% of the overdue invoice amount shall apply to any invoice not paid when due.",
    ]);
    expect(FIN_004.check(ctx)).toBeNull();
  });

  it("does NOT fire on a bare percentage near 'past due' with no period", () => {
    const ctx = buildContext([
      "Discounts",
      "A past due account forfeits its 15% early-payment discount.",
    ]);
    expect(FIN_004.check(ctx)).toBeNull();
  });

  it("is silent below 12% even with a stated period", () => {
    const ctx = buildContext([
      "Late Payment",
      "Overdue amounts shall bear interest at 10% per annum.",
    ]);
    expect(FIN_004.check(ctx)).toBeNull();
  });

  // v1.1.0 — the same usurious rate is written under several standard triggers
  // the payment/past-due/overdue list missed: "late charge", "default
  // interest / default rate", "delinquent".
  it("fires on the 'late charge', 'default interest', and 'delinquent' phrasings", () => {
    for (const body of [
      "A late charge of 18% per annum shall accrue on any unpaid balance.",
      "The default interest rate is 24% per annum on all outstanding sums.",
      "Delinquent amounts bear interest at 18% per year until paid.",
    ]) {
      const f = FIN_004.check(buildContext(["Late Payment", body]));
      expect(f, body).not.toBeNull();
      expect(f?.severity).toBe("warning");
    }
  });

  it("still does not fire on a flat 'late charge' with no stated period", () => {
    expect(
      FIN_004.check(
        buildContext(["Late Payment", "A late charge of 15% of the overdue amount applies."]),
      ),
    ).toBeNull();
  });
});

describe("FIN-004 — reads a three-digit rate whole (v1.3.0)", () => {
  it("reports 125%, not its last two digits", () => {
    const f = FIN_004.check(
      buildContext(["Terms", "Late payments bear interest at 125% per annum."]),
    );
    expect(f?.title).toBe("Late-payment interest rate 125% may exceed usury limits");
  });
});

describe("FIN-004 — the spellings a lender actually uses (v1.4.0)", () => {
  it.each([
    "Past-due amounts shall bear interest at 30 percent per annum.",
    "Past-due amounts shall bear interest at thirty percent (30%) per annum.",
    "Overdue amounts bear interest at 30% a year.",
  ])("fires on %s", (t) => {
    expect(FIN_004.check(buildContext(["Terms", t]))?.title).toBe(
      "Late-payment interest rate 30% may exceed usury limits",
    );
  });
});

describe("FIN-004 — a usury savings clause caps itself", () => {
  it.each([
    "Late payments bear interest at the lesser of eighteen percent (18%) per year or the maximum rate permitted by law.",
    "Overdue amounts accrue interest at 18% per annum or the maximum rate permitted by applicable law, whichever is less.",
  ])("is silent on %s", (t) => {
    expect(FIN_004.check(buildContext(["Terms", t]))).toBeNull();
  });

  it("still fires on the same rate without the cap", () => {
    const t = "Late payments bear interest at eighteen percent (18%) per year.";
    expect(FIN_004.check(buildContext(["Terms", t]))).not.toBeNull();
  });
});
