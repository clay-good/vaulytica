import { describe, expect, it } from "vitest";
import { rule as FIN_009 } from "./FIN-009.js";
import { buildContext } from "../../_test-fixtures.js";

describe("FIN-009 — late fee above 18%/year", () => {
  it("fires on 2% per month (24%/year)", () => {
    const ctx = buildContext([
      "Payment Terms",
      "Interest shall accrue at the rate of 2% per month on all past-due amounts.",
    ]);
    const f = FIN_009.check(ctx);
    expect(f?.severity).toBe("warning");
    expect(f?.title).toMatch(/24/);
  });

  it("fires on 5% monthly late fee", () => {
    const ctx = buildContext([
      "Late Payment",
      "A late fee of 5% per month shall apply to amounts not paid when due.",
    ]);
    expect(FIN_009.check(ctx)).not.toBeNull();
  });

  it("fires on 24% per annum", () => {
    const ctx = buildContext([
      "Default Interest",
      "Past-due amounts shall bear interest at 24% per annum.",
    ]);
    expect(FIN_009.check(ctx)).not.toBeNull();
  });

  it("is silent at 1% per month (12%/year — below threshold)", () => {
    const ctx = buildContext([
      "Payment Terms",
      "Interest at the rate of 1% per month shall apply to past-due amounts.",
    ]);
    expect(FIN_009.check(ctx)).toBeNull();
  });

  it("is silent at 1.5% per month (18%/year — boundary)", () => {
    const ctx = buildContext(["Payment Terms", "A late fee of 1.5% per month applies."]);
    expect(FIN_009.check(ctx)).toBeNull();
  });

  it("is silent when no rate is specified", () => {
    const ctx = buildContext(["Fees", "Customer shall pay all invoices within thirty (30) days."]);
    expect(FIN_009.check(ctx)).toBeNull();
  });

  // Unit honesty (fix-legal-authority-currency): a missing period is never
  // assumed against the drafter — the old behavior annualized a benign
  // one-time 5% flat fee as ~60%/year usury.

  it("one-time flat fee: info drafting note, no usury assertion", () => {
    const ctx = buildContext([
      "Late Payment",
      "A late fee of 5% of the overdue amount shall apply to any invoice not paid when due.",
    ]);
    const f = FIN_009.check(ctx);
    expect(f?.severity).toBe("info");
    expect(f?.title).toMatch(/one-time/i);
    expect(f?.title).not.toMatch(/above 18%/i);
    expect(`${f?.description} ${f?.explanation}`).not.toMatch(/60(\.0)?%/);
  });

  it("unstated period: info clarification, never annualized", () => {
    const ctx = buildContext([
      "Late Payment",
      "A late charge: 5% will be assessed on late payments.",
    ]);
    const f = FIN_009.check(ctx);
    expect(f?.severity).toBe("info");
    expect(f?.title).toMatch(/no stated period/i);
    expect(f?.description).not.toMatch(/annualizes/i);
  });

  it("explicit per-annum rate still runs the usury comparison", () => {
    const ctx = buildContext([
      "Default Interest",
      "Past-due amounts shall bear interest at 30% per annum.",
    ]);
    const f = FIN_009.check(ctx);
    expect(f?.severity).toBe("warning");
    expect(f?.title).toMatch(/30/);
  });
});
