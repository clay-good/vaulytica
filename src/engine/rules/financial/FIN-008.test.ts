import { describe, expect, it } from "vitest";
import { rule as FIN_008 } from "./FIN-008.js";
import { buildContext } from "../../_test-fixtures.js";

const fires = (body: string) => FIN_008.check(buildContext(["Commitment", body])) !== null;

describe("FIN-008 — minimum commitment / take-or-pay", () => {
  it("fires on the existing minimum-commitment / take-or-pay terms", () => {
    expect(fires("Customer agrees to a minimum commitment of $500,000 per year.")).toBe(true);
    expect(fires("This is a take-or-pay arrangement for the gas supply.")).toBe(true);
  });

  // v1.1.0 — the same commitment is written minimum purchase / spend / volume,
  // committed volume, etc.
  it("fires on the minimum-purchase / spend / committed-volume synonyms", () => {
    expect(fires("Buyer shall meet a minimum purchase of 10,000 units annually.")).toBe(true);
    expect(fires("A minimum spend of $250,000 applies each contract year.")).toBe(true);
    expect(fires("The committed volume is 5,000 units per quarter.")).toBe(true);
    expect(fires("Customer guarantees a minimum annual volume of 100,000 licenses.")).toBe(true);
  });

  it("does not fire on an unrelated 'minimum age' clause", () => {
    expect(fires("The minimum age for the service is 18 years.")).toBe(false);
  });

  it("reads guaranteed-minimum / period-minimum / minimum-revenue / purchase-quota forms (v1.2.0)", () => {
    expect(fires("Customer shall pay a guaranteed minimum of $100,000 annually.")).toBe(true);
    expect(fires("The agreement includes an annual minimum guarantee of $250,000.")).toBe(true);
    expect(fires("Customer shall meet an annual minimum of $500,000 in purchases.")).toBe(true);
    expect(fires("Distributor shall generate a minimum revenue of $1,000,000 per year.")).toBe(true);
    expect(fires("Customer shall purchase at least 10,000 units per calendar year.")).toBe(true);
  });

  it("does not fire on an unrelated 'minimum notice' or 'minimum standard' clause (v1.2.0)", () => {
    expect(fires("Either party shall give a minimum notice of 30 days.")).toBe(false);
    expect(fires("A minimum standard of care applies to all work.")).toBe(false);
  });
});
