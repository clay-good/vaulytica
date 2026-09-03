import { describe, expect, it } from "vitest";
import { rule as RISK_010 } from "./RISK-010.js";
import { buildContext } from "../../_test-fixtures.js";

const fires = (body: string) => RISK_010.check(buildContext(["Insurance", body])) !== null;

describe("RISK-010 — insurance requirement levels", () => {
  it("surfaces the originally-supported coverage types", () => {
    expect(
      fires("Contractor shall maintain commercial general liability insurance of $1,000,000."),
    ).toBe(true);
    expect(fires("Vendor shall carry professional liability insurance of $2,000,000.")).toBe(true);
  });

  // v1.1.0 — services / construction contracts also state umbrella / workers'
  // comp / auto / D&O limits and abbreviate CGL / D&O, all previously unsurfaced.
  it("surfaces the previously-missed coverage types and abbreviations", () => {
    for (const body of [
      "Contractor shall maintain CGL insurance of $1,000,000 per occurrence.",
      "Vendor shall carry umbrella liability coverage of $5,000,000.",
      "Contractor shall maintain workers compensation insurance of $1,000,000.",
      "Automobile liability of $1,000,000 combined single limit is required.",
      "The Company shall maintain D&O insurance of $10,000,000.",
    ]) {
      expect(fires(body), body).toBe(true);
    }
  });

  it("does not read an 'umbrella clause of $X' (non-insurance) as a coverage limit", () => {
    expect(fires("The umbrella clause of $5,000 governs the parties' relationship.")).toBe(false);
  });

  // v1.2.0 — an international contract states its minimum in an ISO code or a
  // non-dollar symbol, and the rule wanted the dollar GLYPH. The extractor has
  // read the codes since it was written; the rule layer now shares its token.
  it.each([
    ["the glyph", "Vendor shall maintain cyber liability insurance of $2,000,000 per occurrence."],
    ["USD", "Vendor shall maintain cyber liability insurance of USD 2,000,000 per occurrence."],
    ["EUR", "Vendor shall maintain cyber liability insurance of EUR 2.000.000 per occurrence."],
    [
      "a pound sign",
      "Vendor shall maintain cyber liability insurance of £2,000,000 per occurrence.",
    ],
  ])("reads a coverage minimum stated in %s", (_label, body) => {
    expect(fires(body), body).toBe(true);
  });
});
