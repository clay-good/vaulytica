import { describe, expect, it } from "vitest";

import { extractDealValue } from "./deal-value.js";
import { buildTree } from "./_fixtures.js";

function dealValue(...paras: string[]) {
  return extractDealValue(buildTree(["Agreement", ...paras]));
}

describe("extractDealValue — labeled total only (never a guess)", () => {
  it("extracts a labeled total contract value with separators", () => {
    expect(dealValue("The total contract value is $5,000,000 over the term.")).toEqual({
      value: 5_000_000,
      label: "total contract value",
    });
  });

  it("resolves scale words and suffixes", () => {
    expect(dealValue("Total consideration: $1.5 million.")?.value).toBe(1_500_000);
    expect(dealValue("aggregate fees of $500k")?.value).toBe(500_000);
    expect(dealValue("total purchase price $2.25 billion")?.value).toBe(2_250_000_000);
  });

  it("matches a 'not to exceed' cap phrasing", () => {
    expect(dealValue("Fees under this SOW shall not to exceed $250,000.")?.value).toBe(250_000);
  });

  it("returns null when no labeled total is stated (never guesses from a stray amount)", () => {
    expect(dealValue("A late fee of $1,000 applies. The cap is 8x fees.")).toBeNull();
    expect(dealValue("No dollar figures here at all.")).toBeNull();
  });

  it("does not fire when a label is not immediately followed by an amount", () => {
    expect(
      dealValue("The total contract value shall be determined by the parties in Schedule A."),
    ).toBeNull();
  });

  it("earliest label wins across the document (deterministic)", () => {
    const r = dealValue(
      "Total consideration: $3,000,000.",
      "Later, the aggregate fees of $9,000,000 are noted.",
    );
    expect(r?.value).toBe(3_000_000);
    expect(r?.label).toBe("total consideration");
  });

  it("is deterministic", () => {
    const doc = "The total contract value is $7,500,000.";
    expect(dealValue(doc)).toEqual(dealValue(doc));
  });
});
