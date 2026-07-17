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

  it("does not read an unlabeled amount that merely sits near other text", () => {
    expect(dealValue("The cap is 8x fees and a $50,000 penalty applies on default.")).toBeNull();
    expect(dealValue("Payment of $9,999,999 is due to the vendor each quarter.")).toBeNull();
  });

  it("ignores a labeled total whose amount is zero or missing (no false deal size)", () => {
    // A '$0' placeholder is filtered (value must be > 0); with no other labeled
    // amount the result is null, not a bogus 0.
    expect(dealValue("Total contract value: $0 (to be set in Schedule A).")).toBeNull();
  });

  it("handles a colon and a k-suffix on a labeled total", () => {
    expect(dealValue("Total Fees: $750k.")?.value).toBe(750_000);
  });

  // Regression (reviewer P1): the amount must be the labeled total, not a stray
  // figure in a LATER sentence that merely follows the label phrase.
  it("does not read an amount from a later sentence than the label", () => {
    expect(
      dealValue(
        "This clause has nothing to do with the total contract value. A late fee of $500 applies per invoice.",
      ),
    ).toBeNull();
    expect(
      dealValue(
        "The total contract value excludes taxes. See $75 filing fee below. The actual total is $9,000,000 in Exhibit A.",
      ),
    ).toBeNull();
  });

  it("reads a labeled total joined by a connector (is / of / equals / colon)", () => {
    expect(dealValue("The total contract value equals $8,000,000.")?.value).toBe(8_000_000);
    expect(dealValue("Total consideration of $8,000,000.")?.value).toBe(8_000_000);
  });

  it("falls back to null (honest default) when a non-connector clause separates label and amount", () => {
    // Honesty-first: rather than risk misattributing the amount, an unusual
    // clause between the label and the figure yields no deal value (the run
    // then uses the base default and the user can pass --deal-value).
    expect(dealValue("The total contract value under this Agreement is $8,000,000.")).toBeNull();
  });

  it("does not read an unrelated figure buried mid-clause after the label", () => {
    expect(
      dealValue("The total contract value, less the $500 processing deposit noted above, remains."),
    ).toBeNull();
  });

  it("matches the label case-insensitively", () => {
    expect(dealValue("TOTAL CONTRACT VALUE: $5,000,000.")?.value).toBe(5_000_000);
  });

  it("does not read a non-dollar quantity after 'not to exceed' (e.g. a day count)", () => {
    expect(dealValue("The cure period shall not to exceed 30 days.")).toBeNull();
  });

  it("skips a label with no valid amount and uses a later labeled total", () => {
    // First 'total fees' has no adjacent amount; the later 'total contract
    // value: $4,000,000' is the real, earliest VALID labeled total.
    const r = dealValue("Total fees are described in Exhibit B. Total contract value: $4,000,000.");
    expect(r?.value).toBe(4_000_000);
  });

  // Form 2 — amount first, parenthetically labeled (common in purchase agreements).
  it("reads the parenthetical amount-first form", () => {
    expect(dealValue('The purchase price is $5,000,000 (the "Total Contract Value").')?.value).toBe(
      5_000_000,
    );
    expect(dealValue("Consideration of $2.5 million (Total Consideration) is due.")?.value).toBe(
      2_500_000,
    );
  });

  it("does not match a parenthetical that is not the label alone", () => {
    // A non-label parenthetical, and a negated label in parens, must not match.
    expect(dealValue("A fee of $500 (a late charge) applies.")).toBeNull();
    expect(dealValue("The $500 (not the total contract value) is a deposit.")).toBeNull();
    expect(dealValue("$500 (the total contract value is stated elsewhere).")).toBeNull();
  });
});
