import { describe, expect, it } from "vitest";
import { rule as STRUCT_002 } from "./STRUCT-002.js";
import { buildContext } from "../../_test-fixtures.js";

describe("STRUCT-002 — the execution date of a signed form", () => {
  // A contributor license agreement, a consent, an acknowledgment and an offer
  // letter all put their only date on the "Date:" line the signer fills in, at
  // the BOTTOM of the page — nowhere near the first quarter — and every one of
  // them was told it states no effective date.
  it.each(["Date: May 14, 2026", "Dated: May 14, 2026", "Dated this 14th day of May, 2026"])(
    "accepts %s on the signature block",
    (line) => {
      expect(
        STRUCT_002.check(
          buildContext([
            "Individual Contributor License Agreement",
            "You grant the Foundation a perpetual, worldwide, royalty-free copyright license to Your Contributions.",
            "You represent that each of Your Contributions is Your original creation.",
            "Signature: /s/ Rosalind Achebe-Karlsson",
            line,
          ]),
        ),
      ).toBeNull();
    },
  );

  it("still reports a document with no date anywhere", () => {
    expect(
      STRUCT_002.check(
        buildContext([
          "Agreement",
          "The parties agree as follows.",
          "Vendor shall provide the Services.",
        ]),
      ),
    ).not.toBeNull();
  });
});

describe("STRUCT-002 — the execution recital at the foot of an instrument", () => {
  // "IN WITNESS WHEREOF, the parties have EXECUTED this Assignment of Claim AS
  // OF November 12, 2026." An instrument that dates itself only where it is
  // signed has an identifiable starting point, and the first-quarter test
  // never reaches it.
  it.each([
    "IN WITNESS WHEREOF, the parties have executed this Assignment of Claim as of November 12, 2026.",
    "The parties have signed this instrument as of 12 November 2026.",
  ])("accepts %s", (line) => {
    expect(
      STRUCT_002.check(
        buildContext([
          "Assignment of Claim",
          "For value received, Assignor assigns to Assignee all of its right, title and interest in the Claim.",
          "Assignor represents that it is the sole owner of the Claim.",
          line,
        ]),
      ),
    ).toBeNull();
  });

  it("does not accept a date that cannot exist", () => {
    // The corpus's `bad-nda` is dated "as of February 30, 2026", which is the
    // point of that fixture. The recital branch reads the EXTRACTED date, so a
    // surface pattern that looks like a date but does not parse is not one.
    expect(
      STRUCT_002.check(
        buildContext([
          "Mutual Non-Disclosure Agreement",
          "Each party shall keep the other's Confidential Information confidential.",
          "This Agreement is entered into as of February 30, 2026 between the parties.",
        ]),
      ),
    ).not.toBeNull();
  });

  it("does not accept an execution recital with no date", () => {
    expect(
      STRUCT_002.check(
        buildContext([
          "Assignment of Claim",
          "For value received, Assignor assigns to Assignee all of its right, title and interest in the Claim.",
          "IN WITNESS WHEREOF, the parties have executed this Assignment of Claim as of the date first written above.",
        ]),
      ),
    ).not.toBeNull();
  });
});

/**
 * The FORMAL EXECUTION LINE of an instrument.
 *
 * "SIGNED AND SEALED this 2nd day of February, 2026". Every bond, deed, will,
 * affidavit, and acknowledgment dates itself there and nowhere else. The
 * branch that read the "Nth day of" scaffold wanted the word "Dated" in front
 * of it, so a payment and performance bond whose foot carries its own date in
 * the oldest form there is was told it states no effective date.
 */
describe("STRUCT-002 — the formal execution line", () => {
  const bond = (closing: string) =>
    buildContext([
      "Payment and Performance Bond",
      "KNOW ALL PERSONS BY THESE PRESENTS, that we, the Principal and the Surety, are held and firmly bound unto the Obligee in the penal sum stated above.",
      "Surety's aggregate liability under this Bond shall not exceed the penal sum.",
      closing,
    ]);

  it.each([
    ["all caps with a sealing verb", "SIGNED AND SEALED this 2nd day of February, 2026."],
    ["mixed case", "Executed this 6th day of February, 2026."],
    ["the attesting hand", "WITNESS my hand this 14th day of March, 2026."],
    ["the older form still", "Dated this 3rd day of April, 2026."],
  ])("finds the date in %s", (_label, closing) => {
    expect(STRUCT_002.check(bond(closing))).toBeNull();
  });

  // Load-bearing: the identical instrument with an UNDATED execution line is
  // exactly what the rule exists to report.
  it.each([
    ["a blank day", "SIGNED AND SEALED this ____ day of ____________, 20__."],
    ["no execution line at all", "The Surety executes this Bond by its Attorney-in-Fact."],
  ])("still fires on %s", (_label, closing) => {
    expect(STRUCT_002.check(bond(closing))).not.toBeNull();
  });
});
