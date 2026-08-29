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
