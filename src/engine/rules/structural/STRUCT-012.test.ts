import { describe, expect, it } from "vitest";
import { rule as STRUCT_012 } from "./STRUCT-012.js";
import { buildContext } from "../../_test-fixtures.js";

describe("STRUCT-012 — duplicate headings", () => {
  it("reports two sections at one level sharing a heading", () => {
    const ctx = buildContext(
      ["Payment", "Customer shall pay within thirty days."],
      ["Payment", "Late amounts bear interest."],
    );
    expect(STRUCT_012.check(ctx)?.description).toBe("Payment");
  });

  it("does not count a signature or notary block's label as a section", () => {
    // Set in heading type, a party's name heads each signature block and a
    // deed's venue heads each acknowledgment; nothing cross-refers to them.
    const ctx = buildContext(
      ["HOLLOWAY & NANDAKUMAR LLP", "Counsel for Appellant"],
      ["Argument", "The judgment should be reversed."],
      ["HOLLOWAY & NANDAKUMAR LLP", "/s/ Devarshi Nandakumar"],
      ["STATE OF TEXAS, COUNTY OF TRAVIS", "Acknowledged before me."],
      ["STATE OF TEXAS, COUNTY OF TRAVIS", "Acknowledged before me."],
    );
    expect(STRUCT_012.check(ctx)).toBeNull();
  });
});
