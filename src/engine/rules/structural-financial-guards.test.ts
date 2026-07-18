/**
 * Guards against false-negative (prose satisfies a heuristic) and false-positive
 * (cross-clause / disclaimed / intentional-schedule) findings in the structural
 * and financial launch rules. Each case reproduced a wrong finding or a wrong
 * silence on realistic drafting before the fix; both directions are pinned.
 */
import { describe, expect, it } from "vitest";
import { buildContext } from "../_test-fixtures.js";
import { rule as STRUCT003 } from "./structural/STRUCT-003.js";
import { rule as STRUCT016 } from "./structural/STRUCT-016.js";
import { rule as FIN002 } from "./financial/FIN-002.js";

const doc = (heading: string, ...rest: string[]) => buildContext([heading, ...rest]);

describe("STRUCT-003 — signature-block detection", () => {
  it("fires 'no signature block' when only prose words (by/date/title) appear", () => {
    // "passes by that date", "Title to the Goods" must NOT count as signature
    // signals — otherwise the critical finding is silently suppressed.
    expect(
      STRUCT003.check(
        doc(
          "Delivery",
          "Title to the Goods passes upon delivery by Vendor, and risk of loss transfers by that date. The parties are done.",
        ),
      ),
    ).not.toBeNull();
  });

  it("stays silent on a real colon- or underscore-labelled signature block", () => {
    expect(
      STRUCT003.check(
        doc("Signatures", "By: ______  Name: Jane Roe", "Title: CEO  Date: 2026-01-01"),
      ),
    ).toBeNull();
    expect(
      STRUCT003.check(
        doc(
          "Execution",
          "IN WITNESS WHEREOF the parties execute this Agreement.",
          "By ______________",
          "Name ______________",
        ),
      ),
    ).toBeNull();
  });
});

describe("STRUCT-016 — incorporation by reference", () => {
  it("does not fire on a disclaimed support-portal URL in a governing-law clause", () => {
    expect(
      STRUCT016.check(
        doc(
          "Governing Law",
          "This Agreement shall be governed by the laws of Delaware. For general product Documentation, see the support portal at https://support.example.com/docs, which is provided for convenience only and is not part of this Agreement.",
        ),
      ),
    ).toBeNull();
  });

  it("still fires on a genuine URL-hosted incorporation", () => {
    expect(
      STRUCT016.check(
        doc(
          "Terms",
          "Customer's use is subject to Vendor's Acceptable Use Policy available at https://vendor.example.com/aup.",
        ),
      ),
    ).not.toBeNull();
  });
});

describe("FIN-002 — inconsistent named amounts", () => {
  it("does not flag an intentional escalation schedule as a conflict", () => {
    expect(
      FIN002.check(
        doc(
          "Rent",
          "For the first Lease Year, the Base Rent of $2,000 per month applies.",
          "For the second Lease Year, the Base Rent of $2,200 per month applies, reflecting escalation.",
        ),
      ),
    ).toBeNull();
  });

  it("still flags a genuine value contradiction", () => {
    expect(
      FIN002.check(
        doc(
          "Cap",
          "Liability is limited to the Liability Cap of $1,000,000.",
          "Notwithstanding, the Liability Cap of $500,000 shall control.",
        ),
      ),
    ).not.toBeNull();
  });
});
