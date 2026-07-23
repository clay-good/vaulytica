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
import { rule as FIN005 } from "./financial/FIN-005.js";

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

describe("STRUCT-003 — the individual signatory (v1.1.0)", () => {
  it("attestation formula plus a single By: line is an executed signature page", () => {
    // An individual signs with a bare typed name — no By/Name/Title labels —
    // so a company-and-person contract carries exactly one anchored token.
    // The IN WITNESS WHEREOF recital supplies the second signal.
    expect(
      STRUCT003.check(
        doc(
          "General",
          "This Agreement may be amended only in writing.",
          "IN WITNESS WHEREOF, the parties have executed this Agreement as of the Effective Date.",
          "Halewood Media LLC",
          "By: Jordan Feld, Managing Member",
          "Priya Raman",
          "Contractor",
        ),
      ),
    ).toBeNull();
  });

  it("the recital alone, with no signature line at all, still fires", () => {
    expect(
      STRUCT003.check(
        doc(
          "General",
          "IN WITNESS WHEREOF, the parties have executed this Agreement as of the date first written above. The parties are done.",
        ),
      ),
    ).not.toBeNull();
  });
});

describe("FIN-005 — a purchase-price schedule is a payment term (v1.1.0)", () => {
  it("accepts 'payable as follows' with business-day intervals", () => {
    expect(
      FIN005.check(
        doc(
          "Purchase Price",
          "The purchase price for the Purchased Assets is $410,000, payable as follows: (a) $41,000 as an earnest deposit within three (3) business days after the Effective Date; and (b) $369,000 in cash at the Closing.",
        ),
      ),
    ).toBeNull();
  });

  it("accepts the installment form", () => {
    expect(
      FIN005.check(
        doc(
          "Note",
          "The note fee is payable in twelve (12) equal monthly installments beginning thirty (30) days after the Closing Date.",
        ),
      ),
    ).toBeNull();
  });

  it("still fires when payment is referenced with no stated term", () => {
    expect(
      FIN005.check(
        doc("Fees", "Customer shall make payment for the services set forth in the Order Form."),
      ),
    ).not.toBeNull();
  });
});
