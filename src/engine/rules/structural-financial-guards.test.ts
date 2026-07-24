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
import { rule as STRUCT018 } from "./structural/STRUCT-018.js";
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

describe("STRUCT-003 — conformed signatures and certification (v1.2.0)", () => {
  it("accepts a bylaws certification with a conformed /s/ signature", () => {
    const ctx = buildContext(
      ["Bylaws", "These Bylaws were adopted by the Board of Directors."],
      ["Amendment", "These Bylaws may be amended by the Board."],
      [
        "Certification",
        "Certified as adopted by the Board of Directors as of April 2, 2026.",
        "/s/ Priya Raman Priya Raman, Secretary",
      ],
    );
    expect(STRUCT003.check(ctx)).toBeNull();
  });

  it("still fires when a document has a certification recital but no signature line", () => {
    const ctx = buildContext(
      ["Bylaws", "These Bylaws were adopted by the Board of Directors."],
      ["Amendment", "These Bylaws may be amended by the Board of Directors at any meeting."],
    );
    expect(STRUCT003.check(ctx)).not.toBeNull();
  });
});

describe("STRUCT-003 — a dated adoption recital executes an adopted instrument (v1.3.0)", () => {
  it("accepts a committee charter adopted by board resolution", () => {
    const ctx = buildContext(
      ["Audit Committee Charter", "Adopted by the Board of Directors on August 15, 2026."],
      ["Purpose", "The Committee oversees the integrity of the financial statements."],
      ["Reports", "The Committee shall report regularly to the Board."],
    );
    expect(STRUCT003.check(ctx)).toBeNull();
  });

  it("an undated 'may be adopted by the Board' amendment clause is not execution", () => {
    const ctx = buildContext(
      ["Charter", "The Committee oversees the audit function."],
      ["Amendment", "This Charter may be adopted, amended, or repealed by the Board."],
    );
    expect(STRUCT003.check(ctx)).not.toBeNull();
  });
});

describe("STRUCT-003 — a delivery instrument executes by delivery (v1.4.0)", () => {
  it("accepts disclosure schedules delivered pursuant to an SPA", () => {
    const ctx = buildContext(
      [
        "Disclosure Schedules",
        "These Disclosure Schedules are delivered by Seller pursuant to the Stock Purchase Agreement dated December 15, 2026.",
      ],
      ["Litigation", "The matters set forth below are disclosed in response to Section 3.7."],
    );
    expect(STRUCT003.check(ctx)).toBeNull();
  });
});

describe("STRUCT-018 — decimal schedule designators (v1.1.0)", () => {
  it("reconciles 'Schedule 3.7' against its own titled section", () => {
    const ctx = buildContext(
      ["Intro", "The items on Schedule 3.7 are disclosed in response to the Agreement."],
      ["Body", "3. Schedule 3.7 — Litigation. The matters below are disclosed."],
    );
    expect(STRUCT018.check(ctx)).toBeNull();
  });

  it("still reports a genuinely missing decimal schedule", () => {
    const ctx = buildContext([
      "Intro",
      "The excluded assets are listed on Schedule 2.4 to this Agreement.",
    ]);
    expect(STRUCT018.check(ctx)).not.toBeNull();
  });
});

describe("STRUCT-003 — a published notice is issued, not signed (v1.5.0)", () => {
  it("accepts a cookie notice carrying a 'Last updated' stamp", () => {
    const ctx = buildContext(
      ["Cookie Notice", "Last updated: March 3, 2027"],
      ["About", "This Cookie Notice explains how we use cookies on our website."],
      ["Consent", "We place non-essential cookies only after you give consent."],
    );
    expect(STRUCT003.check(ctx)).toBeNull();
  });

  it("an unsigned agreement with only an 'Effective Date:' line still fires", () => {
    const ctx = buildContext(
      ["Services Agreement", "Effective Date: March 3, 2027"],
      ["Services", "Vendor shall provide the Services described in Exhibit A."],
    );
    expect(STRUCT003.check(ctx)).not.toBeNull();
  });
});
