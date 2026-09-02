import { describe, expect, it } from "vitest";
import { rule as TEMP_010 } from "./TEMP-010.js";
import { buildContext } from "../../_test-fixtures.js";

const doc = (heading: string, ...rest: string[]) => buildContext([heading, ...rest]);

describe("TEMP-010 — specific dates after expiry", () => {
  // v1.1.0 — previously matched only ISO-formatted expiry dates, so it never
  // fired on the "Month DD, YYYY" form real contracts use.
  it("fires on a 'Month DD, YYYY' expiry with a later date", () => {
    const f = TEMP_010.check(
      doc(
        "Term",
        "This Agreement expires on December 31, 2026. Vendor shall deliver the final report by March 15, 2027.",
      ),
    );
    expect(f).not.toBeNull();
    expect(f?.title).toMatch(/2027-03-15/);
    expect(f?.title).toMatch(/2026-12-31/);
  });

  it("still fires on an ISO-formatted expiry with a later date", () => {
    const f = TEMP_010.check(
      doc(
        "Term",
        "This Agreement expires 2026-12-31. A milestone is due 2027-06-01 under a separate schedule.",
      ),
    );
    expect(f).not.toBeNull();
  });

  it("is silent when no date falls after the expiration", () => {
    expect(
      TEMP_010.check(
        doc(
          "Term",
          "This Agreement expires on December 31, 2026. It was executed on January 1, 2026.",
        ),
      ),
    ).toBeNull();
  });

  it("is silent when there is no expiration keyword", () => {
    expect(
      TEMP_010.check(doc("Dates", "The kickoff is March 1, 2026 and delivery is June 1, 2027.")),
    ).toBeNull();
  });
});

describe("TEMP-010 — an amendment recites the expiry it replaces (v1.2.0)", () => {
  it("takes the LATEST stated expiration, not the first", () => {
    // The recital of an amendment states the expiry being replaced, and the
    // operative section states the new one. Taking the first made every date
    // in the extension — including its own commencement date — read as
    // falling after the contract's expiration, which is a false statement
    // about the document.
    expect(
      TEMP_010.check(
        doc(
          "Third Amendment to Office Lease",
          "The Term of the Lease is scheduled to expire on August 31, 2026, and the parties wish to extend the Term.",
          "The Term is extended for sixty months, commencing September 1, 2026 and expiring August 31, 2031.",
        ),
      ),
    ).toBeNull();
  });

  it("still fires on a date after the latest stated expiration", () => {
    expect(
      TEMP_010.check(
        doc(
          "Third Amendment to Office Lease",
          "The Term of the Lease is scheduled to expire on August 31, 2026, and the parties wish to extend the Term.",
          "The Term is extended, commencing September 1, 2026 and expiring August 31, 2031.",
          "Tenant shall deliver the final reconciliation statement by March 15, 2032.",
        ),
      ),
    ).not.toBeNull();
  });
});

describe("a notary's commission is not the document's expiration", () => {
  // A notarial certificate ends "My commission expires: October 31, 2028",
  // and it sits at the bottom of every recorded deed, mortgage, will, and
  // affidavit. A deed of trust securing a note that matures in 2036 was
  // reported as containing a date after its own expiration in 2028.
  it("does not read the notary block as an expiration", () => {
    const f = TEMP_010.check(
      doc(
        "Deed of Trust",
        "This Deed of Trust secures a Promissory Note in the principal amount of $4,750,000, with a maturity date of March 14, 2036.",
        "Aoife Brennan, Notary Public. My commission expires: October 31, 2028.",
      ),
    );
    expect(f).toBeNull();
  });

  it("still reads a real expiration in the same document", () => {
    const f = TEMP_010.check(
      doc(
        "Deed of Trust",
        "This Deed of Trust expires on October 31, 2028. Beneficiary may exercise the option at any time before March 14, 2036.",
        "Aoife Brennan, Notary Public. My commission expires: December 31, 2040.",
      ),
    );
    expect(f?.title).toContain("2036-03-14");
  });
});

describe("TEMP-010 — an offer's expiry is the deadline to accept it", () => {
  it("is silent on a start date after the offer expires", () => {
    // "This offer expires on August 10, 2026" sits at the foot of every offer
    // letter, above a start date weeks later. The same shape as the notary's
    // commission the guard was written for.
    expect(
      TEMP_010.check(
        buildContext([
          "Re: Offer of Employment",
          "Your anticipated start date is September 14, 2026, and your first review will be on March 1, 2027.",
          "This offer expires on August 10, 2026. To accept, sign below and return a copy.",
        ]),
      ),
    ).toBeNull();
  });
});
