/**
 * Guards against cross-clause misattribution and document-wide over-suppression
 * false NEGATIVES in the dark-pattern launch rules — a missed dark pattern is a
 * silent under-scan of exactly the manipulative clause these rules exist to
 * catch. Both directions are pinned.
 */
import { describe, expect, it } from "vitest";
import { buildContext } from "../_test-fixtures.js";
import { rule as DARK002 } from "./dark-patterns/DARK-002.js";
import { rule as DARK003 } from "./dark-patterns/DARK-003.js";

const doc = (heading: string, ...rest: string[]) => buildContext([heading, ...rest]);

describe("DARK-002 — auto-renewal notice window", () => {
  it("reads the window from the notice sentence, not an unrelated day count", () => {
    // The real 150-day window (well past the 90-day "buried" threshold) must be
    // detected even though an unrelated "10 days" invoice term sits between
    // "non-renewal" and it.
    expect(
      DARK002.check(
        doc(
          "Term",
          "This Agreement shall automatically renew for successive one-year terms unless a party elects non-renewal. Invoices are due within 10 days of receipt. The party electing non-renewal must give Provider not less than 150 days advance written notice.",
        ),
      ),
    ).not.toBeNull();
  });

  it("does not fire on a short, same-sentence non-renewal window", () => {
    expect(
      DARK002.check(
        doc(
          "Term",
          "This Agreement shall automatically renew unless a party gives non-renewal notice at least 30 days in advance.",
        ),
      ),
    ).toBeNull();
  });

  it("reads the adverb-first 'automatically renews' and a cancellation window (v1.2.0)", () => {
    // "automatically renews" (adverb-first, plural verb) was not detected at
    // all; and the window stated as a cancellation deadline relative to renewal.
    expect(
      DARK002.check(
        doc(
          "Term",
          "The Agreement automatically renews. Notice of cancellation must be given 100 days prior to the renewal date.",
        ),
      ),
    ).not.toBeNull();
    expect(
      DARK002.check(
        doc(
          "Term",
          "The subscription renews automatically. You must cancel at least one hundred twenty (120) days before the renewal date.",
        ),
      ),
    ).not.toBeNull();
  });

  it("does not treat a general cancellation day-count as the renewal window", () => {
    expect(
      DARK002.check(
        doc(
          "Term",
          "The subscription renews automatically. You may cancel within 30 days of any material defect.",
        ),
      ),
    ).toBeNull();
  });
});

describe("DARK-003 — one-way attorneys' fee-shifting", () => {
  it("fires on a one-way clause despite an unrelated 'prevailing party' phrase elsewhere", () => {
    expect(
      DARK003.check(
        doc(
          "Fees",
          "Customer shall pay Vendor's reasonable attorneys' fees incurred in any collection action.",
          "IP Indemnity",
          "In any IP suit, the prevailing party shall recover costs from the losing party.",
        ),
      ),
    ).not.toBeNull();
  });

  it("is suppressed when the fee clause itself uses the prevailing-party formulation", () => {
    expect(
      DARK003.check(
        doc(
          "Fees",
          "Customer shall pay Vendor's reasonable attorneys' fees; provided that in any dispute the prevailing party shall recover its fees.",
        ),
      ),
    ).toBeNull();
  });

  it("reads legal-fees / counsel-fees / legal-costs synonyms and an optional 'the' (v1.3.0)", () => {
    for (const clause of [
      "You shall pay the Company's legal fees and costs incurred in enforcing this Agreement.",
      "Tenant shall reimburse Landlord's reasonable counsel fees.",
      "Borrower agrees to pay Lender's legal costs and expenses.",
    ]) {
      expect(DARK003.check(doc("Fees", clause)), clause).not.toBeNull();
    }
  });

  it("does not fire on a reciprocal 'each party pays its own' clause", () => {
    expect(
      DARK003.check(doc("Fees", "Each party shall pay its own legal fees and costs.")),
    ).toBeNull();
  });
});
