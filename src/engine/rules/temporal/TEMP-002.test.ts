/**
 * TEMP-002 flags a back-dated effective date. Its test was "the earliest date
 * precedes the next by more than 30 days", which is true of any multi-year
 * contract that states only a start and an end: a five-year term loan
 * (2026-03-01 → 2031-03-01) and a one-year insurance policy period
 * (2026-01-01 → 2027-01-01) were both reported as possibly back-dated.
 *
 * Back-dating is the earliest date sitting apart from the document's own
 * cluster of dates, so it needs at least three dates and a gap wider than the
 * spread of the rest.
 */
import { describe, expect, it } from "vitest";
import { rule as TEMP_002 } from "./TEMP-002.js";
import { buildContext } from "../../_test-fixtures.js";

const doc = (t: string) => buildContext(["Agreement", t]);

describe("TEMP-002 — past-dated effective date", () => {
  it("fires when the earliest date sits far before a cluster of other dates", () => {
    expect(
      TEMP_002.check(
        doc(
          "This Agreement is effective as of January 1, 2024. Payment is due March 1, 2026. Delivery occurs March 15, 2026. The term ends April 1, 2026.",
        ),
      ),
    ).not.toBeNull();
  });

  it("stays silent on a two-date term (a five-year loan)", () => {
    expect(
      TEMP_002.check(
        doc(
          "This Loan Agreement is dated March 1, 2026. The final installment is due March 1, 2031.",
        ),
      ),
    ).toBeNull();
  });

  it("stays silent on a lease signed a month before it commences", () => {
    expect(
      TEMP_002.check(
        doc(
          "This Lease is dated March 1, 2026, commencing April 1, 2026 and ending March 31, 2031.",
        ),
      ),
    ).toBeNull();
  });

  it("stays silent on a one-year insurance policy period", () => {
    expect(
      TEMP_002.check(doc("The policy period is January 1, 2026 to January 1, 2027.")),
    ).toBeNull();
  });
});

describe("TEMP-002 — a referenced instrument's date is not this document's", () => {
  it("stays silent when the earliest date belongs to the parent agreement", () => {
    // "incorporated into the Master Services Agreement between the parties
    // dated January 1, 2026" is the MSA's date, not the DPA's effective date,
    // so it cannot evidence that the DPA was back-dated.
    expect(
      TEMP_002.check(
        buildContext(
          [
            "DPA",
            'This Data Processing Agreement ("DPA") is entered into as of February 1, 2026, between Globex Inc. and Wayne Enterprises LLC.',
          ],
          [
            "Incorporation",
            'This DPA supplements and is incorporated into the Master Services Agreement between the parties dated January 1, 2026 (the "MSA").',
          ],
          ["Notice", "Processor shall notify Controller by March 1, 2026."],
        ),
      ),
    ).toBeNull();
  });

  it("still counts the document's OWN 'This Agreement, dated …' date", () => {
    expect(
      TEMP_002.check(
        buildContext([
          "Agreement",
          "This Agreement, dated January 1, 2024, is between A and B. Payment is due March 1, 2026. Delivery March 15, 2026. Ends April 1, 2026.",
        ]),
      ),
    ).not.toBeNull();
  });
});

describe("TEMP-002 — a stated period boundary is not an effective date", () => {
  it("stays silent when the earliest date opens a records period", () => {
    // A HIPAA authorization covering "the period 2024-01-01 through
    // 2026-12-31" is not back-dated to 2024; that is the span of records.
    expect(
      TEMP_002.check(
        buildContext(
          [
            "Authorization",
            "I authorize release of medical records, lab results, and treatment notes from the period 2024-01-01 through 2026-12-31.",
          ],
          ["Expiration", "This authorization expires on 2026-12-31."],
          ["Signature", "Signed on 2026-12-15."],
        ),
      ),
    ).toBeNull();
  });
});

describe("a birthdate is biography, not an effective date (v1.1.0)", () => {
  it("does not compare a declarant's birthdate against the execution date", () => {
    const ctx = buildContext([
      "Declarant",
      "I, Edwin Marsh, born April 4, 1955, residing in Brattleboro, Vermont, make this directive.",
      "Signed voluntarily on November 5, 2026.",
    ]);
    expect(TEMP_002.check(ctx)).toBeNull();
  });
});

describe("a case citation's date is the opinion's, not the document's (v1.2.0)", () => {
  it("does not compare a cited opinion's date against the filing dates", () => {
    const ctx = buildContext([
      "Authorities",
      "Akorn, Inc. v. Fresenius Kabi AG, 2018 WL 4719347 (Del. Ch. Oct. 1, 2018).",
      "The district court entered judgment on August 29, 2026, and the notice of appeal was filed on September 24, 2026.",
    ]);
    expect(TEMP_002.check(ctx)).toBeNull();
  });
});
