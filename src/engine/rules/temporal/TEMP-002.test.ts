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
