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
