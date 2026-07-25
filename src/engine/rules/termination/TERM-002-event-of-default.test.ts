import { describe, expect, it } from "vitest";
import { rule as TERM_002 } from "./TERM-002.js";
import { buildContext } from "../../_test-fixtures.js";

// Guard: the "Event of Default" idiom is a for-cause path even when the Default
// definition and the Remedies (terminate) sentence sit in different sections —
// the standard lease/loan structure. TERM-002 must not warn "no for-cause
// clause" on it, while a bare mention with no termination verb still warns.
describe("TERM-002 Event-of-Default idiom", () => {
  it("recognizes the split Default / Remedies structure", () => {
    const ctx = buildContext(
      [
        "Default",
        'The following constitutes an "Event of Default": the Tenant fails to pay any rent when due and such failure continues for five days after written notice.',
      ],
      ["Remedies", "Upon an Event of Default, the Landlord may terminate this Lease and recover possession."],
    );
    expect(TERM_002.check(ctx)).toBeNull();
  });

  it("recognizes terminate-then-Event-of-Default order", () => {
    expect(
      TERM_002.check(
        buildContext(["Remedies", "The Lender may terminate the Loan upon the occurrence of an Event of Default."]),
      ),
    ).toBeNull();
  });

  it("still warns on a bare 'Event of Default' mention with no termination verb", () => {
    expect(
      TERM_002.check(
        buildContext(["Misc", 'An "Event of Default" is defined in the loan agreement referenced herein.']),
      ),
    ).not.toBeNull();
  });

  it("still warns on convenience-only termination", () => {
    expect(
      TERM_002.check(
        buildContext(["Term", "Either party may terminate this Agreement for convenience on 30 days notice."]),
      ),
    ).not.toBeNull();
  });
});
