import { describe, expect, it } from "vitest";
import { rule as TEMP_004 } from "./TEMP-004.js";
import { buildContext } from "../../_test-fixtures.js";

/**
 * The recommendation says auto-renewal laws require "an easy cancellation
 * path", and the rule never looked for one. A gym membership and a consumer
 * terms of service that let the customer cancel online, at any time, drew the
 * same warning as a renewal with no way out. A rule that states a
 * precondition must test it.
 */
describe("TEMP-004 — an auto-renewal with an online cancellation path", () => {
  it("is info when the customer can cancel online", () => {
    const f = TEMP_004.check(
      buildContext([
        "Membership",
        "Your membership renews automatically each month at the same price until you cancel.",
        "You may cancel your membership at any time online in your account or by email; you do not need to call us.",
      ]),
    );
    expect(f?.severity).toBe("info");
    expect(f?.title).toBe("Auto-renewal clause present, with an online cancellation path");
  });

  it("stays a warning when no easy cancellation path is stated", () => {
    const f = TEMP_004.check(
      buildContext([
        "Membership",
        "Your membership renews automatically each month until you cancel by certified letter to our head office.",
      ]),
    );
    expect(f?.severity).toBe("warning");
  });
});
