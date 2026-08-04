import { describe, expect, it } from "vitest";
import { rule as CHOICE_003 } from "./CHOICE-003.js";
import { buildContext } from "../../_test-fixtures.js";

describe("CHOICE-003 — venue / forum clause present", () => {
  it("does not warn when a court venue is stated", () => {
    const ctx = buildContext([
      "Venue",
      "The state and federal courts located in Wilmington, Delaware shall have exclusive jurisdiction over any dispute.",
    ]);
    expect(CHOICE_003.check(ctx)).toBeNull();
  });

  it("does not warn on an arbitration-only agreement — arbitration IS a forum (v1.1.0)", () => {
    // The forum is stated (before the named tribunal at its seat); warning "the
    // document does not state where disputes must be brought" is a false
    // accusation on every arbitration-only contract.
    for (const clause of [
      "Any dispute shall be resolved by binding arbitration administered by JAMS in San Francisco, California.",
      "The seat of arbitration shall be London, England.",
    ]) {
      expect(CHOICE_003.check(buildContext(["Dispute Resolution", clause])), clause).toBeNull();
    }
  });

  it("still warns when the document states no forum at all", () => {
    const ctx = buildContext([
      "General",
      "The parties agree to cooperate and to perform their obligations in good faith.",
    ]);
    expect(CHOICE_003.check(ctx)).not.toBeNull();
  });
});
