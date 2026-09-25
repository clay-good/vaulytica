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

/**
 * A settlement names its forum by RETAINED jurisdiction: "The Court shall
 * retain jurisdiction to enforce this Agreement" — the court is the one the
 * recitals name, and retention is what lets a federal court enforce a
 * settlement after dismissal (Kokkonen v. Guardian Life, 511 U.S. 375). A clean
 * commercial settlement was told it states no venue.
 */
describe("CHOICE-003 — retained enforcement jurisdiction is a forum clause", () => {
  it("is silent on 'The Court shall retain jurisdiction to enforce this Agreement'", () => {
    expect(
      CHOICE_003.check(
        buildContext([
          "Settlement Agreement",
          "The parties shall file a stipulation dismissing the Action with prejudice.",
          "The Court shall retain jurisdiction to enforce this Agreement.",
        ]),
      ),
    ).toBeNull();
  });
});

/**
 * One law/venue split, one comment. CHOICE-004 (warning, "sometimes
 * deliberate"), CHOICE-012 (warning, "almost always a drafting accident") and
 * CHOICE-009 (info, "a legitimate drafting choice … usually deliberate") all
 * reported Delaware law with a Texas venue, and a reviewed copy of an MSA
 * carried three comments disagreeing with each other about one clause.
 * CHOICE-004 owns the finding; the other two keep only the cases it misses.
 */
describe("CHOICE-004 / -009 / -012 — one law-venue split, one finding", () => {
  it("reports Delaware law with a Texas venue once", async () => {
    const { rule: C4 } = await import("./CHOICE-004.js");
    const { rule: C9 } = await import("./CHOICE-009.js");
    const { rule: C12 } = await import("./CHOICE-012.js");
    const ctx = buildContext([
      "Governing Law",
      "This Agreement is governed by the laws of the State of Delaware. Any action arising out of this Agreement shall be brought exclusively in the state or federal courts located in Travis County, Texas.",
    ]);
    const fired = [C4, C9, C12].filter((r) => r.check(ctx) !== null).map((r) => r.id);
    expect(fired).toEqual(["CHOICE-004"]);
  });
});
