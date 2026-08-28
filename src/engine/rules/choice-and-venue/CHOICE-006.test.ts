/**
 * CHOICE-006 surfaces an arbitration clause. v1.1.0 also recognizes clauses that
 * lead with "arbitral tribunal" or "arbitrators" without the word "arbitration"
 * — while excluding the unrelated word "arbitrary".
 */
import { describe, expect, it } from "vitest";
import { rule as CHOICE_006 } from "./CHOICE-006.js";
import { buildContext } from "../../_test-fixtures.js";

const fires = (s: string) => CHOICE_006.check(buildContext(["Dispute Resolution", s])) !== null;

describe("CHOICE-006 — arbitration clause present", () => {
  it("fires on the word 'arbitration'", () => {
    expect(fires("Any dispute shall be resolved by binding arbitration.")).toBe(true);
  });

  it("reads 'arbitral tribunal' / 'arbitrators' / 'arbitrate' (v1.1.0)", () => {
    expect(
      fires("All disputes shall be finally settled by an arbitral tribunal seated in Geneva."),
    ).toBe(true);
    expect(fires("The dispute shall be referred to three arbitrators under the ICC Rules.")).toBe(
      true,
    );
    expect(fires("The parties agree to arbitrate any dispute.")).toBe(true);
  });

  it("does not fire on the unrelated word 'arbitrary'", () => {
    expect(fires("The decision shall not be arbitrary or capricious.")).toBe(false);
  });

  it("does not fire on a court-litigation clause", () => {
    expect(fires("Disputes shall be resolved in the courts of Delaware.")).toBe(false);
  });
});

describe("CHOICE-006 — arbitration named in a definition is not an arbitration clause", () => {
  /**
   * '"Proceeding" means any threatened, pending, or completed action, suit,
   * arbitration, alternative dispute resolution proceeding, administrative
   * hearing, or investigation' enumerates the forums a claim might take; it
   * does not agree to any of them. Every indemnification agreement, D&O
   * policy, and litigation-hold notice carries that list, and each was
   * reported as having an arbitration clause "with the seat not specified".
   */
  const DEFN =
    '"Proceeding" means any threatened, pending, or completed action, suit, arbitration, alternative dispute resolution proceeding, administrative hearing, or investigation, whether civil, criminal, administrative, or investigative.';

  it("is silent on the enumeration alone", () => {
    expect(CHOICE_006.check(buildContext(["Definitions", DEFN]))).toBeNull();
  });

  it("still fires on a real clause in the same document (v1.2.0)", () => {
    // The enumeration comes first. Testing only the first hit would hide every
    // real occurrence behind it.
    expect(
      CHOICE_006.check(
        buildContext([
          "Definitions",
          DEFN,
          "Disputes",
          "All Proceedings between the parties shall be settled by arbitration under the AAA Commercial Rules.",
        ]),
      ),
    ).not.toBeNull();
  });

  it("does not suppress a paragraph that defines a term and then arbitrates", () => {
    expect(
      CHOICE_006.check(
        buildContext([
          "Disputes",
          '"Dispute" means any claim, action, or suit between the parties. All Disputes shall be resolved by binding arbitration.',
        ]),
      ),
    ).not.toBeNull();
  });
});
