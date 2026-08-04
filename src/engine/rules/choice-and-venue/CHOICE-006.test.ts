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
    expect(fires("All disputes shall be finally settled by an arbitral tribunal seated in Geneva.")).toBe(true);
    expect(fires("The dispute shall be referred to three arbitrators under the ICC Rules.")).toBe(true);
    expect(fires("The parties agree to arbitrate any dispute.")).toBe(true);
  });

  it("does not fire on the unrelated word 'arbitrary'", () => {
    expect(fires("The decision shall not be arbitrary or capricious.")).toBe(false);
  });

  it("does not fire on a court-litigation clause", () => {
    expect(fires("Disputes shall be resolved in the courts of Delaware.")).toBe(false);
  });
});
