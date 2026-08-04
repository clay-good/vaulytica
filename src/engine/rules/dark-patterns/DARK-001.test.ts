import { describe, expect, it } from "vitest";
import { rule as DARK_001 } from "./DARK-001.js";
import { buildContext } from "../../_test-fixtures.js";

const doc = (...paras: string[]) => buildContext(["Modifications", ...paras]);

describe("DARK-001 — unilateral modification right", () => {
  it("fires on the enumerated party + modify form", () => {
    expect(DARK_001.check(doc("The Company may modify these Terms at any time."))).not.toBeNull();
  });

  it("reads the consumer 'we may update / revise' forms (v1.1.0)", () => {
    for (const clause of [
      "We may update these Terms at any time without notice.",
      "We reserve the right to modify the Terms in our sole discretion.",
      "The Company may revise these Terms from time to time.",
      "The Company reserves the right to update these Terms at any time.",
    ]) {
      expect(DARK_001.check(doc(clause)), clause).not.toBeNull();
    }
  });

  it("does not fire on a mutual amendment clause", () => {
    expect(
      DARK_001.check(
        doc("This Agreement may be amended only by a written instrument signed by both parties."),
      ),
    ).toBeNull();
    expect(
      DARK_001.check(doc("The parties may amend this Agreement by mutual written agreement.")),
    ).toBeNull();
  });

  it("is suppressed when the customer has a corresponding termination right", () => {
    expect(
      DARK_001.check(
        doc(
          "The Company may modify these Terms at any time; the Customer may terminate upon notice if it objects.",
        ),
      ),
    ).toBeNull();
  });
});
