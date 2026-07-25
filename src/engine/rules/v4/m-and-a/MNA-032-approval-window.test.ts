import { describe, expect, it } from "vitest";
import { V4_RULES } from "../index.js";
import { buildContext } from "../../../_test-fixtures.js";
import type { Rule } from "../../../finding.js";

const MNA032 = V4_RULES.find((r) => r.id === "MNA-032") as Rule;

// Guard: MNA-032 warns when a merger agreement omits a stockholder-approval
// mechanism. The approval verb and the "stockholders" noun are often separated
// by the object and the entity — "approval of this Agreement by the Company's
// stockholders" — which the rule must recognize, while a merger that says
// nothing about stockholder approval still warns.
describe("MNA-032 stockholder-approval window", () => {
  for (const clause of [
    "The Merger is subject to approval of this Agreement by the Company's stockholders.",
    "Closing is conditioned on adoption of this Agreement by the holders of a majority of the outstanding stock.",
    "The parties shall seek the required vote of the Company's stockholders.",
  ]) {
    it(`recognizes: ${clause.slice(0, 46)}`, () => {
      expect(MNA032.check(buildContext(["Conditions", clause]))).toBeNull();
    });
  }

  it("still warns when no stockholder-approval mechanism is stated", () => {
    expect(
      MNA032.check(
        buildContext(["Conditions", "The Merger is subject to the expiration of the HSR waiting period and the absence of any legal prohibition."]),
      ),
    ).not.toBeNull();
  });
});
