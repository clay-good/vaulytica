import { describe, expect, it } from "vitest";
import { V4_RULES } from "../index.js";
import { buildContext } from "../../../_test-fixtures.js";
import type { Rule } from "../../../finding.js";

const GOV020 = V4_RULES.find((r) => r.id === "GOV-020") as Rule;

// GOV-020 asks whether the operating agreement treats fiduciary duties. Naming
// the duties — loyalty and care — preserves them in terms, and never needs the
// word "fiduciary".
describe("GOV-020 fiduciary duties named by their content", () => {
  it("accepts 'the duties of loyalty and care'", () => {
    expect(
      GOV020.check(
        buildContext([
          "Duties",
          "Each Manager owes the Company and the Members the duties of loyalty and care that a manager of a Delaware limited liability company owes under the Act, and shall discharge those duties in good faith.",
        ]),
      ),
    ).toBeNull();
  });

  it("still fires when no duty is treated at all", () => {
    expect(
      GOV020.check(
        buildContext([
          "Management",
          "The Company shall be managed by a board of two Managers, who may appoint officers.",
        ]),
      ),
    ).not.toBeNull();
  });
});
