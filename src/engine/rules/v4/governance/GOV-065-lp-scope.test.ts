import { describe, expect, it } from "vitest";
import { V4_RULES } from "../index.js";
import { buildContext } from "../../../_test-fixtures.js";
import type { Rule } from "../../../finding.js";

const GOV065 = V4_RULES.find((r) => r.id === "GOV-065") as Rule;

// Guard: GOV-065 (DRULPA § 17-303, LP limited-liability acknowledgment) concerns
// LIMITED partners. A general partnership has none, so it must not be told the
// acknowledgment is "missing"; a limited partnership that lacks it still is.
describe("GOV-065 limited-partnership scope", () => {
  it("does not fire on a general partnership (no limited partners)", () => {
    expect(
      GOV065.check(
        buildContext([
          "Partnership",
          "This general partnership is formed under the Uniform Partnership Act. Each Partner shares in profits and losses and participates in management.",
        ]),
      ),
    ).toBeNull();
  });

  it("still fires on a limited partnership lacking the acknowledgment", () => {
    expect(
      GOV065.check(
        buildContext([
          "Partnership",
          "This limited partnership has one general partner and several limited partners who contribute capital under the agreement.",
        ]),
      ),
    ).not.toBeNull();
  });

  it("does not fire on a limited partnership that includes the acknowledgment", () => {
    expect(
      GOV065.check(
        buildContext([
          "Liability",
          "No Limited Partner shall be liable for the obligations of the Partnership beyond the amount of its capital contribution.",
        ]),
      ),
    ).toBeNull();
  });
});
