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

// GOV-068 (DRULPA § 17-108, indemnification of the GENERAL partner) has the same
// premise: a general partner distinct from limited partners exists only in a
// limited partnership.
describe("GOV-068 limited-partnership scope", () => {
  const GOV068 = V4_RULES.find((r) => r.id === "GOV-068") as Rule;

  it("does not fire on a general partnership", () => {
    expect(
      GOV068.check(
        buildContext([
          "Partnership",
          "The Partners form a general partnership under the North Carolina Uniform Partnership Act. Each Partner has equal rights in management.",
        ]),
      ),
    ).toBeNull();
  });

  it("still fires on a limited partnership with no indemnification of its general partner", () => {
    expect(
      GOV068.check(
        buildContext([
          "Partnership",
          "This limited partnership has one general partner and several limited partners who contribute capital under the agreement.",
        ]),
      ),
    ).not.toBeNull();
  });
});

describe("GOV-069 severity", () => {
  it("is a warning: the designation is made on each year's return", () => {
    const GOV069 = V4_RULES.find((r) => r.id === "GOV-069") as Rule;
    expect(GOV069.default_severity).toBe("warning");
  });
});

describe("GOV-044 — the statutory citation is the recital", () => {
  const GOV044 = V4_RULES.find((r) => r.id === "GOV-044") as Rule;

  it("reads 'pursuant to Section 141(f) of the Delaware General Corporation Law'", () => {
    expect(
      GOV044.check(
        buildContext([
          "Consent",
          "The undersigned directors, acting pursuant to Section 141(f) of the Delaware General Corporation Law, adopt the following resolutions by unanimous written consent.",
        ]),
      ),
    ).toBeNull();
  });

  it("is not satisfied by a bylaw section that happens to be numbered 228", () => {
    expect(
      GOV044.check(
        buildContext([
          "Consent",
          "The undersigned directors, acting under Section 228 of the Bylaws, adopt the following resolutions.",
        ]),
      ),
    ).not.toBeNull();
  });
});

describe("GOV-043 — a title split between a paragraph and a heading", () => {
  it("reads the consenting body across the two (document order)", () => {
    const GOV043 = V4_RULES.find((r) => r.id === "GOV-043") as Rule;
    const ctx = buildContext(
      ["", "ACTION BY UNANIMOUS WRITTEN CONSENT"],
      [
        "OF THE BOARD OF DIRECTORS OF HALCYON INSTRUMENTS, INC.",
        "The undersigned adopt the following resolutions.",
      ],
    );
    expect(GOV043.check(ctx)).toBeNull();
  });
});
