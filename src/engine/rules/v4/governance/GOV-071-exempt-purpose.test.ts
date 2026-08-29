import { describe, expect, it } from "vitest";
import { V4_RULES } from "../index.js";
import { buildContext } from "../../../_test-fixtures.js";
import type { Rule } from "../../../finding.js";

const GOV071 = V4_RULES.find((r) => r.id === "GOV-071") as Rule;

/**
 * Three spellings of ONE fact, conjoined: the recital says the corporation is
 * organized for exempt purposes under § 501(c)(3), and a drafter writes it one
 * way, not three. The rule's own recommendation failed its own conjunction,
 * and a set of nonprofit bylaws whose Section 1.2 carries the textbook recital
 * was told at `critical` that it had none.
 *
 * The bare citation cannot be one of the alternatives: this family's own title
 * is "Nonprofit Bylaws (501(c)(3))", so a pattern matching it alone could
 * never fail. It counts when it is CITED.
 */
describe("GOV-071 — the exempt-purpose recital as drafters write it", () => {
  for (const recital of [
    "The corporation is organized exclusively for charitable and educational purposes within the meaning of Section 501(c)(3) of the Internal Revenue Code of 1986, as amended.",
    "The corporation is organized and operated exclusively for religious and charitable purposes.",
    "The corporation shall be operated exclusively for tax-exempt purposes as defined by the Code.",
  ]) {
    it(`recognizes: ${recital.slice(0, 46)}`, () => {
      expect(GOV071.check(buildContext(["Article I — Purposes", recital]))).toBeNull();
    });
  }

  it("still fires on bylaws that state no purpose at all", () => {
    expect(
      GOV071.check(
        buildContext([
          "Article I — Offices",
          "The principal office of the corporation is located in New Hanover County, North Carolina.",
        ]),
      ),
    ).not.toBeNull();
  });

  it("is not satisfied by the family's own title", () => {
    expect(
      GOV071.check(buildContext(["Nonprofit Bylaws (501(c)(3))", "Adopted on January 24, 2026."])),
    ).not.toBeNull();
  });
});
