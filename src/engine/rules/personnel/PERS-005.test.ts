import { describe, expect, it } from "vitest";
import { rule as PERS_005 } from "./PERS-005.js";
import { buildContext } from "../../_test-fixtures.js";

describe("PERS-005 — non-compete clause present", () => {
  it("fires on `non-compete`", () => {
    const ctx = buildContext([
      "Restrictive Covenants",
      "Employee agrees to a non-compete obligation for twelve (12) months following termination.",
    ]);
    expect(PERS_005.check(ctx)?.severity).toBe("warning");
  });

  it("fires on `covenant not to compete`", () => {
    const ctx = buildContext([
      "Restrictions",
      "Employee enters into a covenant not to compete for two years post-employment within the State of New York.",
    ]);
    expect(PERS_005.check(ctx)).not.toBeNull();
  });

  it("fires on `shall not directly or indirectly compete`", () => {
    const ctx = buildContext([
      "Post-Employment",
      "Contractor shall not directly or indirectly compete with the Company for 12 months.",
    ]);
    expect(PERS_005.check(ctx)).not.toBeNull();
  });

  it("is silent on a standard non-solicitation (not a non-compete)", () => {
    const ctx = buildContext([
      "Non-Solicitation",
      "For twelve months following termination, Employee shall not solicit the Company's customers.",
    ]);
    expect(PERS_005.check(ctx)).toBeNull();
  });

  it("reads 'Non-Competition' and the will/agrees-not-to-compete verb forms (v1.1.0)", () => {
    for (const clause of [
      "Section 9. Non-Competition. The Executive agrees to the following restrictions.",
      "Executive will not compete with the Company during the term.",
      "Employee agrees not to compete with the Company for two years.",
    ]) {
      expect(
        PERS_005.check(buildContext(["Restrictive Covenants", clause])),
        clause,
      ).not.toBeNull();
    }
  });

  it("stays silent on a disclaimer of a non-competition covenant (v1.1.0)", () => {
    expect(
      PERS_005.check(
        buildContext([
          "Restrictive Covenants",
          "This Agreement contains no non-competition covenant of any kind.",
        ]),
      ),
    ).toBeNull();
  });
});

describe("PERS-005 — the incoming-obligations representation", () => {
  /**
   * Every offer letter and employment agreement asks the candidate to promise
   * they are NOT bound by someone else's covenant. It is the opposite of
   * imposing one, and it was reported at `warning` as a non-compete clause
   * present on a letter that contains none.
   */
  it("is silent on a representation that the candidate is not bound by one", () => {
    for (const clause of [
      "By accepting this offer you represent that you are not subject to any employment, confidentiality, non-competition, or other agreement that would prevent you from accepting this position.",
      "Employee represents that Employee is not a party to any non-compete or non-solicitation agreement with a former employer.",
      "The Consultant is not bound by any covenant not to compete that would restrict the Services.",
    ]) {
      expect(PERS_005.check(buildContext(["Representations", clause])), clause).toBeNull();
    }
  });

  it("still fires when a real covenant follows the representation (v1.2.0)", () => {
    // The disclaimer test used to run against the FIRST hit only, so a
    // document that opens with the representation would have been silenced no
    // matter what it imposed later. Every hit is scanned now.
    const f = PERS_005.check(
      buildContext([
        "Representations",
        "Employee represents that Employee is not subject to any non-competition agreement with a former employer.",
        "Restrictive Covenants",
        "For twelve months after termination, Employee shall not compete with the Company anywhere in North America.",
      ]),
    );
    expect(f).not.toBeNull();
    expect(f?.excerpt.text).toContain("shall not compete");
  });
});
