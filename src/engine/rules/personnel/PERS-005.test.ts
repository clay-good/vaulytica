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
});
