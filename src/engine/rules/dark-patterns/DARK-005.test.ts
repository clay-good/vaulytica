import { describe, expect, it } from "vitest";
import { rule as DARK_005 } from "./DARK-005.js";
import { buildContext } from "../../_test-fixtures.js";

describe("DARK-005 — class-action waiver", () => {
  it("fires on `waives class action`", () => {
    const ctx = buildContext([
      "Arbitration",
      `Customer waives any right to participate in a class action or class-wide arbitration against Vendor.`,
    ]);
    expect(DARK_005.check(ctx)?.severity).toBe("critical");
  });

  it("fires on `gives up the right to … collective action`", () => {
    const ctx = buildContext([
      "Disputes",
      `Employee gives up the right to bring or join a collective action or representative action.`,
    ]);
    expect(DARK_005.check(ctx)).not.toBeNull();
  });

  it("fires on `no class action`", () => {
    const ctx = buildContext([
      "H",
      "There shall be no class action or class-wide proceedings under this Agreement.",
    ]);
    expect(DARK_005.check(ctx)).not.toBeNull();
  });

  it("fires on `on an individual basis only`", () => {
    const ctx = buildContext([
      "Arbitration",
      `All disputes shall be resolved on an individual basis only and not as part of any class.`,
    ]);
    expect(DARK_005.check(ctx)).not.toBeNull();
  });

  it("silent on a clean arbitration clause", () => {
    const ctx = buildContext([
      "Arbitration",
      `Any dispute shall be finally settled by binding arbitration under the AAA Commercial Rules.`,
    ]);
    expect(DARK_005.check(ctx)).toBeNull();
  });

  it("silent on a clause that merely mentions class actions in passing", () => {
    const ctx = buildContext([
      "H",
      "Class actions have been recognized by US courts for over a century.",
    ]);
    expect(DARK_005.check(ctx)).toBeNull();
  });

  // Regression: a clause DISCLAIMING any waiver must not be flagged as a waiver.
  it("silent on `no class action waiver` (a disclaimer, the honest opposite)", () => {
    const ctx = buildContext([
      "Disputes",
      "There is no class action waiver in this Agreement. You retain the full right to participate in a class action against the Company at any time.",
    ]);
    expect(DARK_005.check(ctx)).toBeNull();
  });
});
