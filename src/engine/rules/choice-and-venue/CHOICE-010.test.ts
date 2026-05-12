import { describe, expect, it } from "vitest";
import { rule as CHOICE_010 } from "./CHOICE-010.js";
import { buildContext } from "../../_test-fixtures.js";

describe("CHOICE-010 — asymmetric jury-trial waiver", () => {
  it("fires when only Customer waives jury trial", () => {
    const ctx = buildContext([
      "Disputes",
      "Customer hereby waives any right to trial by jury in any action arising from this Agreement.",
    ]);
    const f = CHOICE_010.check(ctx);
    expect(f?.severity).toBe("warning");
    expect(f?.title).toMatch(/asymmetric jury/i);
  });

  it("fires when only Employee waives jury trial", () => {
    const ctx = buildContext([
      "Arbitration",
      "Employee waives all rights to a jury trial in any employment-related dispute.",
    ]);
    expect(CHOICE_010.check(ctx)).not.toBeNull();
  });

  it("is silent when each party waives bilaterally", () => {
    const ctx = buildContext([
      "Disputes",
      "Each party hereby waives any right to trial by jury in any action under this Agreement.",
    ]);
    expect(CHOICE_010.check(ctx)).toBeNull();
  });

  it("is silent when `the parties waive`", () => {
    const ctx = buildContext([
      "Disputes",
      "The parties hereby waive any right to a jury trial in any litigation arising from this Agreement.",
    ]);
    expect(CHOICE_010.check(ctx)).toBeNull();
  });

  it("is silent when no jury-waiver language exists", () => {
    const ctx = buildContext([
      "Disputes",
      "Any dispute shall be finally settled by binding arbitration under the AAA Commercial Rules.",
    ]);
    expect(CHOICE_010.check(ctx)).toBeNull();
  });
});
