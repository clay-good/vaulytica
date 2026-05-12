import { describe, expect, it } from "vitest";
import { rule as CHOICE_011 } from "./CHOICE-011.js";
import { buildContext } from "../../_test-fixtures.js";

describe("CHOICE-011 — out-of-state choice-of-law on California worker", () => {
  it("fires when employee is California-based but governing law is Delaware", () => {
    const ctx = buildContext([
      "Parties",
      "Employee is a California resident who works from San Francisco, California.",
      "This Agreement shall be governed by and construed in accordance with the laws of the State of Delaware.",
    ]);
    const f = CHOICE_011.check(ctx);
    expect(f?.severity).toBe("warning");
    expect(f?.title).toMatch(/california/i);
  });

  it("is silent when governing law is California", () => {
    const ctx = buildContext([
      "Parties",
      "Employee is a California resident who works from Los Angeles, California.",
      "This Agreement shall be governed by the laws of the State of California.",
    ]);
    expect(CHOICE_011.check(ctx)).toBeNull();
  });

  it("is silent when no California-worker signal exists", () => {
    const ctx = buildContext([
      "Parties",
      "Employee is a New York resident based in Manhattan.",
      "This Agreement shall be governed by the laws of the State of Delaware.",
    ]);
    expect(CHOICE_011.check(ctx)).toBeNull();
  });
});
