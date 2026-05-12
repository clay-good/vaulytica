import { describe, expect, it } from "vitest";
import { rule as CHOICE_009 } from "./CHOICE-009.js";
import { buildContext } from "../../_test-fixtures.js";

describe("CHOICE-009 — governing law differs from venue", () => {
  it("fires when Delaware law + California venue", () => {
    const ctx = buildContext([
      "Governing Law",
      "This Agreement shall be governed by the laws of the State of Delaware.",
      "Exclusive venue shall be in the state and federal courts located in San Francisco, California.",
    ]);
    const f = CHOICE_009.check(ctx);
    expect(f?.severity).toBe("info");
    expect(f?.title).toMatch(/differs/i);
  });

  it("is silent when both clauses pick Delaware", () => {
    const ctx = buildContext([
      "Governing Law",
      "This Agreement shall be governed by the laws of the State of Delaware.",
      "Exclusive venue shall be in the federal courts located in Delaware.",
    ]);
    expect(CHOICE_009.check(ctx)).toBeNull();
  });

  it("is silent when only governing law is specified", () => {
    const ctx = buildContext([
      "Governing Law",
      "This Agreement shall be governed by the laws of the State of New York.",
    ]);
    expect(CHOICE_009.check(ctx)).toBeNull();
  });

  it("is silent when only venue is specified", () => {
    const ctx = buildContext([
      "Disputes",
      "Exclusive venue shall be in the federal courts located in New York.",
    ]);
    expect(CHOICE_009.check(ctx)).toBeNull();
  });
});
