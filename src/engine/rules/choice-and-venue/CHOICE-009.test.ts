import { describe, expect, it } from "vitest";
import { rule as CHOICE_009 } from "./CHOICE-009.js";
import { buildContext } from "../../_test-fixtures.js";

describe("CHOICE-009 — governing law differs from venue", () => {
  // 9.757.0: CHOICE-004 owns a plain law/venue split; this rule defers to it.
  it("defers to CHOICE-004 on Delaware law + California venue", async () => {
    const { rule: CHOICE_004 } = await import("./CHOICE-004.js");
    const ctx = buildContext([
      "Governing Law",
      "This Agreement shall be governed by the laws of the State of Delaware.",
      "Exclusive venue shall be in the state and federal courts located in San Francisco, California.",
    ]);
    expect(CHOICE_004.check(ctx)?.title).toMatch(/differ/i);
    expect(CHOICE_009.check(ctx)).toBeNull();
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
