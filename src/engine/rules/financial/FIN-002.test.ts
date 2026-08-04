import { describe, expect, it } from "vitest";
import { rule as FIN_002 } from "./FIN-002.js";
import { buildContext } from "../../_test-fixtures.js";

describe("FIN-002 — inconsistent named amounts (v1.1.0)", () => {
  const fires = (text: string) => FIN_002.check(buildContext(["Amounts", text]));

  it("flags a named amount stated at a sentence start with a conflicting value", () => {
    // "The Cap" opens a sentence — the lowercase-only "the" match previously
    // skipped it, so the conflict with the later "the Cap of $250,000" was lost.
    const f = fires(
      "The Cap of $100,000 applies to direct damages. Note that the Cap of $250,000 applies elsewhere.",
    );
    expect(f).not.toBeNull();
    expect(f?.title).toMatch(/Cap/);
  });

  it("still flags the fully mid-sentence lowercase form", () => {
    const f = fires(
      "Escrow: the Holdback of $50,000 is released at closing, and the Holdback of $75,000 is released later.",
    );
    expect(f).not.toBeNull();
  });

  it("stays silent when the named amount is consistent", () => {
    expect(
      fires("The Cap of $100,000 applies here, and the Cap of $100,000 applies there."),
    ).toBeNull();
  });

  it("stays silent on an intentional escalation schedule", () => {
    expect(
      fires("The Rent of $10,000 applies in Year 1, and the Rent of $12,000 applies in Year 2."),
    ).toBeNull();
  });

  it("does not treat a lowercase 'the purchase price' as a defined amount", () => {
    // The name capture stays upper-anchored — ordinary prose is not a named
    // amount, so a lowercase-name reference does not group with a defined one.
    expect(
      fires("the purchase price of $100,000 was agreed, and the purchase price of $200,000 later."),
    ).toBeNull();
  });
});
