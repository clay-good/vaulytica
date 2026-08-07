import { describe, expect, it } from "vitest";
import { rule as TERM_003 } from "./TERM-003.js";
import { buildContext } from "../../_test-fixtures.js";

describe("TERM-003 — one-sided termination for convenience", () => {
  const fires = (b: string) => !!TERM_003.check(buildContext(["Termination", b]) as never);

  it.each([
    "The Company may terminate this Agreement for convenience upon 30 days' notice.",
    "The Licensor may terminate this Agreement for convenience at any time.",
    "The Supplier may terminate for convenience upon written notice.",
  ])("fires on a one-sided convenience right regardless of party label: %s", (b) => {
    expect(fires(b)).toBe(true);
  });

  it.each([
    "Either party may terminate this Agreement for convenience upon 30 days' notice.",
    "The Company may terminate for convenience, and the Customer may likewise terminate for convenience.",
    "The Licensor may terminate for convenience, and the Licensee may also terminate for convenience.",
  ])("stays silent on a reciprocal convenience right: %s", (b) => {
    expect(fires(b)).toBe(false);
  });

  it("emits a warning-severity finding", () => {
    expect(
      TERM_003.check(
        buildContext([
          "Termination",
          "The Licensor may terminate for convenience at any time.",
        ]) as never,
      )?.severity,
    ).toBe("warning");
  });
});
