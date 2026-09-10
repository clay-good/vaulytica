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

  // The mutual escape's window may not cross a sentence. A termination article
  // that opens with a for-cause right for EITHER party and then hands ONE party
  // a convenience right is the commonest layout there is, and both sentences fit
  // inside 160 characters.
  it("still fires when the sentence before it grants a mutual FOR-CAUSE right", () => {
    expect(
      fires(
        "9.2 Either party may terminate for material breach on ten (10) days' written notice " +
          "if the breach is not cured within that period. Client may terminate for convenience " +
          "on written notice, in which case Client shall pay for work performed to the date of " +
          "termination.",
      ),
    ).toBe(true);
  });

  // The same clause with the period spelled in digits alone is seven characters
  // shorter — which is all it took to slip inside the old window, so one
  // document was read two ways depending on how it typed a number.
  it("reads the same clause the same way whichever way the period is spelled", () => {
    expect(
      fires(
        "Either party may terminate this Agreement if the other materially breaches it and " +
          "fails to cure within 30 days after written notice describing the breach. Licensee " +
          "may terminate support for convenience at the end of any support year.",
      ),
    ).toBe(true);
  });

  // A decimal point inside a section number is not a sentence boundary.
  it("still clears a reciprocal right stated across a cross-reference", () => {
    expect(
      fires(
        "Either party may terminate this Agreement for convenience under Section 5.5 on " +
          "sixty (60) days' written notice.",
      ),
    ).toBe(false);
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
