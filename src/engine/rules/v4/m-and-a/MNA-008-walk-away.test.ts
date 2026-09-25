import { describe, expect, it } from "vitest";
import { V4_RULES } from "../index.js";
import { buildContext } from "../../../_test-fixtures.js";
import type { Rule } from "../../../finding.js";

const MNA008 = V4_RULES.find((r) => r.id === "MNA-008") as Rule;

// MNA-008 guards against a binding LOI term running indefinitely. A right to
// walk away, or an exclusivity period that is itself bounded, answers that as
// fully as a drop-dead date.
describe("MNA-008 — an LOI that cannot run forever", () => {
  it("accepts a right to end negotiations", () => {
    expect(
      MNA008.check(
        buildContext(["Non-Binding Effect", "Either party may end negotiations at any time."]),
      ),
    ).toBeNull();
  });

  it("accepts a bounded exclusivity period", () => {
    expect(
      MNA008.check(
        buildContext([
          "Exclusivity",
          "For sixty (60) days after the date of this letter, the Company and the Sellers shall not solicit or negotiate any proposal from any other person.",
        ]),
      ),
    ).toBeNull();
  });

  it("still fires on open-ended exclusivity", () => {
    expect(
      MNA008.check(
        buildContext([
          "Exclusivity",
          "The Company shall not solicit or negotiate any proposal from any other person.",
        ]),
      ),
    ).not.toBeNull();
  });
});
