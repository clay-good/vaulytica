/**
 * RISK-007 surfaces a waiver of consequential / special / incidental / punitive
 * damages. v1.1.0 fixes an inverse-FP: the "liable for" branch required no
 * negation, so an AFFIRMATIVE liability clause ("each party remains liable for
 * consequential damages") — the opposite of a waiver — was flagged.
 */
import { describe, expect, it } from "vitest";
import { rule as RISK_007 } from "./RISK-007.js";
import { buildContext } from "../../_test-fixtures.js";

const fires = (body: string) =>
  RISK_007.check(buildContext(["Limitation of Liability", body])) !== null;

describe("RISK-007 — consequential damages waiver present", () => {
  it("fires on genuine waiver phrasings", () => {
    expect(fires("Vendor shall not be liable for consequential damages.")).toBe(true);
    expect(fires("Vendor is not liable for any consequential damages.")).toBe(true);
    expect(fires("In no event shall either party be liable for no consequential damages.")).toBe(
      true,
    );
    expect(
      fires("Neither party is liable for special, incidental, consequential, or punitive damages."),
    ).toBe(true);
    expect(fires("Each party waives any consequential damages.")).toBe(true);
  });

  it("does not fire on an AFFIRMATIVE liability clause (inverse-FP guard, v1.1.0)", () => {
    expect(fires("Each party remains liable for consequential damages.")).toBe(false);
    expect(fires("The breaching party is liable for consequential damages.")).toBe(false);
  });
});
