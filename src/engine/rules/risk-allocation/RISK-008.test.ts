import { describe, expect, it } from "vitest";
import { rule as RISK_008 } from "./RISK-008.js";
import { buildContext } from "../../_test-fixtures.js";

describe("RISK-008 — one-sided consequential-damages waiver", () => {
  const fires = (b: string) => !!RISK_008.check(buildContext(["Liability", b]) as never);

  it.each([
    "The Company shall not be liable for any consequential damages.",
    "The Supplier shall not be liable for any consequential or special damages.",
    "Licensor shall not be liable for any indirect, incidental, or consequential damages.",
  ])("fires on a one-sided waiver regardless of the protected party's label: %s", (b) => {
    expect(fires(b)).toBe(true);
  });

  it.each([
    "Neither party shall be liable for any consequential damages.",
    "The Company shall not be liable for consequential damages, and the Customer shall not be liable for consequential damages.",
    "The Seller shall not be liable for consequential damages, and the Buyer shall not be liable for consequential damages.",
  ])("stays silent on a mutual waiver: %s", (b) => {
    expect(fires(b)).toBe(false);
  });

  it("emits a warning-severity finding", () => {
    const f = RISK_008.check(
      buildContext([
        "Liability",
        "The Supplier shall not be liable for consequential damages.",
      ]) as never,
    );
    expect(f?.severity).toBe("warning");
  });
});
