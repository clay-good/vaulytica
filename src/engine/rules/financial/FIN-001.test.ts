import { describe, expect, it } from "vitest";
import { buildContext } from "../../_test-fixtures.js";
import { rule as FIN_001 } from "./FIN-001.js";

describe("FIN-001 — word/numeral mismatch, stated as a reader writes an amount", () => {
  it("groups the digits of both amounts", () => {
    const f = FIN_001.check(
      buildContext(["Fees", "Customer shall pay fifty thousand dollars ($75,000) on signing."]),
    );
    expect(f?.description).toBe("Spelled-out amount 50,000 does not match numeral 75,000.");
  });

  it("shows a fraction as cents", () => {
    const f = FIN_001.check(
      buildContext([
        "Fees",
        "Customer shall pay one thousand two hundred dollars ($1,250.50) monthly.",
      ]),
    );
    expect(f?.description).toBe("Spelled-out amount 1,200 does not match numeral 1,250.50.");
  });
});
