/**
 * RISK-013 detects a force-majeure clause. v1.1.0 recognizes clauses drafted
 * without the Latin term — around the idiom "causes beyond [a party's]
 * reasonable control" / "beyond the control of the parties" — plus the plural
 * "acts of God".
 */
import { describe, expect, it } from "vitest";
import { rule as RISK_013 } from "./RISK-013.js";
import { buildContext } from "../../_test-fixtures.js";

const fires = (s: string) => RISK_013.check(buildContext(["Force Majeure", s])) !== null;

describe("RISK-013 — force majeure clause present", () => {
  it("fires on the literal 'force majeure' term", () => {
    expect(fires("Neither party shall be liable for delays caused by an event of force majeure.")).toBe(
      true,
    );
  });

  it("reads the descriptive 'beyond … reasonable control' form (v1.1.0)", () => {
    expect(
      fires(
        "Neither party shall be liable for any failure or delay in performance due to causes beyond its reasonable control.",
      ),
    ).toBe(true);
    expect(
      fires("A party shall be excused where performance is prevented by causes beyond their reasonable control."),
    ).toBe(true);
    expect(
      fires("Each party is excused from performance for events beyond the reasonable control of the parties."),
    ).toBe(true);
    expect(fires("Delays arising from causes beyond the control of either party shall excuse performance.")).toBe(
      true,
    );
  });

  it("reads the plural 'acts of God' (v1.1.0)", () => {
    expect(fires("Performance is excused for acts of God, war, and pandemic.")).toBe(true);
  });

  it("does not fire on unrelated 'control' language", () => {
    expect(
      fires("The Company shall retain control of the board and reasonable oversight of operations."),
    ).toBe(false);
  });

  it("is silent when a force-majeure clause is disclaimed", () => {
    expect(fires("This Agreement contains no force majeure clause.")).toBe(false);
  });
});
