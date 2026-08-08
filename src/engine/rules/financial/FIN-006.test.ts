import { describe, expect, it } from "vitest";
import { rule as FIN_006 } from "./FIN-006.js";
import { buildContext } from "../../_test-fixtures.js";

const fires = (t: string) => FIN_006.check(buildContext(["Damages", t])) !== null;

describe("FIN-006 — liquidated damages recognizes the 'liquidated and ascertained damages' (LADs) form (v1.1.0)", () => {
  it.each([
    "The Contractor shall pay liquidated damages of $1,000 per day.",
    "The Contractor shall pay liquidated and ascertained damages of £500 per week of delay.",
    "Delay damages shall be payable as liquidated and ascertained damages (LADs).",
  ])("fires on a liquidated-damages clause: %s", (t) => {
    expect(fires(t)).toBe(true);
  });

  it.each([
    "This clause does not provide for liquidated damages.",
    "No liquidated damages shall be payable under this Agreement.",
    "The parties agree to actual damages only.",
  ])("stays silent on a disclaimed / absent clause: %s", (t) => {
    expect(fires(t)).toBe(false);
  });
});
