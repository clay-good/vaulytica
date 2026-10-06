import { describe, expect, it } from "vitest";
import { orderRounds } from "./round-order.js";

const names = (ns: string[]) => orderRounds(ns, (n) => n);

describe("orderRounds — round order read from file names", () => {
  it("compares the numbers as numbers: round2 before round10", () => {
    expect(names(["round10.json", "round2.json", "round1.json"])).toEqual({
      ok: true,
      items: ["round1.json", "round2.json", "round10.json"],
    });
  });

  it("refuses a name with no number, naming it", () => {
    const r = names(["round1.json", "final.json"]);
    expect(r.ok).toBe(false);
    expect(!r.ok && r.reason).toMatch(/final\.json carries no round number/);
  });

  it("refuses two names with the same number, leading zeros aside", () => {
    const r = names(["round-1.json", "round-01.json"]);
    expect(!r.ok && r.reason).toMatch(
      /round-1\.json and round-01\.json carry the same round number/,
    );
  });
});
