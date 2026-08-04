import { describe, expect, it } from "vitest";
import { rule as OBLI_006 } from "./OBLI-006.js";
import { buildContext } from "../../_test-fixtures.js";

const doc = (heading: string, ...rest: string[]) => buildContext([heading, ...rest]);
const fires = (body: string) => OBLI_006.check(doc("Discretion", body)) !== null;

describe("OBLI-006 — sole-discretion language", () => {
  it("fires on the canonical 'in its sole discretion'", () => {
    expect(fires("The Company may terminate the Service in its sole discretion.")).toBe(true);
  });

  // v1.1.0 — the preposition is as often "at", an article can precede a named
  // party, and the qualifier is written absolute / unfettered / complete /
  // exclusive as well as sole.
  it("fires on the previously-missed common forms", () => {
    expect(fires("Vendor may suspend access at its sole discretion.")).toBe(true);
    expect(fires("Fees may be adjusted in the Company's sole discretion.")).toBe(true);
    expect(fires("The Board may act at its absolute discretion.")).toBe(true);
    expect(fires("Licensor may revoke the license in its unfettered discretion.")).toBe(true);
    expect(fires("Approval rests within Provider's sole and absolute discretion.")).toBe(true);
  });

  it("is silent on 'reasonable discretion' and a bare 'in its discretion'", () => {
    expect(fires("The Company shall act in its reasonable discretion.")).toBe(false);
    expect(fires("Payment timing is left to its discretion under the schedule.")).toBe(false);
  });
});
