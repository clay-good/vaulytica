import { describe, expect, it } from "vitest";
import { rule as TERM_006 } from "./TERM-006.js";
import { buildContext } from "../../_test-fixtures.js";

const fires = (body: string) => TERM_006.check(buildContext(["Transition", body])) !== null;

describe("TERM-006 — wind-down / transition services", () => {
  it("fires on the existing wind-down / transition-services terms", () => {
    expect(fires("The Vendor shall provide wind-down services for 90 days.")).toBe(true);
    expect(fires("Transition services shall be provided at the then-current rates.")).toBe(true);
  });

  // v1.1.0 — outsourcing / MSA drafting names the same obligation "termination
  // assistance", "transition assistance / plan", "disentanglement".
  it("fires on the outsourcing synonyms", () => {
    expect(fires("Vendor shall provide termination assistance for up to 12 months.")).toBe(true);
    expect(fires("The parties shall cooperate on transition assistance upon expiry.")).toBe(true);
    expect(fires("A detailed transition plan shall be delivered before expiration.")).toBe(true);
    expect(fires("The Disentanglement services are described in Schedule 5.")).toBe(true);
  });

  it("does not fire on a generic 'transition' or corporate 'winding up'", () => {
    expect(fires("The transition to the new fiscal year affects billing.")).toBe(false);
    expect(fires("Upon winding up of the company, assets are distributed to members.")).toBe(false);
  });
});
