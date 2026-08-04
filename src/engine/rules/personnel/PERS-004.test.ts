import { describe, expect, it } from "vitest";
import { rule as PERS_004 } from "./PERS-004.js";
import { buildContext } from "../../_test-fixtures.js";

const fires = (body: string) => PERS_004.check(buildContext(["No-Hire", body])) !== null;

describe("PERS-004 — anti-poaching / no-hire", () => {
  it("fires on the explicit 'will not hire the other party's employees'", () => {
    expect(fires("Employer will not hire the other party's employees during the term.")).toBe(true);
  });

  // v1.1.0 — the rule is literally about anti-poaching but missed the DOJ's own
  // term "no-poach", and missed the dominant "Neither party will hire ..." form
  // whose negation is carried by "neither", not "not".
  it("fires on 'no-poach' / 'no-poaching' (the DOJ term)", () => {
    expect(fires("The parties agree to a no-poach arrangement covering their employees.")).toBe(
      true,
    );
    expect(fires("This is a no-poaching agreement between the parties as to employees.")).toBe(
      true,
    );
  });

  it("fires on the 'Neither party will hire/solicit the other party' form", () => {
    expect(fires("Neither party will hire the other party's employees during the term.")).toBe(
      true,
    );
    expect(fires("Neither party will solicit or hire the other party's employees.")).toBe(true);
  });

  it("fires on a party-to-party non-solicit but NOT a one-way employee non-solicit", () => {
    // "solicit" is anti-poaching only when it runs between the parties.
    expect(
      fires("Neither Party shall solicit for employment any employee of the other Party."),
    ).toBe(true);
    // An ordinary employment restrictive covenant (Executive vs Employer) is not
    // an antitrust-sensitive no-poach and must not fire this rule.
    expect(fires("Executive shall not solicit Employer's customers or employees.")).toBe(false);
  });

  it("does not misread an internal hiring-governance clause as anti-poaching", () => {
    // "Neither party will hire employees" without an "other party" object is an
    // internal governance term, not a mutual no-hire between competitors.
    expect(fires("Neither party will hire employees without prior board approval.")).toBe(false);
    expect(fires("The Company will hire qualified staff for the project as needed.")).toBe(false);
  });
});
