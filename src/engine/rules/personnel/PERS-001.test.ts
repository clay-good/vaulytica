import { describe, expect, it } from "vitest";
import { rule as PERS_001 } from "./PERS-001.js";
import { buildContext } from "../../_test-fixtures.js";

describe("PERS-001 — non-compete present (v1.1.0)", () => {
  const fires = (text: string) => PERS_001.check(buildContext(["Non-Competition", text])) !== null;

  it("fires on the bare 'shall not compete' form", () => {
    expect(
      fires(
        "During employment and for twelve (12) months thereafter, the Employee shall not compete with the Company within the Territory.",
      ),
    ).toBe(true);
  });

  it("fires on 'shall not, directly or indirectly, compete'", () => {
    expect(fires("The Employee shall not, directly or indirectly, compete with the Company.")).toBe(
      true,
    );
  });

  it("fires on the 'non-competition' noun (not only 'non-compete')", () => {
    expect(fires("The Employee agrees to a non-competition covenant for one (1) year.")).toBe(true);
  });

  it("fires on 'engage in a business that competes'", () => {
    expect(
      fires("The Employee shall not engage in any business that competes with the Company."),
    ).toBe(true);
  });

  it("fires on 'will not compete' and the classic own/manage/operate form", () => {
    expect(fires("Executive will not compete with the Company for eighteen (18) months.")).toBe(
      true,
    );
    expect(fires("The Employee shall not own, manage, or operate a competing enterprise.")).toBe(
      true,
    );
  });

  it("stays silent on a non-solicit, confidentiality, or 'non-competitive' pricing", () => {
    expect(fires("The Employee shall not solicit the Company's customers or employees.")).toBe(
      false,
    );
    expect(fires("Each party shall keep the other's Confidential Information confidential.")).toBe(
      false,
    );
    expect(
      fires("The bids were submitted through a non-competitive process at non-competitive prices."),
    ).toBe(false);
  });

  it("stays silent on a disclaimer that it is NOT a non-compete", () => {
    expect(
      fires("This clause is not a non-compete and imposes no restriction on the Employee."),
    ).toBe(false);
  });
});

describe("PERS-001 — the scope it exists to surface (v1.3.0)", () => {
  // PERS-005 reports that a non-compete is present, at `warning`, with the
  // jurisdiction analysis. Both rules were emitting the same title over the
  // same span on three specimens: one drafting fact, reported twice in the
  // same words. What this rule adds is the SCOPE.
  const titleOf = (clause: string) =>
    PERS_001.check(buildContext(["Restrictive Covenants", clause]))?.title;

  it("names the duration and the radius", () => {
    expect(
      titleOf(
        "9.1 Non-Competition. For twelve (12) months after termination, the Physician shall not provide gastroenterology services at any facility located within fifteen (15) miles of the Group's principal office.",
      ),
    ).toContain("Non-compete scope: For twelve (12) months, within fifteen (15) miles");
  });

  it("names a state where the covenant states one", () => {
    expect(
      titleOf(
        "For two (2) years after the Closing, Seller shall not compete with the Business in the State of Georgia.",
      ),
    ).toContain("Non-compete scope: For two (2) years, in the State of Georgia");
  });

  it("prompts rather than accuses when the scope is not in the clause", () => {
    // The trigger matches the section HEADING as readily as the covenant, and
    // the scope is then in the paragraph beneath it.
    expect(titleOf("14. Covenant Not to Compete.")).toBe(
      "Non-compete clause — check scope and enforceability",
    );
  });
});
