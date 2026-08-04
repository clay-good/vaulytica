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
