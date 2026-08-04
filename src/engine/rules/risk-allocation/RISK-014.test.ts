import { describe, expect, it } from "vitest";
import { rule as RISK_014 } from "./RISK-014.js";
import { buildContext } from "../../_test-fixtures.js";

const fires = (body: string) => RISK_014.check(buildContext(["Confidentiality", body])) !== null;

describe("RISK-014 — confidentiality term length", () => {
  it("fires on the survive/continue forms", () => {
    expect(fires("The confidentiality obligations shall survive for five (5) years.")).toBe(true);
    expect(fires("Confidentiality shall continue for 5 years after termination.")).toBe(true);
  });

  // v1.1.0 — the dominant phrasing is "Confidential Information shall remain
  // confidential for N years" / "shall be kept confidential for N years", which
  // the survive/continue/remain-in-effect-only list (anchored on the noun
  // "confidentiality") missed.
  it("fires on 'remain confidential' / 'kept confidential for N years'", () => {
    expect(
      fires(
        "Confidential Information shall remain confidential for five (5) years after termination.",
      ),
    ).toBe(true);
    expect(
      fires("All Confidential Information shall be kept confidential for a period of 3 years."),
    ).toBe(true);
  });

  it("does not fire on an incidental 'confidential ... N year' mention with no duration term", () => {
    expect(fires("Confidential Information disclosed during the 2 year term is protected.")).toBe(
      false,
    );
  });
});
