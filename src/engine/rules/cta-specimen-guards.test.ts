/**
 * Two defects a hand-written clinical trial agreement found.
 *
 * FIN-005's active-voice branch — "shall pay … within N days" — allowed the
 * run-up to the deadline to contain letters, digits, commas, parentheses,
 * currency and quote marks, but not a HYPHEN. Hyphenated words are everywhere
 * in that run-up: "Sponsor shall pay Institution in accordance with the budget
 * attached as Exhibit A, on a PER-SUBJECT basis upon completion and monitoring
 * of each visit, within forty-five (45) days after receipt of a proper
 * invoice" is a plainly stated payment term, and one hyphen stopped the branch
 * from reaching it.
 *
 * `expandSurvivalSectionRefs` took only the FIRST section list in the survival
 * text. A survival clause is frequently spread over more than one paragraph,
 * and the earlier one here carried an unrelated cross-reference — "Nothing in
 * this Section limits the publication rights in Section 11" — which became the
 * whole incorporated list. The operative enumeration ("Sections 5, 6, 9, 10,
 * 11, 12 … survive") was never read, so TEMP-012 reported the indemnity as
 * unnamed in a clause that names it by number.
 */
import { describe, expect, it } from "vitest";
import { buildContext } from "../_test-fixtures.js";
import { rule as FIN_005 } from "./financial/FIN-005.js";
import { rule as TEMP_012 } from "./temporal/TEMP-012.js";

describe("FIN-005 — a hyphen in the run-up to the deadline", () => {
  it("reads a payment term stated after a hyphenated qualifier", () => {
    expect(
      FIN_005.check(
        buildContext([
          "Budget and Payments",
          "Sponsor shall pay Institution in accordance with the budget attached as Exhibit A, on a per-subject basis upon completion and monitoring of each visit, within forty-five (45) days after receipt of a proper invoice.",
        ]),
      ),
    ).toBeNull();
  });

  it("still reports an agreement that names a payment and no term", () => {
    // The gate is the SINGULAR "fee" / "payment" (a deliberate conservatism:
    // the plural "reasonable attorneys' fees" in an indemnity clause is not a
    // commercial payment obligation), so the decoy has to trip it.
    expect(
      FIN_005.check(
        buildContext([
          "Budget and Payments",
          "Sponsor shall pay Institution the per-subject fee set out in the budget attached as Exhibit A. Payment is made after monitoring.",
        ]),
      ),
    ).not.toBeNull();
  });
});

describe("TEMP-012 — a survival clause spread over two paragraphs", () => {
  const AGREEMENT: [string, ...string[]] = [
    "Clinical Trial Agreement",
    "6. Indemnification.",
    "Sponsor shall indemnify, defend, and hold harmless Institution against any third-party claim arising out of the administration of the investigational product.",
    "9. Confidentiality.",
    "Institution shall hold Sponsor's Confidential Information in confidence. This Section survives for seven years after the end of the Study. Nothing in this Section limits the publication rights in Section 11.",
    "11. Publication.",
    "Institution may publish the results of the Study.",
  ];

  it("reads the operative enumeration past an earlier cross-reference", () => {
    expect(
      TEMP_012.check(
        buildContext([
          ...AGREEMENT,
          "14. Term and Termination.",
          "Sections 5, 6, 9, 10, 11, 12, and this Section survive.",
        ]),
      ),
    ).toBeNull();
  });

  it("still reports an indemnity the survival clause leaves out", () => {
    const finding = TEMP_012.check(
      buildContext([
        ...AGREEMENT,
        "14. Term and Termination.",
        "Sections 9 and 11, and this Section, survive.",
      ]),
    );
    expect(finding).not.toBeNull();
    expect(finding!.description).toContain("indemnification");
  });
});
