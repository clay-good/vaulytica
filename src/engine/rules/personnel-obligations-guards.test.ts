/**
 * Guards against false-positive (cross-sentence / over-broad token) and
 * false-negative (missed inflection) findings in the personnel and obligations
 * launch rules. Each case reproduced a wrong finding or a wrong silence on
 * realistic drafting before the fix; both directions are pinned.
 */
import { describe, expect, it } from "vitest";
import { buildContext } from "../_test-fixtures.js";
import { rule as OBLI001 } from "./obligations/OBLI-001.js";
import { rule as PERS002 } from "./personnel/PERS-002.js";
import { rule as PERS004 } from "./personnel/PERS-004.js";
import { rule as PERS009 } from "./personnel/PERS-009.js";

const doc = (heading: string, ...rest: string[]) => buildContext([heading, ...rest]);

describe("OBLI-001 — ambiguous obligor", () => {
  it("does not flag 'the other party' — a precise counterparty reference", () => {
    expect(
      OBLI001.check(
        doc(
          "Notice",
          "The other party shall be notified in writing within five business days of any change of address.",
        ),
      ),
    ).toBeNull();
  });

  it("still flags a genuinely vague obligor", () => {
    expect(
      OBLI001.check(
        doc("Notice", "The appropriate party shall remediate the defect within ten days."),
      ),
    ).not.toBeNull();
  });
});

describe("PERS-002 / PERS-004 — personnel non-solicit / no-hire", () => {
  it("PERS-002 does not borrow 'employees' from an unrelated next sentence", () => {
    expect(
      PERS002.check(
        doc(
          "Marketing",
          "Vendor shall not solicit competing bids for the printing contract. Separately, all employees must complete annual ethics training.",
        ),
      ),
    ).toBeNull();
  });

  it("PERS-002 still fires on a real personnel non-solicit", () => {
    expect(
      PERS002.check(
        doc("Non-Solicit", "Vendor shall not solicit the employees of Customer for 12 months."),
      ),
    ).not.toBeNull();
  });

  it("PERS-004 does not borrow 'employees' across a sentence boundary", () => {
    expect(
      PERS004.check(
        doc(
          "Ops",
          "Contractor will not hire out the loading dock for external events. The other party retains audit rights over all employees.",
        ),
      ),
    ).toBeNull();
  });

  it("PERS-004 still fires on a real no-hire clause", () => {
    expect(
      PERS004.check(
        doc("No-Hire", "During the term, Customer will not hire the employees of Vendor."),
      ),
    ).not.toBeNull();
  });
});

describe("PERS-009 — non-solicit duration", () => {
  it("catches a hyphenated duration as well as the spaced form", () => {
    const hyphen = doc(
      "Restrictive Covenants",
      "Employee agrees not to solicit any customer of the Company for a 24-month period following termination.",
    );
    const spaced = doc(
      "Restrictive Covenants",
      "Employee agrees not to solicit any customer of the Company for a 24 month period following termination.",
    );
    expect(PERS009.check(hyphen)).not.toBeNull();
    expect(PERS009.check(spaced)).not.toBeNull();
  });
});
