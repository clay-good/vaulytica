/**
 * Guards against carve-out / negation blindness in the v4 governance language
 * rules (GOV-011, GOV-022, GOV-060, GOV-070).
 *
 * Each of these fired on text that states the COMPLIANT position — three of
 * them at `critical` severity:
 *
 *  - GOV-011 read across a sentence boundary, so a bylaw that expressly
 *    PRESERVES federal court for Exchange Act claims was reported as
 *    designating Delaware for them.
 *  - GOV-022 / GOV-070 knew the "does not waive" and "nothing … waives"
 *    negations but not "No provision of this Agreement waives …", the standard
 *    way a DE LLC / LP agreement preserves the implied covenant while lawfully
 *    modifying fiduciary duties.
 *  - GOV-060 flagged a charter that limited its non-independent-member
 *    override to the Rule 10A-3 phase-in exception — precisely the drafting
 *    the rule's own `recommendation` asks for.
 *
 * Both directions are pinned for each rule: the compliant form is silent, a
 * genuine violation still fires.
 */
import { describe, expect, it } from "vitest";
import { buildContext } from "../../_test-fixtures.js";
import { GOVERNANCE_RULES } from "./governance/index.js";

const rule = (id: string) => GOVERNANCE_RULES.find((r) => r.id === id)!;
const doc = (heading: string, ...rest: string[]) => buildContext([heading, ...rest]);

describe("GOV-011 — exclusive-forum bylaw preserving Exchange Act claims", () => {
  it("stays silent when the bylaw expressly preserves federal court for Exchange Act claims", () => {
    expect(
      rule("GOV-011").check(
        doc(
          "Exclusive Forum",
          "The exclusive forum for internal corporate claims shall be the Court of Chancery of the State of Delaware. Nothing herein restricts the rights of any person to bring a claim under the Securities Exchange Act of 1934 in federal court, which retains exclusive jurisdiction over such claims.",
        ),
      ),
    ).toBeNull();
  });

  it("still flags a bylaw that does designate Delaware for Exchange Act claims", () => {
    expect(
      rule("GOV-011").check(
        doc(
          "Exclusive Forum",
          "The exclusive forum for all claims shall be the Court of Chancery of the State of Delaware, including any claim arising under the Securities Exchange Act of 1934.",
        ),
      ),
    ).not.toBeNull();
  });
});

describe("GOV-022 — implied covenant preserved by a 'No provision' clause", () => {
  it("stays silent when the agreement preserves the implied covenant while modifying duties", () => {
    expect(
      rule("GOV-022").check(
        doc(
          "Fiduciary Duties",
          "To the maximum extent permitted by Section 18-1101 of the Delaware LLC Act, the fiduciary duties otherwise owed by the Manager to the Company and its Members are hereby eliminated and replaced with the contractual obligations set forth in this Agreement. No provision of this Agreement waives the implied covenant of good faith and fair dealing, which shall continue to apply to all parties.",
        ),
      ),
    ).toBeNull();
  });

  it("still flags an actual implied-covenant waiver", () => {
    expect(
      rule("GOV-022").check(
        doc(
          "Fiduciary Duties",
          "The Members hereby waive the implied covenant of good faith and fair dealing to the fullest extent permitted by law.",
        ),
      ),
    ).not.toBeNull();
  });
});

describe("GOV-070 — implied covenant preserved by a 'No provision' clause", () => {
  it("stays silent when the partnership agreement preserves the implied covenant", () => {
    expect(
      rule("GOV-070").check(
        doc(
          "Fiduciary Duties",
          "To the fullest extent permitted by Section 17-1101(d) of the Delaware Revised Uniform Limited Partnership Act, the fiduciary duties of the General Partner are hereby modified as set forth herein. No provision of this Agreement shall be construed to eliminate the implied covenant of good faith and fair dealing, which shall remain in full force and effect.",
        ),
      ),
    ).toBeNull();
  });

  it("still flags an actual implied-covenant elimination", () => {
    expect(
      rule("GOV-070").check(
        doc(
          "Fiduciary Duties",
          "The Partners hereby eliminate the implied covenant of good faith and fair dealing in its entirety.",
        ),
      ),
    ).not.toBeNull();
  });
});

describe("GOV-060 — audit-committee override limited to the Rule 10A-3 phase-in", () => {
  it("stays silent when the override cites the lawful phase-in exception", () => {
    expect(
      rule("GOV-060").check(
        doc(
          "Composition",
          "The Committee shall consist of at least three independent directors. Consistent with the phase-in exception in Exchange Act Rule 10A-3(b)(1)(iv)(A), a non-independent director may serve on the Audit Committee for a period not exceeding one year from the effective date of the Company's registration statement.",
        ),
      ),
    ).toBeNull();
  });

  it("still flags an unconditional non-independent-member override", () => {
    expect(
      rule("GOV-060").check(
        doc(
          "Composition",
          "The Committee shall consist of at least three directors. A non-independent director may serve on the Audit Committee at the discretion of the Board.",
        ),
      ),
    ).not.toBeNull();
  });
});
