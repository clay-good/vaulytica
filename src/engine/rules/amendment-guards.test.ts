/**
 * An amendment does not restate what its parent agreement already says.
 *
 * A hand-written third amendment to an office lease drew eight warnings, five
 * of which were the always-on absence checks reporting that it had no
 * governing law, no venue, no indemnity, no liability cap, no
 * termination-for-cause, no effect-of-termination, and no IP allocation. It
 * has none of those because the Lease has all of them, and Section 13 says so:
 * "Except as expressly modified by this Amendment, the Lease remains in full
 * force and effect and is ratified and confirmed."
 *
 * That sentence is the drafting convention for saying it, and the finding it
 * drew has no answer — the only change that would satisfy it is restating the
 * parent agreement inside its own amendment.
 *
 * The signal is deliberately narrow: NOT "the document mentions another
 * agreement" (every commercial contract incorporates exhibits by reference,
 * and a DPA incorporates the Standard Contractual Clauses), but the
 * ratification sentence specifically. No corpus fixture carries one, and no
 * committed finding changed.
 */
import { describe, expect, it } from "vitest";
import { buildContext } from "../_test-fixtures.js";
import { rule as CHOICE_001 } from "./choice-and-venue/CHOICE-001.js";
import { rule as CHOICE_003 } from "./choice-and-venue/CHOICE-003.js";
import { rule as RISK_001 } from "./risk-allocation/RISK-001.js";
import { rule as RISK_005 } from "./risk-allocation/RISK-005.js";
import { rule as TERM_002 } from "./termination/TERM-002.js";
import { rule as TERM_005 } from "./termination/TERM-005.js";
import { rule as IPDATA_001 } from "./ip-and-data/IPDATA-001.js";

const RULES = [CHOICE_001, CHOICE_003, RISK_001, RISK_005, TERM_002, TERM_005, IPDATA_001];

/** The operative body of an amendment: it changes named terms and nothing else. */
const BODY = [
  "The Term is extended for sixty months, commencing September 1, 2026.",
  "Base Rent for the Existing Premises during the Extension Term is $38.50 per rentable square foot.",
  "The Security Deposit is increased from $118,000 to $155,000.",
];

const RATIFICATION =
  "Except as expressly modified by this Amendment, the Lease remains in full force and effect and is ratified and confirmed.";

describe("the always-on absence checks on an amending document", () => {
  it.each(RULES.map((r) => [r.id, r] as const))(
    "%s stays silent when the document ratifies its parent",
    (_id, rule) => {
      const finding = rule.check(
        buildContext(["Third Amendment to Office Lease", ...BODY, RATIFICATION]),
      );
      expect(finding, `flagged an amendment: ${finding?.title ?? ""}`).toBeNull();
    },
  );

  it.each(RULES.map((r) => [r.id, r] as const))(
    "%s still fires on the same body without the ratification clause",
    (_id, rule) => {
      // Load-bearing in both directions: the identical text, with only the
      // ratification sentence removed, is an ordinary standalone document and
      // every one of these checks belongs on it.
      const finding = rule.check(buildContext(["Office Lease", ...BODY]));
      expect(finding, "did not fire on a standalone document").not.toBeNull();
    },
  );

  it("is not switched off by an ordinary incorporation of exhibits", () => {
    // The narrowness matters: "the Exhibits are incorporated herein by
    // reference" is in nearly every commercial agreement, and matching it
    // would disable these checks across the catalog.
    const finding = CHOICE_001.check(
      buildContext([
        "Master Services Agreement",
        ...BODY,
        "The Exhibits and Schedules attached hereto are incorporated herein by reference and form a part of this Agreement.",
      ]),
    );
    expect(finding).not.toBeNull();
  });
});
