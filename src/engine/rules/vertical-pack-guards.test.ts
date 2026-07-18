/**
 * Guards against cross-clause misattribution (EST-201) and negation-blindness
 * (PNOT-TX exact-wording) false findings in the opt-in vertical packs. Both are
 * gated/dormant by default, but a false accusation when the pack is enabled is
 * still a real honesty failure. Both directions are pinned.
 */
import { describe, expect, it } from "vitest";
import { buildContext } from "../_test-fixtures.js";
import { ESTATE_CHECK_RULES } from "./v4/trust-estate/estate-checks.js";
import { PNOT_RULES } from "./privacy-notice/rules.js";

const EST201 = ESTATE_CHECK_RULES.find((r) => r.id === "EST-201")!;
const TX007 = PNOT_RULES.find((r) => r.id === "PNOT-TX-007")!;
const TX008 = PNOT_RULES.find((r) => r.id === "PNOT-TX-008")!;
const doc = (heading: string, ...rest: string[]) => buildContext([heading, ...rest]);

describe("EST-201 — residuary share arithmetic", () => {
  it("does not sum an unrelated percentage (a trustee-fee cap) into the residuary total", () => {
    expect(
      EST201.check(
        doc(
          "Residuary",
          "I give the rest, residue and remainder of my estate fifty percent (50%) to my daughter and fifty percent (50%) to my son.",
          "Trustee",
          "The trustee's compensation shall not exceed 3% of the fair market value.",
        ),
      ),
    ).toBeNull();
  });

  it("is not suppressed by an unrelated 'per stirpes' bequest elsewhere", () => {
    expect(
      EST201.check(
        doc(
          "Residuary",
          "I give the residue of my estate forty percent (40%) to my daughter and fifty percent (50%) to my son.",
          "Bequest",
          "I give my jewelry to my grandchildren, per stirpes.",
        ),
      ),
    ).not.toBeNull();
  });

  it("leaves a correct 100% split alone and still flags a genuine short split", () => {
    expect(
      EST201.check(
        doc(
          "Residuary",
          "I give the residue of my estate fifty percent (50%) to my daughter and fifty percent (50%) to my son.",
        ),
      ),
    ).toBeNull();
    expect(
      EST201.check(
        doc(
          "Residuary",
          "I give the residue of my estate forty percent (40%) to A and fifty percent (50%) to B.",
        ),
      ),
    ).not.toBeNull();
  });
});

describe("PNOT-TX-007 / PNOT-TX-008 — Texas exact-wording sale notices", () => {
  it("does not demand the notice when the document disclaims selling the data", () => {
    expect(
      TX007.check(
        doc(
          "Privacy",
          "We do not sell your sensitive personal data to any third party, and we have never done so.",
        ),
      ),
    ).toBeNull();
    expect(
      TX007.check(
        doc("Privacy", "We never sell or share sensitive personal data with any third party."),
      ),
    ).toBeNull();
    expect(
      TX008.check(doc("Privacy", "We do not sell your biometric personal data to anyone.")),
    ).toBeNull();
  });

  it("still flags a controller that actually sells the data without the notice", () => {
    expect(
      TX007.check(
        doc(
          "Privacy",
          "We sell your sensitive personal data to third-party advertisers for revenue.",
        ),
      ),
    ).not.toBeNull();
  });
});
