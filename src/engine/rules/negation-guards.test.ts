import { describe, expect, it } from "vitest";
import { buildContext } from "../_test-fixtures.js";
import { rule as TEMP_004 } from "./temporal/TEMP-004.js";
import { rule as TERM_008 } from "./termination/TERM-008.js";
import { rule as CHOICE_006 } from "./choice-and-venue/CHOICE-006.js";
import { rule as CHOICE_008 } from "./choice-and-venue/CHOICE-008.js";
import { rule as PERS_001 } from "./personnel/PERS-001.js";
import { rule as PERS_002 } from "./personnel/PERS-002.js";
import { rule as PERS_005 } from "./personnel/PERS-005.js";
import { rule as IPDATA_010 } from "./ip-and-data/IPDATA-010.js";
import { rule as OBLI_004 } from "./obligations/OBLI-004.js";

/**
 * Negation-blindness regressions: an always-on rule must not fire on the
 * DISCLAIMED form of the clause it detects (accusing a document of a
 * manipulative term it explicitly disclaims is the worst honesty failure),
 * while still firing on the genuine clause.
 */
describe("launch-rule negation guards", () => {
  const ctx = (...paras: string[]) => buildContext(["Clause", ...paras]);

  it("TEMP-004 does not flag a disclaimed auto-renewal, but flags a real one", () => {
    expect(
      TEMP_004.check(
        ctx(
          "This Agreement shall not automatically renew and will terminate upon expiration of the Initial Term.",
        ),
      ),
    ).toBeNull();
    expect(
      TEMP_004.check(
        ctx("This Agreement shall automatically renew for successive one-year terms."),
      ),
    ).not.toBeNull();
  });

  it("TERM-008 does not flag a notice-and-cure suspension it disclaims", () => {
    expect(
      TERM_008.check(
        ctx(
          "Provider shall not immediately terminate this Agreement for non-payment without first providing Customer a 10-day cure period to remedy the default.",
        ),
      ),
    ).toBeNull();
  });

  it("CHOICE-006 does not flag arbitration that is explicitly excluded", () => {
    expect(
      CHOICE_006.check(
        ctx(
          "Any dispute shall not be subject to arbitration and shall be resolved exclusively in the state courts of Delaware.",
        ),
      ),
    ).toBeNull();
    expect(
      CHOICE_006.check(
        ctx("Any dispute shall be resolved by binding arbitration under the AAA rules."),
      ),
    ).not.toBeNull();
  });

  it("CHOICE-008 does not flag a jury-trial right it preserves, but flags a waiver", () => {
    expect(
      CHOICE_008.check(
        ctx(
          "Nothing in this Section shall be construed to waive either party's right to a trial by jury.",
        ),
      ),
    ).toBeNull();
    expect(
      CHOICE_008.check(ctx("Each party waives its right to a trial by jury in any action.")),
    ).not.toBeNull();
  });

  it("PERS-001/002 do not flag disclaimed non-compete / non-solicit", () => {
    expect(
      PERS_001.check(
        ctx("This Agreement does not contain a non-compete and Employee may work for competitors."),
      ),
    ).toBeNull();
    expect(
      PERS_002.check(
        ctx(
          "This Agreement does not include any non-solicit or non-solicitation obligation on Employee.",
        ),
      ),
    ).toBeNull();
  });

  it("PERS-005 flags a real 'shall not compete' covenant but not a disclaimer of one", () => {
    // The operative covenant — its "not" is the restriction, not a disclaimer.
    expect(
      PERS_005.check(
        ctx(
          "Executive shall not solicit Employer's customers and shall not compete with Employer in the same line of business.",
        ),
      ),
    ).not.toBeNull();
    // A disclaimer of any non-compete.
    expect(
      PERS_005.check(
        ctx(
          "For the avoidance of doubt, nothing in this Agreement shall be construed as a covenant not to compete.",
        ),
      ),
    ).toBeNull();
  });

  it("IPDATA-010 does not flag a narrowly-scoped 'non-perpetual' license", () => {
    expect(
      IPDATA_010.check(
        ctx(
          "Customer hereby grants Vendor a non-perpetual, revocable, non-transferable, non-sublicensable, restricted license to use Feedback solely to improve the Service.",
        ),
      ),
    ).toBeNull();
    expect(
      IPDATA_010.check(
        ctx(
          "Customer hereby grants Vendor a perpetual, irrevocable, worldwide, royalty-free, sublicensable license to use Feedback.",
        ),
      ),
    ).not.toBeNull();
  });

  it("OBLI-004 does not flag a declined best-efforts standard, but flags real and emphatic ones", () => {
    // Declined — the contract chose reasonable efforts, not best efforts.
    expect(
      OBLI_004.check(
        ctx(
          "The parties shall use commercially reasonable efforts, and not best efforts, to perform.",
        ),
      ),
    ).toBeNull();
    // Genuine best-efforts obligation.
    expect(
      OBLI_004.check(ctx("Contractor shall use best efforts to deliver the software.")),
    ).not.toBeNull();
    // Emphatic obligation — "not less than best efforts" is still a best-efforts
    // standard; the negator governs "less than", not the phrase, so it must fire.
    expect(
      OBLI_004.check(
        ctx("Contractor shall use not less than best efforts to deliver the software."),
      ),
    ).not.toBeNull();
  });
});
