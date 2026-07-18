/**
 * Guards against match-inside-a-word and cross-clause-misattribution false
 * findings in the IP/data and choice-of-law launch rules. Each case reproduced
 * a confident wrong finding on realistic drafting before the fix; both
 * directions are pinned so a future edit cannot regress either.
 */
import { describe, expect, it } from "vitest";
import { buildContext } from "../_test-fixtures.js";
import { rule as CHOICE007 } from "./choice-and-venue/CHOICE-007.js";
import { rule as IPDATA004 } from "./ip-and-data/IPDATA-004.js";
import { rule as IPDATA010 } from "./ip-and-data/IPDATA-010.js";

const doc = (heading: string, ...rest: string[]) => buildContext([heading, ...rest]);

describe("CHOICE-007 — consumer-contract detection", () => {
  it("does not treat a 'Release of Claims' heading as a consumer lease", () => {
    // "lease" must not match inside "Release".
    expect(
      CHOICE007.check(
        doc(
          "Release of Claims",
          "The parties agree to a class action waiver for any dispute under this Release.",
        ),
      ),
    ).toBeNull();
  });

  it("still fires on a genuine residential lease", () => {
    expect(
      CHOICE007.check(
        doc("Residential Lease", "Tenant agrees to a class action waiver for any dispute."),
      ),
    ).not.toBeNull();
  });
});

describe("IPDATA-004 — data ownership addressed", () => {
  it("recognizes stated Service Data ownership", () => {
    expect(
      IPDATA004.check(
        doc("Data", "Vendor owns the Service Data and all analytics derived therefrom."),
      ),
    ).toBeNull();
  });

  it("still flags Service Data whose ownership is never stated", () => {
    expect(
      IPDATA004.check(doc("Data", "The Service Data is processed for analytics.")),
    ).not.toBeNull();
  });
});

describe("IPDATA-010 — perpetual-license overreach", () => {
  it("does not flag a narrow Feedback clause using an unrelated clause's modifiers", () => {
    expect(
      IPDATA010.check(
        doc(
          "License",
          "Company grants Customer a perpetual, worldwide, royalty-free, irrevocable license to use the pre-existing Documentation furnished under this Agreement. Separately, Customer's feedback license to Company is limited to a non-exclusive, non-transferable, non-sublicensable right to use Feedback solely to improve the Service.",
        ),
      ),
    ).toBeNull();
  });

  it("still fires on a genuinely overreaching Feedback grant", () => {
    expect(
      IPDATA010.check(
        doc(
          "License",
          "Customer hereby grants Company a perpetual, irrevocable, royalty-free, worldwide, sublicensable license to use all Feedback for any purpose.",
        ),
      ),
    ).not.toBeNull();
  });
});
