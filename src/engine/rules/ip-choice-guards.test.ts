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

  // v1.1.0 — a contract that PRESERVES class rights trips the same words; it is
  // the opposite of the waiver and must not be flagged.
  it("is silent when the consumer contract preserves class rights", () => {
    expect(
      CHOICE007.check(
        doc(
          "Terms of Service",
          "You do not waive your right to participate in a class action against us.",
        ),
      ),
    ).toBeNull();
    expect(
      CHOICE007.check(
        doc("Terms of Service", "Nothing in this Agreement waives your right to a class action."),
      ),
    ).toBeNull();
    expect(
      CHOICE007.check(
        doc("Terms of Service", "This agreement does not contain a class action waiver."),
      ),
    ).toBeNull();
  });

  it("still fires when an unrelated negation shares the sentence with a real waiver", () => {
    expect(
      CHOICE007.check(
        doc(
          "Terms of Service",
          "You may not receive a refund, and you agree to a class action waiver.",
        ),
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

  it("recognizes data-object-first and 'owns all' ownership forms (v1.2.0)", () => {
    const base = "The Service processes Customer Data on the Customer's behalf.";
    for (const ownership of [
      "Customer Data is and remains owned by the Customer.",
      "All Customer Data shall belong to the Customer.",
      "Customer Data is the exclusive property of the Customer.",
      "The Customer owns all Customer Data.",
    ]) {
      expect(IPDATA004.check(doc("Data", `${base} ${ownership}`)), ownership).toBeNull();
    }
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
