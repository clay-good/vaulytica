/**
 * Rule-detection fidelity regressions (fix-rule-detection-fidelity).
 *
 * Four launch rules mis-detected on realistic contract language — each
 * reproduced live through the shipped CLI before the fix. Every case
 * here lands as a two-sided pair: the document that used to mis-detect,
 * and a counter-fixture pinning that the rule still fires on the true
 * positive it was built for.
 */

import { describe, expect, it } from "vitest";
import { buildContext } from "../_test-fixtures.js";
import { rule as FIN_001 } from "./financial/FIN-001.js";
import { rule as IPDATA_001 } from "./ip-and-data/IPDATA-001.js";
import { rule as PERS_009 } from "./personnel/PERS-009.js";
import { rule as TEMP_003 } from "./temporal/TEMP-003.js";

describe("FIN-001 — magnitude suffixes are applied, not ignored", () => {
  it('no false critical on "one million dollars ($1M)"', () => {
    // The regex tolerated the suffix but never multiplied it: this fired a
    // CRITICAL "1000000 does not match numeral 1" on consistent drafting.
    const ctx = buildContext(["Fees", "The fee is one million dollars ($1M)."]);
    expect(FIN_001.check(ctx)).toBeNull();
  });

  it("suffixed and unsuffixed forms both normalize (k, mm, bn)", () => {
    for (const text of [
      "A cap of five hundred thousand dollars ($500k).",
      "A cap of two million dollars ($2MM).",
      "A cap of one billion dollars ($1bn).",
    ]) {
      expect(FIN_001.check(buildContext(["Fees", text])), text).toBeNull();
    }
  });

  it("still fires on a genuinely mismatched suffixed amount", () => {
    const ctx = buildContext(["Fees", "The fee is one million dollars ($2M)."]);
    const finding = FIN_001.check(ctx);
    expect(finding?.severity).toBe("critical");
    expect(finding?.description).toContain("2000000");
  });
});

describe("IPDATA-001 — assignment must have an IP object", () => {
  it("a receivables assignment no longer satisfies the IP presence check", () => {
    const ctx = buildContext([
      "Assignment of Receivables",
      "The Borrower hereby assigns to the Lender all of its accounts receivable and the proceeds thereof as security for the obligations.",
    ]);
    expect(IPDATA_001.check(ctx)?.title).toBe("No IP-ownership clause detected");
  });

  it("still satisfied by a real IP assignment", () => {
    const ctx = buildContext([
      "Ownership",
      "Contractor hereby assigns to the Company all right, title and interest in and to all inventions and works of authorship created under this Agreement.",
    ]);
    expect(IPDATA_001.check(ctx)).toBeNull();
  });

  it("still satisfied by work-for-hire / IP-ownership phrasing", () => {
    expect(
      IPDATA_001.check(buildContext(["Ownership", "All deliverables are works made for hire."])),
    ).toBeNull();
  });
});

describe("PERS-009 — duration attribution is sentence-scoped", () => {
  it("a 24-month support commitment sharing the paragraph is not a 24-month non-solicit", () => {
    const ctx = buildContext([
      "Covenants",
      "During the Restricted Period, the Executive shall not solicit any employee of the Company; the Restricted Period is defined in Exhibit A. Separately, the Company shall provide transition support for twenty-four (24) months following the Closing.",
    ]);
    expect(PERS_009.check(ctx)).toBeNull();
  });

  it("still fires when the long duration sits in the non-solicit sentence", () => {
    const ctx = buildContext([
      "Covenants",
      "The Executive shall not solicit any employee of the Company for a period of twenty-four (24) months following termination.",
    ]);
    const finding = PERS_009.check(ctx);
    expect(finding).not.toBeNull();
    expect(finding?.title).toContain("24 months");
  });
});

describe("TEMP-003 — term/notice pairing awareness", () => {
  it("a month-to-month auto-renewing term with 60-day notice is not flagged", () => {
    const ctx = buildContext([
      "Term",
      "This Agreement has an initial term of 1 month and shall automatically renew for successive one-month periods unless either party gives 60 days prior written notice of non-renewal.",
    ]);
    expect(TEMP_003.check(ctx)).toBeNull();
  });

  it("still fires (warning) when the same clause pairs a longer notice with the term", () => {
    const ctx = buildContext([
      "Term",
      "This Agreement has a term of 30 days and may be terminated on 90 days prior written notice.",
    ]);
    const finding = TEMP_003.check(ctx);
    expect(finding?.severity).toBe("warning");
    expect(finding?.description).toContain("same clause");
  });

  it("cross-paragraph pairing downgrades to info and says so", () => {
    const ctx = buildContext([
      "Term",
      "This Agreement has a term of 30 days.",
      "Vendor may modify the SLA on 90 days prior written notice.",
    ]);
    const finding = TEMP_003.check(ctx);
    expect(finding?.severity).toBe("info");
    expect(finding?.explanation).toContain("lower-confidence");
  });
});

describe("PERS-009 — a sale-of-business covenant is a different regime (v1.2.0)", () => {
  it("does not apply the post-employment 12-month bound to a seller covenant protecting purchased goodwill", () => {
    const ctx = buildContext([
      "Covenants",
      "For five (5) years after the Closing Date, Seller and its owners shall not solicit members or employees of the Business; the parties agree these restrictions are necessary to protect the goodwill Buyer is purchasing.",
    ]);
    expect(PERS_009.check(ctx)).toBeNull();
  });

  it("still flags a long post-employment non-solicit", () => {
    const ctx = buildContext([
      "Restrictive Covenants",
      "For twenty-four (24) months after termination of employment, Employee shall not solicit any customer or employee of the Company.",
    ]);
    expect(PERS_009.check(ctx)).not.toBeNull();
  });
});

describe("IPDATA-001 — a license allocates ownership by reserving it (v1.2.0)", () => {
  it("reads 'are and remain the sole property of Licensor'", () => {
    expect(
      IPDATA_001.check(
        buildContext([
          "Ownership",
          "The Licensed Works are and remain the sole property of Licensor. This Agreement is a license, not a transfer of copyright ownership.",
        ]),
      ),
    ).toBeNull();
  });

  it("reads the reservation-of-rights formula", () => {
    expect(
      IPDATA_001.check(
        buildContext([
          "Grant",
          "Licensor grants Licensee a non-exclusive license to reproduce the Works. All rights not expressly granted are reserved.",
        ]),
      ),
    ).toBeNull();
  });

  it("still fires when nothing allocates ownership", () => {
    expect(
      IPDATA_001.check(
        buildContext(["Services", "Vendor shall provide the Services described in Exhibit A."]),
      ),
    ).not.toBeNull();
  });
});
