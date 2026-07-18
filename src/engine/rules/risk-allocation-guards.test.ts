/**
 * Guards against cross-clause misattribution, embedded-token, and unrecognized-
 * reciprocity false findings in the risk-allocation launch rules (indemnity /
 * liability / insurance / fees). Each case reproduced a wrong finding or a wrong
 * silence on realistic drafting before the fix; both directions are pinned.
 */
import { describe, expect, it } from "vitest";
import { buildContext } from "../_test-fixtures.js";
import { rule as R004 } from "./risk-allocation/RISK-004.js";
import { rule as R006 } from "./risk-allocation/RISK-006.js";
import { rule as R010 } from "./risk-allocation/RISK-010.js";
import { rule as R011 } from "./risk-allocation/RISK-011.js";
import { rule as R014 } from "./risk-allocation/RISK-014.js";
import { rule as R016 } from "./risk-allocation/RISK-016.js";
import { rule as R017 } from "./risk-allocation/RISK-017.js";

const doc = (heading: string, ...rest: string[]) => buildContext([heading, ...rest]);

describe("RISK-004 — indemnity carved out of the cap", () => {
  it("does not fire when a later sentence states indemnity IS inside the cap", () => {
    expect(
      R004.check(
        doc(
          "LoL",
          "In no event shall aggregate liability exceed the fees paid, except for claims arising from bodily injury. For clarity, the Provider's indemnification in Section 8 is fully subject to the aggregate cap.",
        ),
      ),
    ).toBeNull();
  });

  it("still fires on a genuine indemnity carve-out", () => {
    expect(
      R004.check(
        doc(
          "LoL",
          "The limitation of liability shall not apply, except for a party's indemnification obligations, which are uncapped.",
        ),
      ),
    ).not.toBeNull();
  });
});

describe("RISK-006 — LoL carve-out list", () => {
  it("does not list carve-out names from an unrelated later sentence", () => {
    const f = R006.check(
      doc(
        "LoL",
        "This Limitation of Liability applies. Aggregate liability shall not exceed the fees, except for claims arising from a breach of Section 4 (Payment Obligations). Separately, neither party has committed fraud, and the parties waive willful misconduct.",
      ),
    );
    const present = (f?.description ?? "").split("Missing:")[0];
    expect(present).not.toMatch(/fraud|willful/);
  });
});

describe("RISK-010 / RISK-016 — insurance coverage minimum", () => {
  it("RISK-010 does not report an unrelated contract price as the coverage minimum", () => {
    expect(
      R010.check(
        doc(
          "Insurance",
          "Contractor shall maintain commercial general liability insurance in accordance with standards. The total Contract value is $50,000.",
        ),
      ),
    ).toBeNull();
  });

  it("RISK-010 still reports a genuine coverage minimum", () => {
    expect(
      R010.check(
        doc(
          "Insurance",
          "Contractor shall maintain commercial general liability insurance with limits of $1,000,000 per occurrence.",
        ),
      ),
    ).not.toBeNull();
  });

  it("RISK-016 still fires when only an unrelated dollar figure is present", () => {
    expect(
      R016.check(
        doc(
          "Insurance",
          "Contractor shall maintain commercial general liability insurance during the Term. The annual contract fee is $10,000.",
        ),
      ),
    ).not.toBeNull();
  });

  it("RISK-016 is suppressed by a genuine coverage minimum", () => {
    expect(
      R016.check(
        doc(
          "Insurance",
          "Contractor shall maintain commercial general liability insurance with a limit of $1,000,000 per occurrence.",
        ),
      ),
    ).toBeNull();
  });
});

describe("RISK-011 — indemnity defense-control element", () => {
  it("reports 'defense control' missing when only unrelated 'sole control' appears", () => {
    const f = R011.check(
      doc(
        "Indemnity",
        "Vendor shall indemnify Customer against any third-party claim. Customer retains sole control over its own internal systems and data.",
      ),
    );
    expect(f?.description).toMatch(/defense control/);
  });

  it("recognizes a real defense-control provision", () => {
    expect(
      R011.check(
        doc(
          "Indemnity",
          "Vendor shall indemnify Customer, provide prompt written notice, have sole control of the defense of the claim, and settlement requires consent.",
        ),
      ),
    ).toBeNull();
  });
});

describe("RISK-014 — confidentiality term length", () => {
  it("does not report an unrelated survival term as the confidentiality term", () => {
    expect(
      R014.check(
        doc(
          "Confidentiality",
          "The confidentiality obligations of Section 7 are important. Separately, the indemnification obligations under Section 8 shall survive for ten (10) years.",
        ),
      ),
    ).toBeNull();
  });

  it("still reports a genuine confidentiality survival term", () => {
    expect(
      R014.check(
        doc(
          "Confidentiality",
          "The confidentiality obligations shall survive termination for five (5) years.",
        ),
      ),
    ).not.toBeNull();
  });
});

describe("RISK-017 — asymmetric attorneys' fees", () => {
  it("does not flag a fully reciprocal two-sentence fees clause", () => {
    expect(
      R017.check(
        doc(
          "Fees",
          "If Vendor brings an action, Vendor shall be entitled to recover its reasonable attorneys' fees from Customer. If Customer brings an action, Customer shall likewise be entitled to recover its reasonable attorneys' fees from Vendor.",
        ),
      ),
    ).toBeNull();
  });

  it("still flags a genuinely one-way fees award", () => {
    expect(
      R017.check(
        doc(
          "Fees",
          "Vendor shall be entitled to recover its reasonable attorneys' fees and costs in any action to enforce this Agreement.",
        ),
      ),
    ).not.toBeNull();
  });
});
