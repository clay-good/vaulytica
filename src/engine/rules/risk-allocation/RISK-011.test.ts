import { describe, expect, it } from "vitest";
import { rule as RISK_011 } from "./RISK-011.js";
import { buildContext } from "../../_test-fixtures.js";

describe("RISK-011 — the notice element stated with the verb", () => {
  // "We will notify you of any such claim" is the notice term. The element
  // matched only the NOUN ("prompt notice" / "written notice"), so an
  // indemnity that spells the obligation out was told it states no notice
  // procedure at all.
  it("reads 'we will notify you of any such claim'", () => {
    const f = RISK_011.check(
      buildContext([
        "13. Indemnification",
        "You agree to indemnify and hold harmless Tidemark from any claim arising out of your breach of these Terms. We will notify you of any such claim, will give you sole control of the defense, and will not settle without your prior written consent.",
      ]),
    );
    expect(f).toBeNull();
  });

  it("still reports notice missing when the indemnity states no notice term", () => {
    const f = RISK_011.check(
      buildContext([
        "13. Indemnification",
        "You agree to indemnify and hold harmless Tidemark from any claim arising out of your breach of these Terms.",
      ]),
    );
    expect(f?.title).toContain("notice");
  });
});

describe("RISK-011 v1.6.0 — the British spelling of a defence", () => {
  it("reads 'control of the defence'", () => {
    // A UK or Commonwealth indemnity spells it with a c, and this repo already
    // reads "licence" beside "license" for the same reason. The textbook
    // clause was reported as an indemnity missing its defence-control element.
    const ctx = buildContext([
      "Indemnity",
      "Contractor shall indemnify Client against any third-party claim that the Work infringes a copyright, provided that Client promptly notifies Contractor of the claim, gives Contractor control of the defence, and cooperates at Contractor's expense. Contractor shall not settle a claim that admits fault on Client's part without Client's prior written consent.",
    ]);
    expect(RISK_011.check(ctx)).toBeNull();
  });
});
