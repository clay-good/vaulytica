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

describe("RISK-011 v1.7.0 — 'indemnify, defend, and hold harmless the Escrow Agent'", () => {
  it("stays silent on the stakeholder's own protection", () => {
    // The carve-out for a neutral agent's fiduciary indemnity wanted
    // "indemnify and hold harmless the Escrow Agent" adjacently, and the
    // three-verb form is at least as common. An M&A escrow agreement was told
    // that the clause protecting its escrow agent controls no defense and
    // requires no settlement consent.
    const ctx = buildContext([
      "9. Indemnification of the Escrow Agent",
      "Buyer and the Sellers, jointly and severally, shall indemnify, defend, and hold harmless the Escrow Agent and its officers, directors, employees, and agents from and against all claims, losses, liabilities, and reasonable out-of-pocket expenses arising out of this Escrow Agreement, except to the extent caused by the Escrow Agent's gross negligence or willful misconduct.",
    ]);
    expect(RISK_011.check(ctx)).toBeNull();
  });

  it("still audits a commercial indemnity that names a party, not an agent", () => {
    const ctx = buildContext([
      "9. Indemnification",
      "Supplier shall indemnify, defend, and hold harmless Buyer and its officers, directors, employees, and agents from and against all claims arising out of the Products.",
    ]);
    expect(RISK_011.check(ctx)).not.toBeNull();
  });
});
