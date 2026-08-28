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
