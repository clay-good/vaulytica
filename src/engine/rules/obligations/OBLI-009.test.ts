import { describe, expect, it } from "vitest";
import { rule as OBLI_009 } from "./OBLI-009.js";
import { buildContext } from "../../_test-fixtures.js";

describe("OBLI-009 — residuals clause swallows confidentiality", () => {
  it("fires on the word `Residuals`", () => {
    const ctx = buildContext([
      "Residuals",
      "Notwithstanding the foregoing, Recipient may use Residuals for any purpose.",
    ]);
    const f = OBLI_009.check(ctx);
    expect(f?.severity).toBe("warning");
    expect(f?.title).toMatch(/residuals/i);
  });

  it("fires on `unaided memory` language", () => {
    const ctx = buildContext([
      "Use of Information",
      "Recipient's representatives may use any information retained in the unaided memory of such representative.",
    ]);
    expect(OBLI_009.check(ctx)).not.toBeNull();
  });

  it("fires on `general knowledge, skills and experience`", () => {
    const ctx = buildContext([
      "Carve-Outs",
      "Nothing herein restricts use of general knowledge, skills and experience gained in the course of evaluation.",
    ]);
    expect(OBLI_009.check(ctx)).not.toBeNull();
  });

  it("is silent on a plain NDA without residuals", () => {
    const ctx = buildContext([
      "Confidentiality",
      "Recipient shall not disclose Confidential Information to any third party.",
    ]);
    expect(OBLI_009.check(ctx)).toBeNull();
  });
});
