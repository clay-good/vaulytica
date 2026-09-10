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

describe("OBLI-009 — residuals detection recognizes plural 'unaided memories' (v1.1.0)", () => {
  const fires = (b: string) => !!OBLI_009.check(buildContext(["Confidentiality", b]) as never);

  it("fires on the plural 'unaided memories of its employees' form", () => {
    expect(
      fires(
        "The Receiving Party may freely use ideas, concepts, and know-how retained in intangible form in the unaided memories of its employees.",
      ),
    ).toBe(true);
  });

  it("still stays silent on an ordinary confidentiality obligation", () => {
    expect(
      fires("The Receiving Party shall protect Confidential Information using reasonable care."),
    ).toBe(false);
  });
});

// NDA-D-009 detects the same clause and learned this in 9.640.0; this sibling
// did not, so the same paragraph drew a warning from one rule and not the
// other. The patterns have a single owner in `_helpers.ts` now.
describe("OBLI-009 — a clause that REJECTS residuals (v1.2.0)", () => {
  const fires = (b: string) => !!OBLI_009.check(buildContext(["Confidentiality", b]) as never);

  it("stays silent when the paragraph's own heading is the only bare 'Residuals'", () => {
    expect(
      fires(
        "7.3 Residuals. Nothing in this Agreement grants a residuals right, and neither Party " +
          "may use the other's Confidential Information on the basis that its personnel retained " +
          "it in unaided memory.",
      ),
    ).toBe(false);
  });

  it("stays silent on an express rejection", () => {
    expect(fires("The parties expressly reject any residuals right.")).toBe(false);
  });

  it("still fires on a genuine residuals grant in a paragraph containing an unrelated 'not'", () => {
    expect(
      fires(
        "Recipient shall not disclose Confidential Information to any third party. Recipient's " +
          "personnel may use Residuals for any purpose, and nothing in this Section limits that " +
          "right.",
      ),
    ).toBe(true);
  });
});
