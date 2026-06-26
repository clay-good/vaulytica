import { describe, expect, it } from "vitest";
import { rule as STRUCT_015 } from "./STRUCT-015.js";
import { buildContext } from "../../_test-fixtures.js";

describe("STRUCT-015 — numbered section gaps", () => {
  it("fires when sections jump from 2 to 4 (missing 3)", () => {
    const ctx = buildContext(
      ["1. Definitions", "Defined terms appear below."],
      ["2. Confidentiality", "Recipient shall protect Confidential Information."],
      ["4. Term", "This Agreement is effective for two years."],
    );
    const f = STRUCT_015.check(ctx);
    expect(f?.severity).toBe("info");
    expect(f?.description).toMatch(/missing 3/);
  });

  it("is silent when sections are consecutive", () => {
    const ctx = buildContext(
      ["1. Definitions", "Defined terms."],
      ["2. Confidentiality", "Confidentiality."],
      ["3. Term", "Term."],
    );
    expect(STRUCT_015.check(ctx)).toBeNull();
  });

  it("is silent when fewer than 3 numbered siblings exist (one stray)", () => {
    const ctx = buildContext(["1. Definitions", "Body."], ["4. Term", "Body."]);
    expect(STRUCT_015.check(ctx)).toBeNull();
  });

  it("is silent for unnumbered headings", () => {
    const ctx = buildContext(
      ["Definitions", "Body."],
      ["Confidentiality", "Body."],
      ["Term", "Body."],
    );
    expect(STRUCT_015.check(ctx)).toBeNull();
  });

  it("fires when two gaps appear and reports them all", () => {
    const ctx = buildContext(["1. A", "Body."], ["3. B", "Body."], ["5. C", "Body."]);
    const f = STRUCT_015.check(ctx);
    expect(f).not.toBeNull();
    expect(f!.description).toMatch(/2.*4|missing.*2/);
  });
});
