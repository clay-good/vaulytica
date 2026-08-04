import { describe, expect, it } from "vitest";
import { rule as CHOICE_002 } from "./CHOICE-002.js";
import { buildContext } from "../../_test-fixtures.js";

describe("CHOICE-002 — governing-law jurisdiction specificity (v1.1.0)", () => {
  const fires = (text: string) => CHOICE_002.check(buildContext(["Governing Law", text])) !== null;

  it("does not flag a two-letter state code as unspecified", () => {
    // "NY" / "DE" are fully specific jurisdictions — the extractor records them
    // as a 2-char raw_text, which the old length >= 3 test mislabeled.
    expect(fires("This Agreement is governed by the laws of the State of NY.")).toBe(false);
    expect(fires("This Agreement is governed by the laws of NY.")).toBe(false);
    expect(fires("Governed by DE law.")).toBe(false);
  });

  it("does not flag a spelled-out jurisdiction", () => {
    expect(fires("This Agreement is governed by the laws of the State of New York.")).toBe(false);
    expect(fires("Governed by the laws of the United States of America.")).toBe(false);
  });

  it("stays silent when there is no governing-law clause to evaluate", () => {
    expect(fires("The parties agree to negotiate in good faith.")).toBe(false);
  });
});
