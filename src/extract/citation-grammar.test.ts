import { describe, expect, it } from "vitest";
import { INDIGO_BOOK_SOURCE, REPORTERS, isKnownReporter } from "./citation-grammar.js";

describe("citation-grammar", () => {
  it("cites The Indigo Book, never a proprietary manual", () => {
    expect(INDIGO_BOOK_SOURCE.cite).toBe("The Indigo Book 2.0 (2021)");
    expect(INDIGO_BOOK_SOURCE.url).toMatch(/^https:\/\//);
    expect(INDIGO_BOOK_SOURCE.retrieved_at).toMatch(/^\d{4}-\d{2}-\d{2}$/);
  });

  it("carries the required core reporters", () => {
    for (const r of [
      "U.S.",
      "S. Ct.",
      "F.",
      "F.2d",
      "F.3d",
      "F. Supp.",
      "F. Supp. 2d",
      "F. Supp. 3d",
      "F. App'x",
      "Cal.",
      "Cal. 4th",
      "N.Y.",
      "N.E.2d",
      "P.3d",
      "So. 2d",
      "A.3d",
    ]) {
      expect(REPORTERS).toContain(r);
    }
  });

  it("recognizes known reporters", () => {
    expect(isKnownReporter("U.S.")).toBe(true);
    expect(isKnownReporter("F.3d")).toBe(true);
  });

  it("normalizes whitespace before comparing", () => {
    expect(isKnownReporter("  F.   Supp.   2d  ")).toBe(true);
    expect(isKnownReporter("F.Supp.2d")).toBe(false);
  });

  it("rejects unknown reporters", () => {
    expect(isKnownReporter("Fake Rep.")).toBe(false);
    expect(isKnownReporter("")).toBe(false);
  });
});
