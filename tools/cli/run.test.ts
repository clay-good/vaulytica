import { describe, expect, it } from "vitest";
import { splitGlob, globToRegExp } from "./run.js";

describe("splitGlob (CLI glob resolution)", () => {
  it("resolves a bare glob against the current directory", () => {
    // Regression: the previous slice(0, lastIndexOf('/')) produced "*.doc"
    // for a bare "*.docx", so readdir failed and nothing matched.
    expect(splitGlob("*.docx")).toEqual({ dir: ".", pattern: "*.docx" });
  });

  it("splits a dir/pattern glob at the last slash", () => {
    expect(splitGlob("contracts/*.docx")).toEqual({ dir: "contracts", pattern: "*.docx" });
    expect(splitGlob("./deal-room/*.pdf")).toEqual({ dir: "./deal-room", pattern: "*.pdf" });
    expect(splitGlob("a/b/c/*.txt")).toEqual({ dir: "a/b/c", pattern: "*.txt" });
  });

  it("keeps an absolute root directory", () => {
    expect(splitGlob("/*.docx")).toEqual({ dir: "/", pattern: "*.docx" });
  });
});

describe("globToRegExp", () => {
  it("matches files by extension and treats dots literally", () => {
    const re = globToRegExp("*.docx");
    expect(re.test("nda.docx")).toBe(true);
    expect(re.test("nda.docxx")).toBe(false);
    expect(re.test("ndaXdocx")).toBe(false); // the dot is literal, not 'any char'
  });

  it("anchors so a prefix/suffix does not partial-match", () => {
    const re = globToRegExp("contract-*.pdf");
    expect(re.test("contract-2026.pdf")).toBe(true);
    expect(re.test("my-contract-2026.pdf")).toBe(false);
    expect(re.test("contract-2026.pdf.bak")).toBe(false);
  });
});
