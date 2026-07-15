import { describe, expect, it } from "vitest";
import fc from "fast-check";
import { extractCitations, type ParsedCitation } from "./citations.js";

describe("extractCitations — positive cases", () => {
  it("parses a well-formed full case citation", () => {
    const hits = extractCitations("See 410 U.S. 113 for the holding.");
    const c = hits.find((h) => h.kind === "case");
    expect(c).toMatchObject({
      volume: "410",
      reporter: "U.S.",
      page: "113",
      well_formed: true,
    });
  });

  it("flags a case citation with an unknown reporter as malformed", () => {
    const hits = extractCitations("123 Fake Rep. 45 is not a real citation.");
    const c = hits.find((h) => h.kind === "case");
    expect(c).toMatchObject({
      volume: "123",
      reporter: "Fake Rep.",
      page: "45",
      well_formed: false,
    });
  });

  it("parses a federal statute citation", () => {
    const hits = extractCitations("As provided by 28 U.S.C. § 1331, the court has jurisdiction.");
    const c = hits.find((h) => h.kind === "statute");
    expect(c).toMatchObject({ title: "28", code: "U.S.C.", section: "1331" });
  });

  it("parses a procedural rule citation", () => {
    const hits = extractCitations("Under Fed. R. App. P. 32, briefs are limited.");
    const c = hits.find((h) => h.kind === "rule");
    expect(c).toMatchObject({ section: "32" });
  });

  it("parses an Id. cross-reference", () => {
    const hits = extractCitations("Id. at 5.");
    const c = hits.find((h) => h.kind === "id");
    expect(c?.raw).toBe("Id.");
  });

  it("parses a supra reference with the referenced name", () => {
    const hits = extractCitations("As discussed in Roe, supra, the standard applies.");
    const c = hits.find((h) => h.kind === "supra");
    expect(c?.refers_to).toBe("Roe");
  });

  it("parses a short-form case reference", () => {
    const hits = extractCitations("Brown v. Board established the principle.");
    const c = hits.find((h) => h.kind === "short-case");
    expect(c?.refers_to).toBe("Brown v. Board");
  });
});

describe("extractCitations — negative cases", () => {
  it("does not treat plain number-word-number prose as a case citation", () => {
    const hits = extractCitations("the 3 blind 5 mice ran away");
    expect(hits.some((h) => h.kind === "case")).toBe(false);
  });
});

describe("extractCitations — overlap and ordering", () => {
  it("returns matches sorted by start with no overlapping spans", () => {
    const hits = extractCitations(
      "Brown v. Board, 347 U.S. 483 (1954); see also 28 U.S.C. § 1331; Fed. R. App. P. 32; Id. at 2; Roe, supra.",
    );
    for (let i = 1; i < hits.length; i += 1) {
      expect(hits[i]!.start).toBeGreaterThanOrEqual(hits[i - 1]!.end);
    }
    const kinds = hits.map((h) => h.kind);
    expect(kinds).toContain("short-case");
    expect(kinds).toContain("case");
    expect(kinds).toContain("statute");
    expect(kinds).toContain("rule");
    expect(kinds).toContain("id");
    expect(kinds).toContain("supra");
  });
});

describe("extractCitations — totality (never throws)", () => {
  it("never throws and always returns bounded, sorted, non-overlapping spans", () => {
    fc.assert(
      fc.property(fc.string({ maxLength: 500 }), (text) => {
        let hits: ParsedCitation[] = [];
        expect(() => {
          hits = extractCitations(text);
        }).not.toThrow();
        for (const h of hits) {
          expect(h.start).toBeGreaterThanOrEqual(0);
          expect(h.end).toBeGreaterThan(h.start);
          expect(h.end).toBeLessThanOrEqual(text.length);
          expect(h.raw).toBe(text.slice(h.start, h.end));
        }
        for (let i = 1; i < hits.length; i += 1) {
          expect(hits[i]!.start).toBeGreaterThanOrEqual(hits[i - 1]!.start);
          expect(hits[i]!.start).toBeGreaterThanOrEqual(hits[i - 1]!.end);
        }
      }),
      { numRuns: 500 },
    );
  });
});
