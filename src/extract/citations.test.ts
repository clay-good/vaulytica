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

  it("parses common state statute forms with the full jurisdiction prefix", () => {
    const cases: [string, string, string][] = [
      // input                                    expected code                 section
      ["Cal. Civ. Code § 1234", "Cal. Civ. Code", "1234"],
      ["N.Y. Gen. Bus. Law § 349", "N.Y. Gen. Bus. Law", "349"],
      ["42 Pa. Cons. Stat. § 8542", "42 Pa. Cons. Stat.", "8542"],
      ["Del. Code Ann. tit. 8, § 102", "Del. Code Ann.", "102"],
      ["Tex. Bus. & Com. Code § 17.46", "Tex. Bus. & Com. Code", "17.46"],
      ["Fla. Stat. § 501.201", "Fla. Stat.", "501.201"],
      ["Mass. Gen. Laws ch. 93A, § 2", "Mass. Gen. Laws", "2"],
    ];
    for (const [input, code, section] of cases) {
      const hits = extractCitations(`As held under ${input}, the parties agree.`);
      const c = hits.find((h) => h.kind === "statute");
      expect(c, input).toBeDefined();
      // The FULL jurisdiction prefix is captured, not the bare "Code"/"Stat.".
      expect(c!.code, input).toBe(code);
      expect(c!.section, input).toBe(section);
    }
  });

  it("reads Illinois Compiled Statutes as a statute, never a malformed case", () => {
    // Regression: "740 Ill. Comp. Stat. 14/15" and "740 ILCS 5/2" used to read
    // as malformed CASE citations (unknown reporter) and draw a false CITE-001.
    for (const form of ["740 Ill. Comp. Stat. 14/15", "740 ILCS 5/2", "815 ILCS 505/2"]) {
      const hits = extractCitations(`Liability arises under ${form}.`);
      expect(
        hits.some((h) => h.kind === "statute"),
        form,
      ).toBe(true);
      expect(
        hits.filter((h) => h.kind === "case" && h.well_formed === false),
        form,
      ).toHaveLength(0);
    }
  });

  it("does not read ordinary capitalized prose before a section sign as a statute", () => {
    // Each jurisdiction token must be a period-terminated abbreviation, so a
    // non-abbreviation capitalized run is not mistaken for a code name.
    for (const prose of [
      "The Board Approved Plan sets out § 4 obligations.",
      "The Company Handbook Section governs § 12 conduct.",
    ]) {
      expect(extractCitations(prose).filter((h) => h.kind === "statute")).toHaveLength(0);
    }
  });

  it("parses a procedural rule citation", () => {
    const hits = extractCitations("Under Fed. R. App. P. 32, briefs are limited.");
    const c = hits.find((h) => h.kind === "rule");
    expect(c).toMatchObject({ section: "32" });
  });

  it("parses a Federal Rule of Evidence (no trailing 'P.')", () => {
    // Regression: the Rules of Evidence are cited "Fed. R. Evid. 403" — the old
    // pattern demanded "Evid. P.", a form that never occurs, so every FRE cite
    // was silently missed.
    expect(
      extractCitations("under Fed. R. Evid. 403").find((h) => h.kind === "rule"),
    ).toMatchObject({ section: "403" });
    expect(extractCitations("See FRE 702.").find((h) => h.kind === "rule")).toMatchObject({
      section: "702",
    });
  });

  it("parses a Federal Rule of Bankruptcy Procedure", () => {
    expect(
      extractCitations("Fed. R. Bankr. P. 3002 governs.").find((h) => h.kind === "rule"),
    ).toMatchObject({ section: "3002" });
    expect(extractCitations("See FRBP 7001.").find((h) => h.kind === "rule")).toMatchObject({
      section: "7001",
    });
  });

  it("does not read a bare rule acronym in prose as a citation (number required)", () => {
    expect(extractCitations("The FRE report was filed today.").some((h) => h.kind === "rule")).toBe(
      false,
    );
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

  it("audit pins: pin cites, prose, cross-references, and rule cites are not malformed cases", () => {
    // "at"-form pin cite: the reporter must not swallow " at".
    const pin = extractCitations("Smith, 950 F.3d at 458.");
    expect(pin.filter((h) => h.kind === "case" && h.well_formed === false)).toHaveLength(0);
    // Prose after a dotted token between two numbers.
    const prose = extractCitations("15 U.S.C. class sizes exceed 40 students.");
    expect(prose.filter((h) => h.kind === "case")).toHaveLength(0);
    // Modern reporters are known.
    const modern = extractCitations("See 12 F.4th 300 and 61 Cal. App. 5th 500.");
    expect(modern.filter((h) => h.kind === "case" && h.well_formed === false)).toHaveLength(0);
    // New York's modern series and the New York Supplement are well-formed —
    // only the bare "N.Y." was listed, so "5 N.Y.2d 100" read as malformed.
    const ny = extractCitations("5 N.Y.2d 100, 1 N.Y.3d 5, 850 N.Y.S.2d 12, 40 N.Y.S. 9.");
    expect(ny.filter((h) => h.kind === "case")).toHaveLength(4);
    expect(ny.filter((h) => h.kind === "case" && h.well_formed === false)).toHaveLength(0);
    // South Eastern Reporter Third Series is well-formed — every sibling regional
    // reporter listed its 3d series except S.E.3d, so "1 S.E.3d 100" read as malformed.
    const se = extractCitations("800 S.E.2d 100, 1 S.E.3d 55.");
    expect(se.filter((h) => h.kind === "case")).toHaveLength(2);
    expect(se.filter((h) => h.kind === "case" && h.well_formed === false)).toHaveLength(0);
    // The Bankruptcy Reporter is well-formed; the bare-acronym prose decoy is not a cite.
    const br = extractCitations("In re Foo, 500 B.R. 100. The B.R. department reviewed 5 files.");
    expect(br.filter((h) => h.kind === "case" && h.well_formed)).toHaveLength(1);
    // TOA leader digit + rule cite is a RULE, not a malformed case.
    const toa = extractCitations("42 U.S.C. § 1983 ...... 4 Fed. R. App. P. 32 ...... 5");
    expect(toa.filter((h) => h.kind === "case" && h.well_formed === false)).toHaveLength(0);
    expect(toa.some((h) => h.kind === "rule")).toBe(true);
    // "See supra Part II" is an internal cross-reference, not a citation.
    const xref = extractCitations("See supra Part II; see also supra note 3.");
    expect(xref.filter((h) => h.kind === "supra")).toHaveLength(0);
    // The malformed space-in-series form is still caught.
    const bad = extractCitations("Smith v. Jones, 123 F. 3d 456 (9th Cir. 1997).");
    expect(bad.some((h) => h.kind === "case" && h.well_formed === false)).toBe(true);
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

describe("extractCitations — prose is not a citation", () => {
  it("does not treat a number-Word-number prose run as a malformed case citation", () => {
    // The reporter group used to accept any capitalized run, so an address or
    // quantity clause produced a well_formed:false case candidate that CITE-001
    // then flagged as a malformed citation — a false accusation on plain prose.
    for (const prose of [
      "Notices shall be sent to 123 Main St Suite 4400, and copies to Legal.",
      "The Company shall deliver 10 Widget Units 200 to the warehouse by Friday.",
    ]) {
      expect(extractCitations(prose).filter((c) => c.kind === "case")).toHaveLength(0);
    }
    // A real reporter (with a period) is still recognized.
    const real = extractCitations("See 410 U.S. 113 and 123 F.3d 456.");
    expect(real.filter((c) => c.kind === "case" && c.well_formed)).toHaveLength(2);
  });
});
