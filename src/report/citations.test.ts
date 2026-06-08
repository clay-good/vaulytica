import { describe, expect, it } from "vitest";
import {
  formatCitation,
  formatBibliographyEntry,
  citationFamily,
  freshnessSignal,
  breakLongTokens,
} from "./citations.js";
import type { SourceCitation } from "../dkb/types.js";

/** Minimal citation around a given `source`, with a fixed retrieval year. */
function cite(source: string, source_url = "https://example.gov/x"): SourceCitation {
  return {
    id: source.toLowerCase().replace(/[^a-z0-9]+/g, "-"),
    source,
    source_url,
    retrieved_at: "2026-05-11T00:00:00Z",
    license: "Public domain",
    license_url: "https://www.usa.gov/government-works",
  };
}

const uscode: SourceCitation = {
  id: "9-usc-2",
  source: "9 U.S.C. § 2",
  source_url: "https://uscode.house.gov/view.xhtml?req=granuleid:USC-prelim-title9-section2",
  retrieved_at: "2026-05-11T00:00:00Z",
  source_published_at: "2024-01-01",
  license: "Public domain (US government work)",
  license_url: "https://www.usa.gov/government-works",
};

const commonPaper: SourceCitation = {
  id: "common-paper-mutual-nda-v1.1",
  source: "Common Paper Mutual NDA, v1.1",
  source_url: "https://github.com/CommonPaper/Mutual-NDA",
  retrieved_at: "2026-05-11T00:00:00Z",
  license: "CC-BY-4.0",
  license_url: "https://creativecommons.org/licenses/by/4.0/",
  attribution: "Common Paper, Mutual NDA, v1.1, CC BY 4.0",
};

describe("formatCitation", () => {
  it("formats US Code in Bluebook flavor with parenthetical year", () => {
    expect(formatCitation(uscode)).toBe(
      "9 U.S.C. § 2 (2024) — https://uscode.house.gov/view.xhtml?req=granuleid:USC-prelim-title9-section2",
    );
  });

  it("falls back to plain Source — URL for non-statutory citations", () => {
    expect(formatCitation(commonPaper)).toBe(
      "Common Paper Mutual NDA, v1.1 — https://github.com/CommonPaper/Mutual-NDA",
    );
  });
});

describe("citation formatter breadth (spec-v8 §16 — pinned to real DKB forms)", () => {
  // Each row is a real `source` string drawn from the shipped DKB rule
  // citations (EU/GDPR, ISO/NIST, secondary, pinpoint), with its exact
  // rendered string pinned. The coverage matrix in
  // docs/v8/citation-standard.md §3 is the source of truth.

  it("classifies each family", () => {
    expect(citationFamily("45 C.F.R. § 164.410(a)(1)")).toBe("us-statutory");
    expect(citationFamily("Regulation (EU) 2016/679 (GDPR), Article 28")).toBe("eu");
    expect(citationFamily("ePrivacy Directive 2002/58/EC (as amended by 2009/136/EC)")).toBe("eu");
    expect(citationFamily("ISO/IEC 27001:2022")).toBe("standard");
    expect(citationFamily("NIST SP 800-53 Rev. 5 — Security and Privacy Controls")).toBe(
      "standard",
    );
    expect(citationFamily("Restatement (Third) of Unfair Competition § 39")).toBe("secondary");
    expect(citationFamily("Uniform Easement Relocation Act")).toBe("secondary");
    expect(citationFamily("Common Paper Mutual NDA, v1.1")).toBe("other");
  });

  it("preserves pinpoint subsections (never truncates to the base section)", () => {
    expect(formatCitation(cite("45 C.F.R. § 164.410(a)(1)"))).toBe(
      "45 C.F.R. § 164.410(a)(1) (2026) — https://example.gov/x",
    );
  });

  it("renders an EU regulation verbatim with no redundant retrieval-year", () => {
    expect(
      formatCitation(
        cite("Regulation (EU) 2016/679 (GDPR), Article 28", "https://eur-lex.europa.eu/eli/reg/2016/679"),
      ),
    ).toBe("Regulation (EU) 2016/679 (GDPR), Article 28 — https://eur-lex.europa.eu/eli/reg/2016/679");
  });

  it("renders an EU directive verbatim", () => {
    expect(formatCitation(cite("ePrivacy Directive 2002/58/EC (as amended by 2009/136/EC)"))).toBe(
      "ePrivacy Directive 2002/58/EC (as amended by 2009/136/EC) — https://example.gov/x",
    );
  });

  it("renders ISO/NIST standards verbatim (version is intrinsic)", () => {
    expect(formatCitation(cite("ISO/IEC 27001:2022"))).toBe("ISO/IEC 27001:2022 — https://example.gov/x");
    expect(formatCitation(cite("NIST SP 800-53 Rev. 5 — Security and Privacy Controls"))).toBe(
      "NIST SP 800-53 Rev. 5 — Security and Privacy Controls — https://example.gov/x",
    );
  });

  it("renders a secondary source verbatim", () => {
    expect(formatCitation(cite("Restatement (Third) of Unfair Competition § 39"))).toBe(
      "Restatement (Third) of Unfair Competition § 39 — https://example.gov/x",
    );
  });
});

describe("breakLongTokens (spec-v8 §18 — wrap, never truncate)", () => {
  const longUrl =
    "https://www.govinfo.gov/content/pkg/CFR-2024-title45-vol2/xml/CFR-2024-title45-vol2-sec164-410.xml";

  it("rejoins to the exact original text (no characters added or removed)", () => {
    for (const text of [longUrl, "short text", "Policy 4.2", "a — b — c", ""]) {
      expect(breakLongTokens(text).join("")).toBe(text);
    }
  });

  it("splits a long URL into multiple wrap segments", () => {
    const segs = breakLongTokens(longUrl);
    expect(segs.length).toBeGreaterThan(1);
    expect(segs.every((s) => s.length > 0)).toBe(true);
  });

  it("leaves short tokens and whitespace intact (one segment per word)", () => {
    expect(breakLongTokens("9 U.S.C. § 2")).toEqual(["9", " ", "U.S.C.", " ", "§", " ", "2"]);
  });
});

describe("formatBibliographyEntry", () => {
  it("numbers the entry, includes attribution and retrieval/license", () => {
    const line = formatBibliographyEntry(3, commonPaper);
    expect(line.startsWith("[3] ")).toBe(true);
    expect(line).toContain("(Common Paper, Mutual NDA, v1.1, CC BY 4.0)");
    expect(line).toContain("retrieved 2026-05-11T00:00:00Z");
    expect(line).toContain("license: CC-BY-4.0");
  });
});

describe("freshness signal (spec-v8 §17 — honest, inert, deterministic)", () => {
  it("renders the retrieval date alone when no publication date is known", () => {
    expect(freshnessSignal(uscode)).toBe("published 2024-01-01, retrieved 2026-05-11");
    expect(freshnessSignal(commonPaper)).toBe("retrieved 2026-05-11");
  });

  it("returns undefined when no retrieval date is recorded (URL-less custom rule)", () => {
    const policy: SourceCitation = {
      id: "policy-4-2",
      source: "Policy 4.2",
      source_url: "",
      retrieved_at: "",
      license: "Team policy",
      license_url: "",
    };
    expect(freshnessSignal(policy)).toBeUndefined();
  });

  it("surfaces a genuine publication date in the bibliography (additive)", () => {
    const line = formatBibliographyEntry(1, uscode);
    expect(line).toContain("(published 2024-01-01)");
  });

  it("omits the publication date when the field is absent (honesty gate)", () => {
    const line = formatBibliographyEntry(1, commonPaper);
    expect(line).not.toContain("published");
  });
});

describe("URL-less / date-less custom citation renders cleanly (spec-v8 §14)", () => {
  // A cited-by-policy custom rule: the interpreter materializes empty
  // source_url / retrieved_at. Before v8 this rendered "Policy 4.2 — " with a
  // dangling em-dash and "[retrieved ; license: Team policy]" with a blank date.
  const policy: SourceCitation = {
    id: "policy-4-2",
    source: "Policy 4.2",
    source_url: "",
    retrieved_at: "",
    license: "Team policy",
    license_url: "",
  };

  it("formatCitation omits the dangling em-dash when there is no URL", () => {
    expect(formatCitation(policy)).toBe("Policy 4.2");
  });

  it("formatBibliographyEntry renders 'cited — license' instead of a blank retrieval", () => {
    const line = formatBibliographyEntry(7, policy);
    expect(line).toBe("[7] Policy 4.2 (cited — Team policy)");
    expect(line).not.toContain("retrieved ;");
  });
});
