import { describe, expect, it } from "vitest";
import { formatCitation, formatBibliographyEntry } from "./citations.js";
import type { SourceCitation } from "../dkb/types.js";

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

describe("formatBibliographyEntry", () => {
  it("numbers the entry, includes attribution and retrieval/license", () => {
    const line = formatBibliographyEntry(3, commonPaper);
    expect(line.startsWith("[3] ")).toBe(true);
    expect(line).toContain("(Common Paper, Mutual NDA, v1.1, CC BY 4.0)");
    expect(line).toContain("retrieved 2026-05-11T00:00:00Z");
    expect(line).toContain("license: CC-BY-4.0");
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
