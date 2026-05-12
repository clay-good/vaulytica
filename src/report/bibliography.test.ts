import { describe, expect, it } from "vitest";
import { buildBibliography, citationIndex } from "./bibliography.js";
import type { Finding } from "../engine/finding.js";
import type { DKB, SourceCitation } from "../dkb/types.js";

function cite(id: string): SourceCitation {
  return {
    id,
    source: `Source ${id}`,
    source_url: `https://example.org/${id}`,
    retrieved_at: "2026-05-11T00:00:00Z",
    license: "MIT",
    license_url: "https://opensource.org/licenses/MIT",
  };
}

function finding(id: string, citationIds: string[], position = 0): Finding {
  return {
    id,
    rule_id: "STRUCT-001",
    rule_version: "1.0.0",
    severity: "info",
    title: id,
    description: "",
    excerpt: { text: "", start_offset: 0, end_offset: 0 },
    explanation: "",
    source_citations: citationIds.map(cite),
    document_position: position,
  };
}

const emptyDkb: DKB = {
  manifest: {
    version: "v0.0.1",
    schema_version: "1.0.0",
    built_at: "2026-05-11T00:00:00Z",
    files: {} as never,
    sources: [],
  },
  clauses: [],
  jurisdictions: [],
  definitions: [],
  dark_patterns: [],
  statutes: [],
  classifier: { vocab: [], patterns: [] },
};

describe("buildBibliography", () => {
  it("deduplicates and numbers in document order of first reference", () => {
    const bib = buildBibliography(
      [finding("f1", ["a", "b"]), finding("f2", ["b", "c"]), finding("f3", ["a"])],
      emptyDkb,
    );
    expect(bib.map((b) => b.source.id)).toEqual(["a", "b", "c"]);
    expect(bib.map((b) => b.index)).toEqual([1, 2, 3]);
    expect(bib[0]!.first_referenced_in).toBe("f1");
    expect(bib[2]!.first_referenced_in).toBe("f2");
  });

  it("citationIndex looks up by id", () => {
    const bib = buildBibliography([finding("f1", ["x", "y"])], emptyDkb);
    expect(citationIndex(bib, "y")).toBe(2);
    expect(citationIndex(bib, "missing")).toBeUndefined();
  });
});
