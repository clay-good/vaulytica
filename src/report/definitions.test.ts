/**
 * Definitions report (add-defined-terms-report): bucket discipline,
 * determinism, and tamper-evidence over a known term inventory.
 */

import fc from "fast-check";
import { describe, expect, it } from "vitest";
import {
  buildDefinitionsReport,
  buildBundleDefinitionsReport,
  buildDefinitionsCsv,
  buildDefinitionsMarkdown,
  verifyDefinitionsHash,
} from "./definitions.js";
import type { DefinitionEntry, DocPosition, ExtractedData } from "../extract/types.js";

const pos = (section: string, start: number): DocPosition => ({
  section_id: section,
  start,
  end: start + 10,
});

const entry = (term: string, definedAt: number, usedAt: number[]): DefinitionEntry => ({
  term,
  definition: `${term} means something.`,
  defined_at: pos("s2", definedAt),
  used_at: usedAt.map((n) => pos("s3", n)),
});

function extractedWith(defs: {
  entries?: DefinitionEntry[];
  unused_terms?: string[];
  undefined_capitalized?: Array<{ term: string; positions: DocPosition[] }>;
  circular_terms?: string[][];
}): Pick<ExtractedData, "definitions"> {
  return {
    definitions: {
      entries: defs.entries ?? [],
      unused_terms: defs.unused_terms ?? [],
      undefined_capitalized: defs.undefined_capitalized ?? [],
      circular_terms: defs.circular_terms,
    },
  };
}

describe("buildDefinitionsReport — buckets over a known inventory", () => {
  const extracted = extractedWith({
    entries: [
      entry("Clean Term", 100, [200, 300]),
      entry("Unused Term", 110, []),
      entry("Early Term", 500, [50]), // used before defined
      entry("Twice Term", 120, [400]),
      entry("Twice Term", 600, [700]), // duplicate definition
    ],
    unused_terms: ["Unused Term"],
    undefined_capitalized: [{ term: "Ghost Term", positions: [pos("s4", 900)] }],
    circular_terms: [["A", "B", "A"]],
  });

  it("assigns every term to exactly one primary bucket, risk-ordered", async () => {
    const r = await buildDefinitionsReport(extracted);
    expect(r.undefined_used.map((u) => u.term)).toEqual(["Ghost Term"]);
    expect(r.duplicates.map((d) => d.term)).toEqual(["Twice Term"]);
    expect(r.duplicates[0]!.defined_at).toHaveLength(2);
    expect(r.used_before_defined.map((u) => u.term)).toEqual(["Early Term"]);
    expect(r.unused.map((u) => u.term)).toEqual(["Unused Term"]);
    expect(r.defined.map((d) => d.term)).toEqual(["Clean Term"]);
    expect(r.circular).toEqual([["A", "B", "A"]]);
    expect(r.counts).toEqual({
      undefined_used: 1,
      duplicates: 1,
      used_before_defined: 1,
      unused: 1,
      defined: 1,
    });
  });

  it("is deterministic and hash-verifiable; edits are detected", async () => {
    const a = await buildDefinitionsReport(extracted);
    const b = await buildDefinitionsReport(extracted);
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
    expect(await verifyDefinitionsHash(a)).toBe(true);
    expect(await verifyDefinitionsHash({ ...a, unused: [] })).toBe(false);
  });

  it("renders CSV (risk-ordered, header first) and Markdown", async () => {
    const r = await buildDefinitionsReport(extracted);
    const csv = buildDefinitionsCsv(r);
    expect(csv.startsWith("bucket,term,detail,locations")).toBe(true);
    expect(csv.indexOf("undefined-but-used")).toBeLessThan(csv.indexOf("defined-but-unused"));
    const md = buildDefinitionsMarkdown(r);
    expect(md).toContain("## Definitions report");
    expect(md).toContain("Ghost Term");
    expect(md).toContain("definitions_hash");
  });

  it("property: every term appears in exactly one primary bucket", async () => {
    const termArb = fc
      .stringMatching(/^[A-Z][a-z]{2,8} [A-Z][a-z]{2,8}$/)
      .filter((t) => t.trim().length > 5);
    await fc.assert(
      fc.asyncProperty(
        fc.uniqueArray(termArb, { minLength: 1, maxLength: 8 }),
        fc.array(fc.nat(3), { minLength: 8, maxLength: 8 }),
        async (terms, shapes) => {
          const entries: DefinitionEntry[] = [];
          const unused: string[] = [];
          terms.forEach((t, i) => {
            const shape = shapes[i % shapes.length]!;
            if (shape === 0) entries.push(entry(t, 100 + i, [500 + i]));
            else if (shape === 1) {
              entries.push(entry(t, 100 + i, []));
              unused.push(t);
            } else if (shape === 2) entries.push(entry(t, 500 + i, [50 + i]));
            else {
              entries.push(entry(t, 100 + i, [400]));
              entries.push(entry(t, 600 + i, [700]));
            }
          });
          const r = await buildDefinitionsReport(extractedWith({ entries, unused_terms: unused }));
          const buckets = [
            ...r.undefined_used.map((x) => x.term),
            ...r.duplicates.map((x) => x.term),
            ...r.used_before_defined.map((x) => x.term),
            ...r.unused.map((x) => x.term),
            ...r.defined.map((x) => x.term),
          ];
          expect(new Set(buckets).size).toBe(buckets.length); // no term twice
          for (const t of terms) expect(buckets).toContain(t); // no term dropped
        },
      ),
      { numRuns: 50 },
    );
  });
});

describe("bundle mode", () => {
  it("merges per-document reports and surfaces cross-document redefinitions", async () => {
    const mk = (name: string, defText: string) =>
      ({
        doc_id: name,
        source_file_name: name,
        playbook_id: "msa",
        tree: { type: "document", sections: [] },
        extracted: {
          definitions: {
            entries: [
              {
                term: "Confidential Information",
                definition: defText,
                defined_at: pos("s1", 10),
                used_at: [pos("s2", 100)],
              },
            ],
            unused_terms: [],
            undefined_capitalized: [],
          },
        },
      }) as unknown as Parameters<typeof buildBundleDefinitionsReport>[0][number];

    const bundle = await buildBundleDefinitionsReport([
      mk("msa.docx", "Confidential Information means all non-public information of a party."),
      mk("sow.docx", "Confidential Information means only information marked confidential."),
    ]);
    expect(bundle.documents).toHaveLength(2);
    expect(bundle.cross_document_redefinitions.map((c) => c.term)).toContain(
      "Confidential Information",
    );
    expect(bundle.definitions_hash).toMatch(/^[0-9a-f]{64}$/);
  });
});
