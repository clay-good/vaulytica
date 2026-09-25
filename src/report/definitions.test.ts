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
import { buildTree } from "../extract/_fixtures.js";
import { extractAll } from "../extract/index.js";
import { undefinedTermCandidates } from "../engine/rules/structural/STRUCT-006.js";

/** The bucketing tests run over a synthetic inventory with no document behind it. */
const EMPTY_TREE = buildTree(["Agreement"]);

const pos = (section: string, start: number): DocPosition => ({
  section_id: section,
  start,
  end: start + 10,
});

/** Minimal RFC-4180 single-row field splitter (quotes, doubled quotes). */
function parseCsvRow(row: string): string[] {
  const out: string[] = [];
  let field = "";
  let inQuotes = false;
  for (let i = 0; i < row.length; i++) {
    const c = row[i]!;
    if (inQuotes) {
      if (c === '"') {
        if (row[i + 1] === '"') {
          field += '"';
          i++;
        } else inQuotes = false;
      } else field += c;
    } else if (c === '"') inQuotes = true;
    else if (c === ",") {
      out.push(field);
      field = "";
    } else field += c;
  }
  out.push(field);
  return out;
}

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
}): Pick<ExtractedData, "definitions" | "parties"> {
  return {
    parties: [],
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
    const r = await buildDefinitionsReport(extracted, EMPTY_TREE);
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
    const a = await buildDefinitionsReport(extracted, EMPTY_TREE);
    const b = await buildDefinitionsReport(extracted, EMPTY_TREE);
    expect(JSON.stringify(a)).toBe(JSON.stringify(b));
    expect(await verifyDefinitionsHash(a)).toBe(true);
    expect(await verifyDefinitionsHash({ ...a, unused: [] })).toBe(false);
  });

  // `definitions.ts` kept its own CSV escaper that quoted commas and quotes
  // but omitted the formula-injection guard the fix-list / obligations CSVs
  // have carried all along. Defined terms are verbatim document text, so a
  // term starting `=`, `+`, `-`, or `@` opened as a live formula in Excel.
  it("neutralizes a defined term that would open as a spreadsheet formula", async () => {
    const r = await buildDefinitionsReport(extracted, EMPTY_TREE);
    const poisoned: typeof r = {
      ...r,
      undefined_used: [
        { term: '=HYPERLINK("http://evil","click")', use_count: 2, positions: [] },
        ...r.undefined_used,
      ],
    };
    const row = buildDefinitionsCsv(poisoned).split("\r\n")[1]!;
    // The term cell must be inert text, not a formula: guarded with a leading
    // apostrophe (inside the RFC-4180 quoting the comma forces).
    expect(row).toContain(`"'=HYPERLINK`);
    expect(row.startsWith("undefined-but-used,=")).toBe(false);
  });

  it("renders CSV (risk-ordered, header first) and Markdown", async () => {
    const r = await buildDefinitionsReport(extracted, EMPTY_TREE);
    const csv = buildDefinitionsCsv(r);
    expect(csv.startsWith("bucket,term,detail,locations")).toBe(true);
    expect(csv.indexOf("undefined-but-used")).toBeLessThan(csv.indexOf("defined-but-unused"));
    const md = buildDefinitionsMarkdown(r);
    expect(md).toContain("## Definitions report");
    expect(md).toContain("Ghost Term");
    expect(md).toContain("definitions_hash");
  });

  it("ends its rows with CRLF, like every other CSV export in the tree", async () => {
    // It used bare LF, and nothing noticed while the browser was its only
    // consumer — a Blob handed to a download is never split on a line ending.
    const csv = buildDefinitionsCsv(await buildDefinitionsReport(extracted, EMPTY_TREE));
    expect(csv.includes("\r\n")).toBe(true);
    expect(/[^\r]\n/.test(csv)).toBe(false);
  });

  it("quotes the undefined-but-used detail so its literal comma keeps the row 4-field (RFC 4180)", async () => {
    const r = await buildDefinitionsReport(extracted, EMPTY_TREE);
    const csv = buildDefinitionsCsv(r);
    const row = csv.split("\r\n").find((l) => l.startsWith("undefined-but-used"))!;
    // The "N use(s), never defined" detail must be quoted, or its comma splits
    // the row into 5 fields and shifts the locations column.
    expect(row).toMatch(/"\d+ use\(s\), never defined"/);
    expect(parseCsvRow(row)).toHaveLength(4);
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
          const r = await buildDefinitionsReport(
            extractedWith({ entries, unused_terms: unused }),
            EMPTY_TREE,
          );
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
          parties: [],
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

/**
 * The "undefined-but-used" bucket is STRUCT-006's list, not the extractor's raw
 * one. A clean will's definitions CSV named the testator's husband, daughter
 * and sister, and its "Independent Executor", as undefined terms in the same
 * run whose findings exempted all four.
 */
describe("buildDefinitionsReport — one list of undefined terms", () => {
  const tree = buildTree([
    "Last Will and Testament of Margaret Ellen Doyle",
    "I give my jewelry to my daughter, Claire Anne Doyle, if she survives me.",
    "I appoint my spouse, Thomas James Doyle, as Independent Executor of this Will.",
    "If Thomas James Doyle fails to serve, I appoint my sister, Ruth Anne Keller, as successor Independent Executor.",
    "Claire Anne Doyle and Ruth Anne Keller shall share the Vacation Property equally.",
    "My Executor may sell the Vacation Property without court order.",
  ]);
  const extracted = extractAll(tree);

  it("prints exactly what STRUCT-006 reports", async () => {
    const r = await buildDefinitionsReport(extracted, tree);
    const bucket = r.undefined_used.map((u) => u.term);
    expect(bucket).toEqual(
      undefinedTermCandidates({ tree, extracted })
        .map((u) => u.term)
        .sort(),
    );
    // The raw list DOES carry the people and the office — the exemptions are
    // what this asserts, not an extractor that never saw them.
    expect(extracted.definitions.undefined_capitalized.map((u) => u.term)).toContain(
      "Independent Executor",
    );
    expect(bucket).not.toContain("Independent Executor");
    expect(bucket).not.toContain("Claire Anne Doyle");
    expect(bucket).toContain("Vacation Property");
  });
});

describe("used-before-defined — occurrences that are not uses", () => {
  const report = async (heading: string, ...paras: string[]) => {
    const tree = buildTree([heading, ...paras]);
    return buildDefinitionsReport(extractAll(tree), tree);
  };

  it("does not count the defining phrase, an inline heading, or a party's name", async () => {
    const r = await report(
      "Equipment Lease",
      'This Equipment Lease Agreement (this "Lease") is made between Ridgeway Equipment Rentals, Inc. ("Lessor") and Blue Heron Landscaping LLC ("Lessee").',
      '1. Lease of Equipment. Lessor leases to Lessee the equipment described in Schedule 1 (the "Equipment").',
      '2. Term. The term of this Lease begins on April 6, 2026 and ends on April 5, 2029 (the "Term"). Lessee shall use the Equipment during the Term.',
    );
    expect(r.used_before_defined.map((u) => u.term)).toEqual([]);
  });

  it("still reports a term used in an earlier section than its definition", async () => {
    const r = await report(
      "Purchase",
      "2. Price. The balance of the Purchase Price is payable at Closing.",
      '7. Closing. Closing shall take place on June 19, 2026 (the "Closing").',
    );
    expect(r.used_before_defined.map((u) => u.term)).toContain("Closing");
  });
});
