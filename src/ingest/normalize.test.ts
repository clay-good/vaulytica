import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import type { DocumentTree } from "./types.js";
import { countWords, normalize, noTextWarning } from "./normalize.js";
import { flattenText } from "./types.js";

const treeOf = (heading: string, paragraphs: string[][]): DocumentTree => ({
  type: "document",
  sections: [
    {
      id: "",
      heading,
      level: 1,
      paragraphs: paragraphs.map((runs) => ({
        id: "",
        runs: runs.map((text) => ({ id: "", text, start: 0, end: 0 })),
      })),
      children: [],
    },
  ],
});

describe("normalize", () => {
  it("assigns stable, document-order ids", () => {
    const tree: DocumentTree = {
      type: "document",
      sections: [
        {
          id: "x",
          heading: "Top",
          level: 1,
          paragraphs: [{ id: "y", runs: [{ id: "z", text: "hello", start: 0, end: 0 }] }],
          children: [
            {
              id: "ignored",
              heading: "Sub",
              level: 2,
              paragraphs: [{ id: "y", runs: [{ id: "z", text: "world", start: 0, end: 0 }] }],
              children: [],
            },
          ],
        },
      ],
    };
    const out = normalize(tree);
    expect(out.sections[0]!.id).toBe("s1");
    expect(out.sections[0]!.paragraphs[0]!.id).toBe("s1.p0");
    expect(out.sections[0]!.paragraphs[0]!.runs[0]!.id).toBe("s1.p0.r0");
    expect(out.sections[0]!.children[0]!.id).toBe("s1.1");
  });

  it("collapses runs of whitespace inside runs", () => {
    const out = normalize(treeOf("H", [["foo   bar\tbaz\n\nqux"]]));
    expect(out.sections[0]!.paragraphs[0]!.runs[0]!.text).toBe("foo bar baz qux");
  });

  it("drops empty runs and empty paragraphs", () => {
    const out = normalize(treeOf("H", [[""], ["  "], ["real"]]));
    expect(out.sections[0]!.paragraphs).toHaveLength(1);
    expect(out.sections[0]!.paragraphs[0]!.runs[0]!.text).toBe("real");
  });

  it("keeps the separating space when a whitespace-only run sits between two words", () => {
    // A lone space inside a formatting/tracked-change span ("does not<b> </b>
    // include") arrives as an isolated whitespace-only run. Dropping it fused
    // the neighbouring words ("does notinclude"), defeating downstream regexes.
    const out = normalize(treeOf("H", [["does not", " ", "include"]]));
    expect(flattenText(out)).toBe("H\ndoes not include\n");
    // Offsets stay contiguous across the run that absorbed the space.
    const runs = out.sections[0]!.paragraphs[0]!.runs;
    expect(runs[0]!.end).toBe(runs[1]!.start);
  });

  it("still drops a leading or trailing whitespace-only run (no stray edge space)", () => {
    const lead = normalize(treeOf("H", [[" ", "real"]]));
    expect(flattenText(lead)).toBe("H\nreal\n");
    const trail = normalize(treeOf("H", [["real", " "]]));
    expect(flattenText(trail)).toBe("H\nreal\n");
  });

  it("does not double a space when a neighbour already carries one", () => {
    const out = normalize(treeOf("H", [["does not ", " ", "include"]]));
    expect(flattenText(out)).toBe("H\ndoes not include\n");
  });

  it("assigns contiguous offsets per run, exclusive end", () => {
    const out = normalize(treeOf("H", [["hello", " world"]]));
    const runs = out.sections[0]!.paragraphs[0]!.runs;
    expect(runs).toHaveLength(2);
    expect(runs[0]!.start).toBeLessThan(runs[0]!.end);
    expect(runs[0]!.end).toBe(runs[1]!.start);
    expect(runs[1]!.end - runs[1]!.start).toBe(runs[1]!.text.length);
  });

  it("is idempotent", () => {
    const once = normalize(treeOf("Title", [["foo   bar"], ["baz"]]));
    const twice = normalize(once);
    expect(twice).toEqual(once);
  });

  it("strips mid-word zero-width and soft-hyphen format characters so a word rejoins", () => {
    // Word/PDF line-wrapping injects these mid-word; JS `\s` does NOT match
    // them, so left in place they split a word for every downstream literal
    // regex — silently defeating a presence disclaimer into a false accusation.
    const cases: Array<[string, string]> = [
      ["does not in\u00ADclude", "does not include"], // SOFT HYPHEN
      ["does not in\u200Bclude", "does not include"], // ZERO WIDTH SPACE
      ["ter\u200Cmi\u200Dnate", "terminate"], // ZWNJ + ZWJ
      ["word\u2060joiner", "wordjoiner"], // WORD JOINER
    ];
    for (const [input, expected] of cases) {
      const out = normalize(treeOf("H", [[input]]));
      expect(out.sections[0]!.paragraphs[0]!.runs[0]!.text).toBe(expected);
    }
  });

  it("still folds true whitespace (NBSP, ideographic space) to a single space", () => {
    const out = normalize(treeOf("H", [["a\u00A0\u3000b"]]));
    expect(out.sections[0]!.paragraphs[0]!.runs[0]!.text).toBe("a b");
  });

  it("strips XML-illegal C0/DEL control characters (OCR/PDF artifacts)", () => {
    // #x1, #x1F, #x7F are forbidden by the XML 1.0 Char production; left in the
    // text they corrupt the DOCX report / reviewed copy. \t/\n are legal and,
    // with #xB/#xC, fold to a space via the \s collapse \u2014 never dropped.
    const c = String.fromCharCode;
    const dirty = "before" + c(0x01) + "mid" + c(0x1f) + "end" + c(0x7f) + "tail";
    const out = normalize(treeOf("H", [[dirty]]));
    expect(out.sections[0]!.paragraphs[0]!.runs[0]!.text).toBe("beforemidendtail");
    const vtff = "a" + c(0x0b) + "b" + c(0x0c) + "c";
    const legal = normalize(treeOf("H", [[vtff]])); // VT, FF \u2192 space
    expect(legal.sections[0]!.paragraphs[0]!.runs[0]!.text).toBe("a b c");
  });

  it("strips format and control characters from a HEADING, not just from runs", () => {
    // The heading used to get only the `\s+` collapse, so a soft hyphen or a
    // zero-width joiner injected mid-word by Word/PDF survived in it while the
    // identical string in a run was cleaned. That matters twice over: the v4
    // classifier matches document families by `headings.includes(keyword)`, so
    // an invisible U+00AD inside "Con[shy]fidentiality" silently loses the
    // match; and a C0 byte in a heading corrupts the DOCX report exactly as it
    // would from a run.
    const c = String.fromCharCode;
    const dirty = "Con\u00adfi\u200bdentiality" + c(0x01);
    const out = normalize(treeOf(dirty, [["body"]]));
    expect(out.sections[0]!.heading).toBe("Confidentiality");
  });

  it("leaves a clean heading byte-identical (no offset churn)", () => {
    // The guard on the fix above: normalizing headings must not move the offset
    // stream for any document that did not carry a format/control character.
    const out = normalize(treeOf("Section 1. Confidentiality", [["body"]]));
    expect(out.sections[0]!.heading).toBe("Section 1. Confidentiality");
  });
});

describe("countWords", () => {
  it("counts heading and body words", () => {
    expect(countWords(treeOf("Title Here", [["four words in body"]]))).toBe(6);
  });
});

describe("flattenText", () => {
  it("includes heading and body in order", () => {
    const t = normalize(treeOf("H", [["a b"], ["c"]]));
    expect(flattenText(t)).toContain("H");
    expect(flattenText(t)).toContain("a b");
    expect(flattenText(t)).toContain("c");
  });
});

describe("footnote markers", () => {
  const text = (t: DocumentTree): string =>
    t.sections
      .flatMap((s) => s.paragraphs.map((p) => p.runs.map((r) => r.text).join("")))
      .join("\n");
  const doc = (s: string): DocumentTree => ({
    type: "document",
    sections: [
      {
        id: "",
        heading: "",
        level: 1,
        paragraphs: [
          { id: "", runs: [{ id: "", text: s, start: 0, end: s.length, formatting: {} }] },
        ],
        children: [],
      },
    ],
  });

  it("removes a marker that follows sentence punctuation", () => {
    expect(text(normalize(doc("The fee is due.\u00B9 Payment follows.")))).toBe(
      "The fee is due. Payment follows.",
    );
  });

  it("keeps a superscript attached to a word — it is an exponent or a unit", () => {
    expect(text(normalize(doc("The premises are 500 m\u00B2 and the load is 10\u00B2 kg.")))).toBe(
      "The premises are 500 m\u00B2 and the load is 10\u00B2 kg.",
    );
  });
});

/**
 * One owner for the empty-document caveat, called by every ingest path — a
 * DOCX of only images and a PDF whose text layer came back blank need the same
 * sentence as an empty paste.
 */
describe("noTextWarning", () => {
  it("is silent for any document with words", () => {
    expect(noTextWarning(1)).toEqual([]);
    expect(noTextWarning(50_000)).toEqual([]);
  });

  it("speaks exactly once for a document with none", () => {
    expect(noTextWarning(0)).toHaveLength(1);
    expect(noTextWarning(0)[0]).toContain("No readable text was found");
  });
});

/**
 * 🚨 WHAT NORMALIZE IS ALLOWED TO FORGET.
 *
 * `normalize` REBUILDS every node — `normalizeParagraph` returns a fresh
 * `{ id, runs, … }` — so any field it does not name is silently dropped. That
 * happened: `min_size_pt` was eaten, which is why the DOCX ingest attaches
 * sizes AFTER normalizing (`attachSizes`) instead of setting them inline, and
 * why the PDF ingest, which does set them inline, got nothing through until
 * 9.1001.0. The workaround made the field look like it worked and left the
 * hole open for the next producer.
 *
 * These cases close the class rather than that instance. The table below is
 * the decision, per field, about what normalization does with it; a field
 * added to `Run`, `Paragraph` or `Section` and not listed here fails by name,
 * which is the prompt to decide whether it is carried or re-derived — not a
 * formality, because getting it wrong is invisible at runtime.
 */
describe("normalize preserves every field it does not re-derive", () => {
  /** What normalization does with each declared field of the tree types. */
  const DISPOSITION: Readonly<Record<string, Readonly<Record<string, string>>>> = {
    Run: {
      id: "re-derived (makeRunId, from position)",
      text: "normalized (whitespace, format/control characters)",
      start: "re-derived (contiguous offset stream)",
      end: "re-derived (contiguous offset stream)",
      formatting: "carried",
    },
    Paragraph: {
      id: "re-derived (makeParagraphId, from position)",
      runs: "rebuilt, each run per the Run row",
      min_size_pt: "carried — what the FILE said about how its text is set",
      displayed_caps: "carried — same reason: the file's own rendering, not text",
    },
    Section: {
      id: "re-derived (makeSectionId, from path)",
      heading: "normalized, exactly as run text is",
      level: "carried",
      paragraphs: "rebuilt, each paragraph per the Paragraph row",
      children: "rebuilt recursively",
    },
  };

  const SOURCE = readFileSync(join(process.cwd(), "src", "ingest", "types.ts"), "utf8");

  /** The field names declared in `export type <name> = { … }`. */
  function declaredFields(typeName: string): string[] {
    const start = SOURCE.indexOf(`export type ${typeName} = {`);
    expect(start, `no "export type ${typeName}" in src/ingest/types.ts`).toBeGreaterThan(-1);
    const end = SOURCE.indexOf("\n};", start);
    const body = SOURCE.slice(start, end);
    // Field lines only: two-space indent, a name, an optional `?`, then `:`.
    return [...body.matchAll(/^ {2}(\w+)\??:/gm)].map((m) => m[1]!);
  }

  it("has a recorded decision for every declared field", () => {
    for (const [typeName, table] of Object.entries(DISPOSITION)) {
      const declared = declaredFields(typeName);
      expect(declared.length, `parsed no fields for ${typeName}`).toBeGreaterThan(1);
      const undecided = declared.filter((f) => !(f in table)).sort();
      expect(
        undecided,
        `src/ingest/types.ts: ${typeName} declares ${undecided.join(", ")}, and normalize.ts has ` +
          `no recorded decision about ${undecided.length === 1 ? "it" : "them"}. normalize() ` +
          `rebuilds every node, so a field it does not name is DROPPED — silently, at runtime. ` +
          `Carry it in normalizeParagraph / normalizeSection and add it to DISPOSITION here, or ` +
          `record that it is re-derived.`,
      ).toEqual([]);
      // A stale row is worse than none: it claims cover the type no longer has.
      const gone = Object.keys(table)
        .filter((f) => !declared.includes(f))
        .sort();
      expect(gone, `DISPOSITION lists ${typeName}.${gone.join(", ")}, no longer declared`).toEqual(
        [],
      );
    }
  });

  it("carries min_size_pt and formatting through, and re-derives ids and offsets", () => {
    const normalized = normalize({
      type: "document",
      sections: [
        {
          id: "junk",
          heading: "ARTICLE I",
          level: 3,
          paragraphs: [
            {
              id: "junk",
              runs: [
                { id: "junk", text: "Set small.", start: 99, end: 99, formatting: { bold: true } },
              ],
              min_size_pt: 8,
            },
            // No size stated: it must stay ABSENT, not become 0 or inherit 8.
            { id: "junk", runs: [{ id: "junk", text: "No size here.", start: 99, end: 99 }] },
          ],
          children: [],
        },
      ],
    });

    const section = normalized.sections[0]!;
    expect(section.level, "level is carried, not recomputed").toBe(3);
    const [small, sizeless] = section.paragraphs;

    expect(small!.min_size_pt, "min_size_pt was dropped by normalize").toBe(8);
    expect(small!.runs[0]!.formatting).toEqual({ bold: true });
    expect(
      sizeless!.min_size_pt,
      "a paragraph with no stated size must stay absent",
    ).toBeUndefined();

    // …and the fields normalize OWNS are re-derived, not passed through.
    expect(section.id).toBe("s1");
    expect(small!.id).toBe("s1.p0");
    expect(small!.runs[0]!.id).toBe("s1.p0.r0");
    expect(small!.runs[0]!.start).toBe(flattenText(normalized).indexOf("Set small."));
  });

  it("keeps the size when whitespace normalization rewrites the paragraph's runs", () => {
    // The field has to survive the path that REBUILDS runs, not just the quiet
    // one: a whitespace-only run between two words is the case that merges runs.
    const normalized = normalize({
      type: "document",
      sections: [
        {
          id: "",
          heading: "",
          level: 1,
          paragraphs: [
            {
              id: "",
              runs: [
                { id: "", text: "does not", start: 0, end: 0 },
                { id: "", text: " ", start: 0, end: 0 },
                { id: "", text: "include", start: 0, end: 0 },
              ],
              min_size_pt: 9,
            },
          ],
          children: [],
        },
      ],
    });
    const p = normalized.sections[0]!.paragraphs[0]!;
    expect(p.runs.map((r) => r.text).join("")).toBe("does not include");
    expect(p.min_size_pt).toBe(9);
  });

  it("is still idempotent with the field set", () => {
    const once = normalize(treeOf("H", [["Body text."]]));
    once.sections[0]!.paragraphs[0]!.min_size_pt = 7;
    const twice = normalize(once);
    expect(twice).toEqual(once);
  });
});
