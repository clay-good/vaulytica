import { describe, expect, it } from "vitest";
import { buildClauseDiff, flattenClauses, MAX_CLAUSE_DIFF_CELLS } from "./clause-diff.js";
import type { DocumentTree } from "../ingest/types.js";

/** Build a minimal DocumentTree from sections of paragraph texts. */
function tree(sections: Array<{ heading: string; paras: string[] }>): DocumentTree {
  return {
    type: "document",
    sections: sections.map((s, si) => ({
      id: `s${si}`,
      heading: s.heading,
      level: 1,
      paragraphs: s.paras.map((t, pi) => ({
        id: `s${si}.p${pi}`,
        runs: [{ id: `s${si}.p${pi}.r0`, text: t, start: 0, end: t.length }],
      })),
      children: [],
    })),
  };
}

/** A single-section document from a list of paragraph texts. */
const doc = (...paras: string[]): DocumentTree => tree([{ heading: "Agreement", paras }]);

describe("flattenClauses", () => {
  it("emits one clause per non-empty paragraph, tagged with the section heading", () => {
    const clauses = flattenClauses(tree([{ heading: "Term", paras: ["One.", "  ", "Two."] }]));
    expect(clauses).toHaveLength(2); // the whitespace-only paragraph is dropped
    expect(clauses[0]).toMatchObject({ heading: "Term", text: "One.", id: "s0.p0" });
    expect(clauses[1]!.text).toBe("Two.");
  });

  it("inherits the nearest enclosing heading for child sections", () => {
    const t: DocumentTree = {
      type: "document",
      sections: [
        {
          id: "s0",
          heading: "Liability",
          level: 1,
          paragraphs: [{ id: "s0.p0", runs: [{ id: "r", text: "Cap applies.", start: 0, end: 12 }] }],
          children: [
            {
              id: "s0.0",
              heading: "", // unheaded subsection inherits "Liability"
              level: 2,
              paragraphs: [{ id: "s0.0.p0", runs: [{ id: "r", text: "Carveout.", start: 0, end: 9 }] }],
              children: [],
            },
          ],
        },
      ],
    };
    const clauses = flattenClauses(t);
    expect(clauses.map((c) => c.heading)).toEqual(["Liability", "Liability"]);
    expect(clauses.map((c) => c.text)).toEqual(["Cap applies.", "Carveout."]);
  });
});

describe("buildClauseDiff", () => {
  it("reports no changes for identical documents", () => {
    const d = buildClauseDiff(doc("A", "B", "C"), doc("A", "B", "C"));
    expect(d.added).toEqual([]);
    expect(d.removed).toEqual([]);
    expect(d.changed).toEqual([]);
    expect(d.unchanged_count).toBe(3);
    expect(d.truncated).toBe(false);
  });

  it("ignores whitespace-only reflow", () => {
    const d = buildClauseDiff(doc("The   fee  is due."), doc("The fee is due."));
    expect(d.unchanged_count).toBe(1);
    expect(d.added).toEqual([]);
    expect(d.removed).toEqual([]);
    expect(d.changed).toEqual([]);
  });

  it("detects a pure insertion", () => {
    const d = buildClauseDiff(doc("A", "C"), doc("A", "B", "C"));
    expect(d.added.map((c) => c.text)).toEqual(["B"]);
    expect(d.removed).toEqual([]);
    expect(d.changed).toEqual([]);
    expect(d.unchanged_count).toBe(2);
  });

  it("detects a pure deletion", () => {
    const d = buildClauseDiff(doc("A", "B", "C"), doc("A", "C"));
    expect(d.removed.map((c) => c.text)).toEqual(["B"]);
    expect(d.added).toEqual([]);
    expect(d.changed).toEqual([]);
    expect(d.unchanged_count).toBe(2);
  });

  it("pairs a replaced clause as a single change", () => {
    const d = buildClauseDiff(
      doc("Liability is capped at $1,000,000.", "Governing law is Delaware."),
      doc("Liability is capped at $5,000,000.", "Governing law is Delaware."),
    );
    expect(d.changed).toHaveLength(1);
    expect(d.changed[0]!.base.text).toContain("$1,000,000");
    expect(d.changed[0]!.revised.text).toContain("$5,000,000");
    expect(d.added).toEqual([]);
    expect(d.removed).toEqual([]);
    expect(d.unchanged_count).toBe(1);
  });

  it("treats an unbalanced replace block as paired + surplus", () => {
    // base has 1 clause where revised has 2 → 1 changed pair + 1 added.
    const d = buildClauseDiff(doc("X", "OLD", "Y"), doc("X", "NEW1", "NEW2", "Y"));
    expect(d.changed).toHaveLength(1);
    expect(d.changed[0]!.base.text).toBe("OLD");
    expect(d.changed[0]!.revised.text).toBe("NEW1");
    expect(d.added.map((c) => c.text)).toEqual(["NEW2"]);
    expect(d.removed).toEqual([]);
  });

  it("keeps a moved clause out of added/removed when it still matches", () => {
    // C moved earlier; LCS keeps the longest common run (A,B) and treats the
    // move as one remove + one add, never a spurious 'changed'.
    const d = buildClauseDiff(doc("A", "B", "C"), doc("C", "A", "B"));
    expect(d.unchanged_count).toBe(2); // A, B
    expect([...d.added, ...d.removed].map((c) => c.text).sort()).toEqual(["C", "C"]);
    expect(d.changed).toEqual([]);
  });

  it("handles empty documents", () => {
    const d = buildClauseDiff(doc(), doc("A"));
    expect(d.added.map((c) => c.text)).toEqual(["A"]);
    expect(d.base_clause_count).toBe(0);
    expect(d.revised_clause_count).toBe(1);
  });

  it("is deterministic: identical inputs → identical output", () => {
    const a = doc("A", "OLD", "C");
    const b = doc("A", "NEW", "C", "D");
    expect(buildClauseDiff(a, b)).toEqual(buildClauseDiff(a, b));
  });

  it("degrades to a bounded set-based diff past the cell ceiling", () => {
    // Two documents large enough that (n+1)(m+1) > MAX_CLAUSE_DIFF_CELLS.
    const n = Math.ceil(Math.sqrt(MAX_CLAUSE_DIFF_CELLS)) + 1; // ~2001 each
    const base = Array.from({ length: n }, (_, i) => `clause ${i}`);
    const revised = [...base, "a brand new clause"];
    const d = buildClauseDiff(doc(...base), doc(...revised));
    expect(d.truncated).toBe(true);
    expect(d.changed).toEqual([]); // no alignment in the fallback
    expect(d.added.map((c) => c.text)).toEqual(["a brand new clause"]);
    expect(d.unchanged_count).toBe(n);
  });
});
