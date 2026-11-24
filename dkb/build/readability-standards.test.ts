/**
 * The `readability_standards` DKB table and its build-time gate
 * (add-readability-measure task 3's remaining half).
 *
 * Sibling to `mandated-texts.test.ts`, and for the same reason: a test beside
 * the source guards the rows where they are written, but the DKB is what SHIPS
 * and what the weekly rebuild regenerates. A gate inside `runBuild` can refuse
 * to WRITE a standard nobody can trace; a test alone cannot.
 *
 * Every defect the gate claims to catch is driven here against a row that has
 * it, because a gate that cannot fail is not one.
 */
import { describe, expect, it } from "vitest";
import {
  assertReadabilityStandardsUsable,
  buildReadabilityStandards,
  readabilityStandardDefects,
} from "./readability-standards.js";
import { READABILITY_STANDARDS } from "../../src/readability/standards.js";
import type { ReadabilityStandardEntry } from "../../src/dkb/types.js";

const rows = buildReadabilityStandards();
/** Florida: a plain score standard, used as the base for each defect case. */
const good = (): ReadabilityStandardEntry => structuredClone(rows.find((r) => r.id === "fl")!);

describe("the table built from the committed rows", () => {
  it("carries every jurisdiction, and passes its own gate as committed", () => {
    expect(rows.length).toBe(READABILITY_STANDARDS.length);
    expect(rows.length, "no rows — every assertion would be vacuous").toBeGreaterThan(10);
    expect(readabilityStandardDefects(rows)).toEqual([]);
    expect(() => assertReadabilityStandardsUsable(rows)).not.toThrow();
  });

  it("is sorted by id, so the file and its manifest hash are stable", () => {
    expect(rows.map((r) => r.id)).toEqual([...rows.map((r) => r.id)].sort());
  });

  it("carries the score-less New York row without inventing a threshold", () => {
    // § 5-702 sets no Flesch minimum. The table must say so by OMITTING the
    // field, not by storing a zero or a default that a finding could quote.
    const ny = rows.find((r) => r.id === "ny-consumer");
    expect(ny, "the ny-consumer row is missing").toBeDefined();
    expect(ny!.min_score).toBeUndefined();
    expect(ny!.captions_required).toBe(true);
    expect(ny!.not_measured).toContain("clear and coherent");
    expect(ny!.max_amount).toBe(250_000);
  });

  it("every row names an official source and a read date", () => {
    for (const r of rows) {
      expect(() => new URL(r.source_url), r.id).not.toThrow();
      expect(r.retrieved_at, r.id).toMatch(/^\d{4}-\d{2}-\d{2}$/);
      expect(r.version.length, r.id).toBeGreaterThan(0);
      expect(r.scope.length, r.id).toBeGreaterThan(10);
    }
  });
});

describe("the gate refuses a standard it cannot vouch for", () => {
  const cases: Array<[string, (r: ReadabilityStandardEntry) => void, RegExp]> = [
    ["no citation", (r) => void (r.citation = " "), /has no citation/],
    ["no name", (r) => void (r.name = ""), /has no name/],
    ["an unusable source_url", (r) => void (r.source_url = "nope"), /unusable source_url/],
    ["no read date", (r) => void (r.retrieved_at = "soon"), /no read date/],
    ["no version history", (r) => void (r.version = ""), /records no version history/],
    ["no scope", (r) => void (r.scope = ""), /states no scope/],
    ["a Flesch minimum outside 0–100", (r) => void (r.min_score = 120), /outside 0–100/],
    [
      "no requirement at all",
      (r) => {
        delete r.min_score;
        delete r.contents_over;
        delete r.captions_required;
      },
      /sets no score, no contents requirement and no captions requirement/,
    ],
  ];

  for (const [label, break_, expected] of cases) {
    it(`refuses ${label}`, () => {
      const row = good();
      break_(row);
      const defects = readabilityStandardDefects([row]);
      expect(defects.length, `${label} was accepted`).toBeGreaterThan(0);
      expect(defects.map((d) => d.problem).join(" | ")).toMatch(expected);
      expect(() => assertReadabilityStandardsUsable([row])).toThrow(/refuses/);
    });
  }

  it("refuses a score-less row that records nothing it does not measure", () => {
    // The honesty case. A standard with no threshold must say what it DOES
    // require, or a reader is left with a citation and no obligation.
    const row = good();
    delete row.min_score;
    row.contents_over = { words: 3000, pages: 3 };
    delete row.not_measured;
    expect(readabilityStandardDefects([row]).map((d) => d.problem)).toContain(
      "sets no score and records nothing it does not measure",
    );
  });

  it("refuses a duplicate id, and names every defect at once", () => {
    expect(readabilityStandardDefects([good(), good()]).map((d) => d.problem)).toContain(
      "is a duplicate id",
    );
    const row = good();
    row.citation = "";
    row.version = "";
    row.scope = "";
    expect(readabilityStandardDefects([row]).length).toBeGreaterThanOrEqual(3);
  });
});
