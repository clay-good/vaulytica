/**
 * The `mandated_texts` table and its build-time gate
 * (add-mandated-text-conformance task 2's schema and validation test).
 *
 * The rows were already guarded by `mandated-texts.test.ts` beside the rules.
 * This is the other half: the DKB is what SHIPS and what the weekly rebuild
 * regenerates, so the check has to be able to refuse a WRITE, not only fail a
 * test run in a repository a bad row has already reached.
 *
 * A gate is only worth having if it can fail, so every defect it claims to
 * catch is driven here against a row that has it.
 */
import { describe, expect, it } from "vitest";
import {
  assertMandatedTextsUsable,
  buildMandatedTexts,
  mandatedTextDefects,
  normalizeMandated,
} from "./mandated-texts.js";
import { MANDATED_TEXTS } from "../../src/engine/rules/text/mandated-texts.js";
import type { MandatedTextEntry } from "../../src/dkb/types.js";

const rows = buildMandatedTexts();
const good = (): MandatedTextEntry => structuredClone(rows[0]!);

describe("the table built from the committed rows", () => {
  it("carries every row and every variant, with a digest each", () => {
    expect(rows.length).toBe(MANDATED_TEXTS.length);
    expect(rows.length, "no rows — every assertion here would be vacuous").toBeGreaterThan(1);
    const variants = MANDATED_TEXTS.reduce((n, r) => n + r.variants.length, 0);
    expect(rows.reduce((n, r) => n + r.variants.length, 0)).toBe(variants);
    for (const row of rows) {
      for (const v of row.variants) {
        expect(v.content_sha256, `${row.id} ${v.where}`).toMatch(/^[0-9a-f]{64}$/);
      }
    }
  });

  it("is sorted by id, so the file and its hash are stable", () => {
    // The manifest records a sha256 of this file; an unstable order would
    // churn it on every build and make a real change indistinguishable.
    expect(rows.map((r) => r.id)).toEqual([...rows.map((r) => r.id)].sort());
  });

  it("passes its own gate as committed", () => {
    expect(mandatedTextDefects(rows)).toEqual([]);
    expect(() => assertMandatedTextsUsable(rows)).not.toThrow();
  });

  it("digests the whitespace-normalized text, so reflowing a literal is not a change", () => {
    expect(normalizeMandated("NOTICE  ANY\n HOLDER")).toBe("NOTICE ANY HOLDER");
  });
});

describe("the gate refuses a row it cannot vouch for", () => {
  /** Every defect, driven against a row that has it. */
  const cases: Array<[string, (r: MandatedTextEntry) => void, RegExp]> = [
    ["no citation", (r) => void (r.citation = "  "), /has no citation/],
    ["no name", (r) => void (r.name = ""), /has no name/],
    ["an unusable source_url", (r) => void (r.source_url = "not a url"), /unusable source_url/],
    [
      "a read date that is not a date",
      (r) => void (r.retrieved_at = "last Tuesday"),
      /no read date/,
    ],
    ["no version history", (r) => void (r.version = ""), /records no version history/],
    ["no variants", (r) => void (r.variants = []), /has no variants/],
    [
      "a variant naming no subsection",
      (r) => void (r.variants = [{ ...r.variants[0]!, where: "" }]),
      /names no subsection/,
    ],
    [
      "a variant too short to be a passage",
      (r) => void (r.variants = [{ ...r.variants[0]!, text: "NOTICE" }]),
      /too short to be a mandated passage/,
    ],
    [
      "a digest that does not match its own text",
      (r) =>
        void (r.variants = [
          { ...r.variants[0]!, text: `${r.variants[0]!.text} AND MORE WORDS HERE` },
        ]),
      /content_sha256 does not match/,
    ],
  ];

  for (const [label, break_, expected] of cases) {
    it(`refuses ${label}`, () => {
      const row = good();
      break_(row);
      const defects = mandatedTextDefects([row]);
      expect(defects.length, `${label} was accepted`).toBeGreaterThan(0);
      expect(defects.map((d) => d.problem).join(" | ")).toMatch(expected);
      expect(() => assertMandatedTextsUsable([row])).toThrow(/refuses/);
    });
  }

  it("refuses a duplicate id", () => {
    const defects = mandatedTextDefects([good(), good()]);
    expect(defects.map((d) => d.problem)).toContain("is a duplicate id");
  });

  it("names EVERY defect, not just the first", () => {
    // One build should tell a maintainer about all of them rather than one
    // per run.
    const row = good();
    row.citation = "";
    row.version = "";
    row.retrieved_at = "";
    expect(mandatedTextDefects([row]).length).toBeGreaterThanOrEqual(3);
  });
});
