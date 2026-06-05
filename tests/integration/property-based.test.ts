import { describe, expect, it, vi } from "vitest";
import fc from "fast-check";
import { normalize } from "../../src/ingest/normalize.js";
import { extractAmounts } from "../../src/extract/amounts.js";
import { extractDates } from "../../src/extract/dates.js";
import { buildTree } from "../../src/extract/_fixtures.js";
import type { DocumentTree, Run, Section } from "../../src/ingest/types.js";

/**
 * spec-v7 Part X (Step 118) — property-based testing.
 *
 * Every other test in the suite is example-based: it proves the inputs the
 * author wrote down. These prove invariants over inputs *no* author wrote down
 * — the properties that should hold for the whole input space, not a handful of
 * fixtures. The targets are the foundational layers everything downstream reads:
 * the normalizer (which every extractor consumes) and the amount/date extractors
 * (which the highest-value financial and temporal rules depend on).
 *
 * Determinism: a fixed seed + fixed run count means the same inputs are
 * generated on every machine and every run, so a failure reproduces exactly —
 * the same contract the rest of the engine honors (a property test that drew
 * fresh random inputs each run would be a non-deterministic gate, which this
 * codebase forbids).
 */

// Generating + normalizing hundreds of recursive trees runs well past vitest's
// 5s default, especially under V8 coverage instrumentation. Give it room (the
// same lesson the pdfjs cold-load test learned): a property gate must never go
// red on a slow CI runner instead of on a real counterexample.
vi.setConfig({ testTimeout: 30_000 });

const SEED = 0x7a17e;
const RUNS = 100;
const opts = { seed: SEED, numRuns: RUNS } as const;

// A realistic legal-text charset: letters, digits, the whitespace the
// normalizer explicitly handles ([ \t\r\n]), and common punctuation. Kept to
// the domain the linter actually operates on (no exotic Unicode), so the
// properties test real behavior rather than chasing out-of-domain edge cases.
const charArb = fc.constantFrom(...[..."abcdefg ABCDEFG 0123456789 \t\n\r.,;:()$%-"]);
const textArb = fc.array(charArb, { maxLength: 24 }).map((a) => a.join(""));

const runArb = fc.record({
  id: fc.constant(""),
  text: textArb,
  start: fc.constant(0),
  end: fc.constant(0),
});
const paraArb = fc.record({
  id: fc.constant(""),
  runs: fc.array(runArb, { maxLength: 4 }),
});
const { section: sectionArb } = fc.letrec<{ section: Section }>((tie) => ({
  section: fc.record({
    id: fc.constant(""),
    heading: fc.oneof(fc.constant(""), textArb),
    level: fc.integer({ min: 1, max: 3 }),
    paragraphs: fc.array(paraArb, { maxLength: 3 }),
    children: fc.array(tie("section"), { maxLength: 2 }),
  }),
}));
const treeArb: fc.Arbitrary<DocumentTree> = fc.record({
  type: fc.constant("document" as const),
  sections: fc.array(sectionArb, { maxLength: 3 }),
});

function flattenRuns(tree: DocumentTree): Run[] {
  const out: Run[] = [];
  const walk = (sections: Section[]): void => {
    for (const s of sections) {
      for (const p of s.paragraphs) for (const r of p.runs) out.push(r);
      walk(s.children);
    }
  };
  walk(tree.sections);
  return out;
}

describe("normalize — structural invariants (spec-v7 Step 118)", () => {
  it("is idempotent: normalize(normalize(t)) deep-equals normalize(t)", () => {
    fc.assert(
      fc.property(treeArb, (t) => {
        const once = normalize(t);
        expect(normalize(once)).toEqual(once);
      }),
      opts,
    );
  });

  it("assigns exact, contiguous, non-overlapping offsets (end - start === text.length)", () => {
    fc.assert(
      fc.property(treeArb, (t) => {
        const runs = flattenRuns(normalize(t));
        let prevEnd = -1;
        for (const r of runs) {
          expect(r.end - r.start).toBe(r.text.length);
          expect(r.start).toBeGreaterThanOrEqual(prevEnd); // monotonic, never overlapping
          prevEnd = r.end;
        }
      }),
      opts,
    );
  });

  it("drops empty and whitespace-only runs and paragraphs", () => {
    fc.assert(
      fc.property(treeArb, (t) => {
        const n = normalize(t);
        for (const r of flattenRuns(n)) {
          expect(r.text.length).toBeGreaterThan(0);
          expect(r.text).not.toBe(" ");
        }
        const walk = (ss: Section[]): void => {
          for (const s of ss) {
            for (const p of s.paragraphs) expect(p.runs.length).toBeGreaterThan(0);
            walk(s.children);
          }
        };
        walk(n.sections);
      }),
      opts,
    );
  });
});

describe("extractors — round-trip properties (spec-v7 Step 118)", () => {
  it("a US-dollar integer round-trips through extractAmounts", () => {
    fc.assert(
      fc.property(fc.integer({ min: 1, max: 9_999_999 }), (n) => {
        // US grouping (commas, no decimals) is exactly what the NUMERIC regex
        // accepts; the extractor strips commas, so the decimal is the integer.
        const formatted = n.toLocaleString("en-US");
        const amounts = extractAmounts(buildTree(["Fees", `The total is $${formatted}.`]));
        expect(amounts.some((a) => a.amount === String(n) && a.currency === "USD")).toBe(true);
      }),
      opts,
    );
  });

  it("a valid ISO date round-trips through extractDates", () => {
    const pad = (x: number): string => String(x).padStart(2, "0");
    fc.assert(
      fc.property(
        fc.integer({ min: 1900, max: 2099 }),
        fc.integer({ min: 1, max: 12 }),
        fc.integer({ min: 1, max: 28 }), // 1..28 is valid in every month, leap year or not
        (y, mo, d) => {
          const iso = `${y}-${pad(mo)}-${pad(d)}`;
          const dates = extractDates(buildTree(["Term", `This is dated ${iso} accordingly.`]));
          expect(dates.some((dr) => dr.iso === iso)).toBe(true);
        },
      ),
      opts,
    );
  });
});
