/**
 * Mutation-scope config guard.
 *
 * Stryker's `mutate` list (stryker.config.json) and the test `include` list
 * (vitest.mutation.config.ts) are two hand-maintained lists that have to name
 * the same set of modules. Adding a file to `mutate` without adding its test
 * file to `include` does not fail loudly — the file reports 0% with every
 * mutant marked "NoCoverage", which reads as a catastrophic coverage collapse
 * when in fact the tests exist and simply never ran. That happened while
 * widening the scope from two extractors to four, and it drags the aggregate
 * under the break threshold, failing the scheduled job for a config reason.
 *
 * So: every mutated `src/**\/x.ts` must have `src/**\/x.test.ts` included, and
 * nothing may be included that is not mutated.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const root = process.cwd();
const stryker = JSON.parse(readFileSync(join(root, "stryker.config.json"), "utf8")) as {
  mutate: string[];
  thresholds: { break: number };
};
const mutationConfig = readFileSync(join(root, "vitest.mutation.config.ts"), "utf8");
const baselineDoc = readFileSync(join(root, "docs", "v7", "mutation-baseline.md"), "utf8");

/** The string literals inside the config's `include: [...]` array. */
function includedTestFiles(source: string): string[] {
  const block = /include:\s*\[([^\]]*)\]/s.exec(source);
  if (!block) return [];
  return [...block[1]!.matchAll(/"([^"]+)"/g)].map((m) => m[1]!);
}

describe("mutation scope", () => {
  const included = includedTestFiles(mutationConfig);

  it("parses a non-empty include list (guards the regex itself)", () => {
    expect(included.length).toBeGreaterThan(0);
  });

  it("includes the test file of every mutated module", () => {
    const expected = stryker.mutate.map((f) => f.replace(/\.ts$/, ".test.ts"));
    expect(included.slice().sort()).toEqual(expected.slice().sort());
  });

  // docs/v7/mutation-baseline.md documents the gate. It sat at "break = 48"
  // against a "55.65%" baseline long after both had moved, so a reader
  // checking whether the gate was healthy got a stale answer from the doc.
  it("is documented with the break threshold the config actually sets", () => {
    expect(baselineDoc).toContain(`\`thresholds.break = ${stryker.thresholds.break}\``);
  });

  // The documented SCORE cannot be re-derived here — only a Stryker run
  // produces it, and that is a slow scheduled job. So it is trust-on-write,
  // and a stale or invented figure would sit in the doc unchallenged. These
  // two assertions are the part that IS machine-checkable.
  it("documents a baseline score consistent with the break threshold", () => {
    const row = /\|\s*\*\*All \(scoped\)\*\*\s*\|\s*\*\*([\d.]+)%\*\*/.exec(baselineDoc);
    expect(row, "no '**All (scoped)**' baseline row found in mutation-baseline.md").not.toBeNull();
    const score = Number(row![1]);
    const brk = stryker.thresholds.break;
    // The config's own rule is "break a couple points under the measured
    // baseline". A score at or below the floor is incoherent; one far above it
    // means either the floor was never ratcheted or the figure is wrong.
    expect(score).toBeGreaterThan(brk);
    expect(score - brk).toBeLessThanOrEqual(5);
  });

  it("documents a baseline row for exactly the mutated files", () => {
    // Catches the other half of a scope change: `mutate` and the include list
    // updated, but the doc's per-file table left describing the old set.
    const documented = [...baselineDoc.matchAll(/^\|\s*`([A-Za-z0-9_-]+\.ts)`\s*\|/gm)].map(
      (m) => m[1]!,
    );
    const expected = stryker.mutate.map((f) => f.split("/").pop()!);
    expect([...new Set(documented)].sort()).toEqual(expected.slice().sort());
  });
});
