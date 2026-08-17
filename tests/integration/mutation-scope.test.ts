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
});
