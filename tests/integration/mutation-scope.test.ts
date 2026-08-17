/**
 * Mutation-scope config guard.
 *
 * Stryker's `mutate` list (stryker.config.json) and the test `include` list
 * (vitest.mutation.config.ts) are two hand-maintained lists that have to
 * describe the same surface. Getting them out of step does not fail loudly:
 * mutants in an uncovered file report "NoCoverage", which reads as a
 * catastrophic coverage collapse when in fact the tests exist and simply never
 * ran, and it drags the aggregate under the break threshold — failing the
 * scheduled job for a config reason.
 *
 * The rule used to be one test file per mutated module, matched by filename.
 * That was too narrow and hid a real measurement error: several modules are
 * also covered by sibling phrasing suites (`date-format-phrasing.test.ts`,
 * `amount-postfix-currency.test.ts`, `arbitration-seat-phrasing.test.ts` …)
 * whose names do not match their module. Those never ran under mutation, so
 * their kills went uncounted and features they had covered for weeks —
 * `DAY_MONTH_YEAR`, `postfixCurrency` — were reported as entirely untested.
 *
 * So the expected list is DERIVED, from what each test file actually imports:
 * every test file importing a mutated module must be included, and nothing may
 * be included that does not import one.
 */

import { readdirSync, readFileSync } from "node:fs";
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

/**
 * Every test file under the mutated modules' directories that imports at least
 * one of them. Import specifiers are emitted as `./x.js` (NodeNext), so the
 * mutated `src/extract/x.ts` is matched by a `./x.js` specifier resolved
 * against the test file's own directory.
 */
function testFilesCoveringMutatedModules(mutated: string[]): string[] {
  const dirs = [...new Set(mutated.map((f) => f.slice(0, f.lastIndexOf("/"))))];
  const mutatedSet = new Set(mutated);
  const found: string[] = [];
  for (const dir of dirs) {
    for (const entry of readdirSync(join(root, dir))) {
      if (!entry.endsWith(".test.ts")) continue;
      const path = `${dir}/${entry}`;
      const source = readFileSync(join(root, path), "utf8");
      const specifiers = [...source.matchAll(/from\s+"(\.[^"]+)"/g)].map((m) => m[1]!);
      const importsMutated = specifiers.some((spec) => {
        // Resolve the specifier against the test file's directory, then map the
        // emitted .js extension back to the .ts source Stryker mutates.
        const resolved = new URL(spec, `file:///${path}`).pathname
          .replace(/^\//, "")
          .replace(/\.js$/, ".ts");
        return mutatedSet.has(resolved);
      });
      if (importsMutated) found.push(path);
    }
  }
  return found.sort();
}

describe("mutation scope", () => {
  const included = includedTestFiles(mutationConfig);

  it("parses a non-empty include list (guards the regex itself)", () => {
    expect(included.length).toBeGreaterThan(0);
  });

  it("includes every test file that imports a mutated module, and only those", () => {
    const expected = testFilesCoveringMutatedModules(stryker.mutate);
    // Guards the derivation itself: a broken resolver returning [] would make
    // the comparison below vacuous for an empty include list.
    expect(expected.length).toBeGreaterThanOrEqual(stryker.mutate.length);
    expect(included.slice().sort()).toEqual(expected);
  });

  it("mutates only modules that have at least one covering test file", () => {
    for (const module of stryker.mutate) {
      const covering = testFilesCoveringMutatedModules([module]);
      expect(covering, `no test file imports ${module}`).not.toHaveLength(0);
    }
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

  // The README quotes the same score in its own words, and went stale twice
  // over: it still advertised "the date/amount extractors" at "55.65%" after
  // the scope had twice widened and the score had moved four times. One number
  // in two places is one number too many unless they are pinned together.
  it("is quoted in the README with the same baseline score", () => {
    const row = /\|\s*\*\*All \(scoped\)\*\*\s*\|\s*\*\*([\d.]+)%\*\*/.exec(baselineDoc);
    const readme = readFileSync(join(root, "README.md"), "utf8");
    expect(
      readme,
      "README's mutation baseline disagrees with docs/v7/mutation-baseline.md",
    ).toContain(`a committed baseline of **${row![1]}%**`);
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
