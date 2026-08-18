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
 *
 * That derivation used to scan only the mutated modules' OWN directories, which
 * reintroduced the same blind spot one level up: a covering suite that lives
 * elsewhere could not be seen, so the guard reported agreement while the
 * measurement was still short. `tests/integration/property-based.test.ts`
 * imports four of the seven mutated extractors and was invisible for exactly
 * that reason. The walk now covers every test file in the repo.
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { EXCLUDED_COVERING_SUITES } from "../../vitest.mutation.config.js";

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

/** Every `*.test.ts` in the repo, as repo-relative paths. */
function allTestFiles(): string[] {
  const skip = new Set(["node_modules", ".git", ".stryker-tmp", "dist", "reports", "coverage"]);
  const found: string[] = [];
  const walk = (dir: string): void => {
    for (const entry of readdirSync(join(root, dir))) {
      if (skip.has(entry) || entry.startsWith(".")) continue;
      const path = dir ? `${dir}/${entry}` : entry;
      if (statSync(join(root, path)).isDirectory()) walk(path);
      else if (entry.endsWith(".test.ts")) found.push(path);
    }
  };
  walk("");
  return found;
}

/**
 * Every test file in the repo that imports at least one mutated module. Import
 * specifiers are emitted as `./x.js` / `../../src/extract/x.js` (NodeNext), so
 * the mutated `src/extract/x.ts` is matched by resolving the specifier against
 * the test file's own directory and mapping `.js` back to the `.ts` source.
 *
 * Scanning the WHOLE repo rather than the mutated files' directories is the
 * point: a covering suite is a covering suite wherever it lives, and a
 * directory-scoped walk silently under-derives (see the header note).
 */
function testFilesCoveringMutatedModules(mutated: string[]): string[] {
  const mutatedSet = new Set(mutated);
  return allTestFiles()
    .filter((path) => {
      const source = readFileSync(join(root, path), "utf8");
      const specifiers = [...source.matchAll(/from\s+"(\.[^"]+)"/g)].map((m) => m[1]!);
      return specifiers.some((spec) => {
        const resolved = new URL(spec, `file:///${path}`).pathname
          .replace(/^\//, "")
          .replace(/\.js$/, ".ts");
        return mutatedSet.has(resolved);
      });
    })
    .sort();
}

describe("mutation scope", () => {
  const included = includedTestFiles(mutationConfig);

  it("parses a non-empty include list (guards the regex itself)", () => {
    expect(included.length).toBeGreaterThan(0);
  });

  it("includes every test file that imports a mutated module, minus the declared exclusions", () => {
    const covering = testFilesCoveringMutatedModules(stryker.mutate);
    // Guards the derivation itself: a broken resolver returning [] would make
    // the comparison below vacuous for an empty include list.
    expect(covering.length).toBeGreaterThanOrEqual(stryker.mutate.length);
    const expected = covering.filter((f) => !(f in EXCLUDED_COVERING_SUITES));
    expect(included.slice().sort()).toEqual(expected);
  });

  // An exclusion is a decision about the measurement's completeness, so it has
  // to be argued in the file, not just listed. Both of these cost the run more
  // than an hour and three out-of-memory restarts; that reasoning belongs next
  // to the entry, where the next person to widen the scope will read it.
  it("declares a reason for every excluded covering suite, and excludes nothing else", () => {
    const covering = new Set(testFilesCoveringMutatedModules(stryker.mutate));
    for (const [file, reason] of Object.entries(EXCLUDED_COVERING_SUITES)) {
      expect(covering.has(file), `${file} is excluded but covers no mutated module`).toBe(true);
      expect(reason.length, `${file} is excluded without a reason`).toBeGreaterThan(20);
    }
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
