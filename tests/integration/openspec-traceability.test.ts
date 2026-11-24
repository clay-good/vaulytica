/**
 * Every openspec change must be named by at least one test file.
 *
 * The repository's own convention, visible in most test headers, is that a
 * suite says which change and task it discharges —
 * "add-executed-copy-conformity task 4", "add-readability-measure task 1".
 * That convention is what makes the spec→test link navigable in both
 * directions: given a change, find what proves it.
 *
 * 🚨 Why it is worth asserting rather than trusting. The question "is every
 * spec actually covered?" was asked by hand at 9.1023.0 and two of the
 * thirty-eight changes came back with ZERO test files naming them:
 * `add-attorney-coherence-views` and `add-authority-citation-lint`. Both
 * turned out to be properly tested — `tools/cli/posture-review.test.ts`,
 * `src/extract/citations.test.ts` and
 * `src/engine/rules/filing/cite-rules.test.ts` cover them thoroughly — they
 * simply never said so, and three of the four suites had no header at all. So
 * the finding was a traceability gap, not a coverage gap.
 *
 * ⚠️ WHAT THIS DOES AND DOES NOT PROVE, because the distinction matters more
 * than the assertion. A test naming a change proves TRACEABILITY — that
 * somebody can get from the spec to the suite that discharges it. It does NOT
 * prove coverage: a header is a comment, and a suite could name a change and
 * assert nothing about it. Coverage is what the gate's 693 files, the reach
 * ratchets and the mutation scope are for. This closes the narrower hole that
 * a change can be marked `[x]` with nothing in the tree pointing at it, which
 * is how a spec quietly becomes documentation.
 *
 * There is deliberately no exceptions table. Every change passed once the
 * three headers were written, and a guard that needs an exception on its first
 * run is the kind that rots — if a change genuinely warrants one later, add
 * the table then, with the reason, rather than leaving a hole now.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const ROOT = process.cwd();
const CHANGES = join(ROOT, "openspec", "changes");

/** Every change directory (anything with a `tasks.md`). */
function changeNames(): string[] {
  return readdirSync(CHANGES)
    .filter((n) => {
      try {
        return statSync(join(CHANGES, n)).isDirectory();
      } catch {
        return false;
      }
    })
    .filter((n) => {
      try {
        return statSync(join(CHANGES, n, "tasks.md")).isFile();
      } catch {
        return false;
      }
    })
    .sort();
}

/** Every test/spec file in the tree, skipping build and sandbox output. */
function testFiles(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (
        entry.name === "node_modules" ||
        entry.name === "dist" ||
        entry.name.startsWith(".") ||
        entry.name === "coverage"
      ) {
        continue;
      }
      testFiles(p, out);
    } else if (/\.(test|spec)\.ts$/.test(entry.name)) {
      out.push(p);
    }
  }
  return out;
}

describe("openspec changes are traceable to tests", () => {
  it("names every change in at least one test file", () => {
    const names = changeNames();
    // Guard the derivation: if the walk found nothing, every assertion below
    // would pass vacuously. This is the shape `negative-assertion.test.ts`
    // exists to teach.
    expect(names.length, "no openspec changes found — the walk is broken").toBeGreaterThan(20);

    // 🚨 THIS FILE IS EXCLUDED FROM ITS OWN CORPUS, and that is not a
    // technicality. The header above names the two changes this guard was
    // written about, so with itself included it SATISFIED ITSELF: both
    // reference counts were non-zero because of a comment in the assertion.
    // Deleting the three real headers left it green. Any change name
    // mentioned in a comment here would be whitewashed the same way, which
    // would make the whole guard vacuous — the exact shape
    // `negative-assertion.test.ts` exists to teach, found by trying to make
    // this test fail and being unable to.
    const SELF = join(ROOT, "tests", "integration", "openspec-traceability.test.ts");
    const files = ["tests", "src", "tools"]
      .flatMap((d) => testFiles(join(ROOT, d)))
      .filter((f) => f !== SELF);
    expect(files.length, "no test files found — the walk is broken").toBeGreaterThan(300);
    expect(files, "this guard must not be in its own corpus").not.toContain(SELF);

    const corpus = files.map((f) => readFileSync(f, "utf8")).join("\n");
    const unreferenced = names.filter((n) => !corpus.includes(n));
    expect(
      unreferenced,
      `these openspec changes are named by no test file. Either the change is untested, or a ` +
        `suite that proves it should say so in its header:\n  ${unreferenced.join("\n  ")}`,
    ).toEqual([]);
  }, 120_000);
});
