/**
 * An e2e spec that skips when its fixture is missing can stop running without
 * anyone noticing.
 *
 * Every Playwright spec in this repo opens with the same honest guard —
 * `test.skip(!existsSync(FIXTURE), "fixture missing: …")` — so a checkout that
 * lacks a binary fixture reports a skip rather than a spurious failure. That is
 * the right behaviour for a missing file and the wrong behaviour for a
 * *deleted* one: the drop-zone smoke test, the no-network privacy proof and the
 * axe accessibility sweep would each go quiet, and **CI would stay green**.
 *
 * This is the vacuous-pass shape the pre-disclosure pack learned the hard way
 * (`negative-assertion.test.ts`) and the one `cli-fixture-guard.test.ts`
 * already closes for the CLI's own fixtures. It is the e2e counterpart.
 *
 * Matching is by BASENAME rather than by resolving each `join(...)`
 * expression: the specs build paths five different ways — `__dirname`,
 * `process.cwd()`, a shared `FIXTURE_DIR`, an env override — and a resolver
 * that understood only some of them would quietly check fewer files than it
 * appeared to. A basename that exists nowhere under `tests/` is unambiguous.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const ROOT = process.cwd();
const E2E = join(ROOT, "tests", "e2e");

/** Every file under `tests/`, by basename. */
function fixtureIndex(dir: string, into = new Set<string>()): Set<string> {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) fixtureIndex(path, into);
    else into.add(entry.name);
  }
  return into;
}

/**
 * Every `.docx` / `.pdf` filename a spec builds a PATH to.
 *
 * ⚠️ Two narrowings, both learned by running it. Matching every quoted
 * filename swept in the DOWNLOAD a spec asserts on (`report.docx`,
 * `bundle.docx`) and two deliberately overflow-stressing filenames — a path is
 * what distinguishes a file that must exist on disk from a name a test merely
 * expects to see. Then matching any `join(...)` still swept in
 * `join(tmp, "scanned.pdf")`, a file the spec WRITES.
 *
 * 🥇 The root of the join is the signal: a fixture is rooted at a stable
 * location (`__dirname`, `process.cwd()`, a module-level `CONST`), and a
 * scratch file is rooted at a runtime variable. That is the rule, rather than
 * a list of names to ignore.
 */
function referencedFixtures(dir: string, into = new Set<string>()): Set<string> {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      referencedFixtures(path, into);
      continue;
    }
    if (!entry.name.endsWith(".spec.ts")) continue;
    const src = readFileSync(path, "utf8");
    const rooted =
      /join\(\s*(?:__dirname|process\.cwd\(\)|[A-Z][A-Z0-9_]*)[^)]*"([A-Za-z0-9._-]+\.(?:docx|pdf))"[^)]*\)/g;
    for (const m of src.matchAll(rooted)) into.add(m[1]!);
  }
  return into;
}

describe("every fixture an e2e spec names is present", () => {
  it("resolves each one somewhere under tests/", () => {
    const present = fixtureIndex(join(ROOT, "tests"));
    const referenced = [...referencedFixtures(E2E)].sort();

    // Anti-vacuity: a scan that matched no filenames would pass with an empty
    // missing list while proving nothing — which is the exact failure this
    // file exists to prevent one layer up.
    expect(referenced.length, "no fixture filenames found — the scan is broken").toBeGreaterThan(4);

    const missing = referenced.filter((name) => !present.has(name));
    expect(
      missing,
      "an e2e spec names a fixture that no longer exists — that spec now SKIPS " +
        "silently and CI stays green. Restore the file, or delete the spec.",
    ).toEqual([]);
  });

  it("the sample-doc bundles a spec drops are non-empty files", () => {
    // A zero-byte .docx passes `existsSync` and fails inside the browser, which
    // reads as a flaky e2e rather than a missing fixture.
    const empty: string[] = [];
    const walk = (dir: string): void => {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const path = join(dir, entry.name);
        if (entry.isDirectory()) walk(path);
        else if (/\.(docx|pdf)$/.test(entry.name) && statSync(path).size === 0) {
          empty.push(path.replace(ROOT + "/", ""));
        }
      }
    };
    walk(E2E);
    expect(empty).toEqual([]);
  });
});
