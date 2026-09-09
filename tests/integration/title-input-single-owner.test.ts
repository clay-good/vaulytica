/**
 * Everything that routes a document reads its title through `titleCorpus`.
 *
 * The title is the single largest contributor to a playbook score (0.3, against
 * 0.2 per distinguishing phrase), and for years every call site built that
 * input by hand as:
 *
 *     ingest.tree.sections[0]?.heading ?? filename
 *
 * `??` catches null and undefined — not the EMPTY STRING the tree builder
 * produces for a document with no styled heading, which is every plain-text or
 * pasted document. So the biggest signal arrived blank and the filename
 * fallback never fired either. `titleCorpus` was extracted to end that, and
 * `title-corpus.test.ts` records the fix as covering "three production call
 * sites plus the parity test".
 *
 * 🚨 It did not. Three more copies of the line survived in the TEST HARNESSES —
 * `tests/integration/_pipeline-helpers.ts`, which ~40 integration tests use to
 * run the 312-specimen corpus, and both golden pipelines. Measured the day this
 * guard was written: routed through the helper's title, **78 of 312 specimens
 * landed on a different playbook than the product gives the same bytes** —
 * `indemnification-agreement.txt` to `generic-fallback`, `handbook.txt` to
 * `employment-at-will-us`, `eula.txt` to `copyright-license`. Every metamorphic
 * relation and false-positive sweep built on that helper had been measuring a
 * pipeline no user runs.
 *
 * A helper is not a single owner until nothing can bypass it. This is the
 * guard that makes it one — and it scans the harnesses, because that is where
 * the copies were.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";

const ROOT = join(import.meta.dirname, "..", "..");
const SCANNED = ["src", "tests", "tools", "site"];
/** The one file allowed to build the title corpus, because it defines it. */
const OWNER = join("src", "playbooks", "matcher.ts");

function sources(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    if (entry === "node_modules" || entry === "dist" || entry.startsWith(".")) continue;
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) sources(full, out);
    else if (full.endsWith(".ts")) out.push(full);
  }
  return out;
}

/** A guard that reads comments is reading documentation, not code. */
function stripComments(src: string): string {
  return src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
}

/**
 * The hand-built shape: the first section's heading with a `??` fallback. The
 * bug is `??` specifically — it passes the empty string through — so that is
 * what the pattern anchors on, not any read of `sections[0]`.
 */
const HAND_BUILT = /sections\[0\]\s*\]?\s*\??\.\s*heading\s*\?\?/;

describe("the matcher's title input has a single owner", () => {
  const files = SCANNED.flatMap((d) => sources(join(ROOT, d))).map((f) => relative(ROOT, f));

  it("scans the files it means to", () => {
    // Anti-vacuity: a sweep that walked an empty tree would pass silently.
    expect(files.length).toBeGreaterThan(500);
    expect(files).toContain(join("tests", "integration", "_pipeline-helpers.ts"));
    expect(files).toContain(OWNER);
  });

  it("nobody rebuilds it by hand", () => {
    const offenders = files.filter(
      (f) => f !== OWNER && HAND_BUILT.test(stripComments(readFileSync(join(ROOT, f), "utf8"))),
    );
    expect(
      offenders,
      "build the matcher's title with titleCorpus(tree, filename) — `?? filename` does not " +
        "catch the empty heading a plain-text document has, and the largest routing signal " +
        "arrives blank",
    ).toEqual([]);
  });

  it("catches the shape it exists to catch", () => {
    // The guard proven by the line it was written for, verbatim.
    // Assembled, not written out: a guard that scans this directory must not
    // trip over its own example.
    const shape = ["const titleSource = ingest.tree.sections[0]", "?.heading ", "?? name;"].join(
      "",
    );
    expect(HAND_BUILT.test(shape)).toBe(true);
    expect(HAND_BUILT.test("const titleSource = titleCorpus(ingest.tree, name);")).toBe(false);
  });

  it("every harness that routes a document uses the helper", () => {
    for (const harness of [
      join("tests", "integration", "_pipeline-helpers.ts"),
      join("tests", "golden", "v3", "_pipeline.ts"),
      join("tests", "golden", "v4", "_pipeline.ts"),
      join("src", "ui", "pipeline.ts"),
      join("tests", "golden", "v4", "bundle.test.ts"),
    ]) {
      const src = stripComments(readFileSync(join(ROOT, harness), "utf8"));
      expect(src, `${harness} routes documents without titleCorpus`).toContain("titleCorpus(");
    }
  });
});
