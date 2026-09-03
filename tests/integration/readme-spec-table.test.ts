/**
 * Every shipped spec has a row in the README's spec table.
 *
 * The table is the README's index of what the tool does and when each part
 * landed. It is also the only place a reader looks for "what is v46?", and it
 * is maintained by hand — so it drifts the way hand-maintained indexes always
 * do. It ended at v44 while v45, v46, and v47 had shipped: the three waves
 * that took the catalog from 145 document families to 265 were absent from the
 * one place that lists them.
 *
 * Every other count in the README has a guard (`readme-rule-count-drift`), and
 * those were all current. The table had none, which is exactly why it was the
 * thing that drifted.
 *
 * The check is deliberately shallow — a row exists and links its own spec —
 * because the row's PROSE is a judgment no test can make. What a test can do
 * is refuse to let a spec ship without one.
 */

import { readFileSync, readdirSync } from "node:fs";
import { describe, expect, it } from "vitest";

const README = readFileSync("README.md", "utf8");
/**
 * Prettier owns the column padding in a markdown table and re-aligns it
 * whenever a cell's width changes, so `| v4 |` becomes `| v4  |` the moment a
 * wider row lands. Every row test below reads the squeezed text: the row's
 * CONTENT is the thing being guarded, and asserting its padding made this test
 * fail exactly when `format:check` was satisfied.
 */
const SQUEEZED = README.replace(/[ \t]+/g, " ");

/** `spec-v45.md` → 45. Ignores `spec.md`, which is the umbrella document. */
function specVersions(): number[] {
  return readdirSync("docs")
    .map((f) => /^spec-v(\d+)\.md$/.exec(f))
    .filter((m): m is RegExpExecArray => m !== null)
    .map((m) => Number(m[1]))
    .sort((a, b) => a - b);
}

describe("README spec table", () => {
  it("every docs/spec-vN.md has a row that links it", () => {
    const missing: string[] = [];
    for (const v of specVersions()) {
      const hasRow = new RegExp(`^\\| v${v} \\|`, "m").test(SQUEEZED);
      const linksSpec = README.includes(`docs/spec-v${v}.md`);
      if (!hasRow || !linksSpec) {
        missing.push(`v${v}${hasRow ? " (row present, spec not linked)" : " (no row)"}`);
      }
    }
    expect(
      missing,
      `these specs shipped without a README spec-table row:\n  ${missing.join("\n  ")}`,
    ).toEqual([]);
  });

  it("every row in the table names a spec that exists", () => {
    const shipped = new Set(specVersions());
    // v1 predates the numbered spec files and is described inline.
    const orphans = [...SQUEEZED.matchAll(/^\| v(\d+) \|/gm)]
      .map((m) => Number(m[1]))
      .filter((v) => v !== 1 && !shipped.has(v));
    expect(orphans, `rows naming a spec with no file: ${orphans.join(", ")}`).toEqual([]);
  });
});
