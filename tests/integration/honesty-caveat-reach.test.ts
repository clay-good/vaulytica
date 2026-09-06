/**
 * Every surface that renders findings must also render the two caveats that
 * qualify them.
 *
 * The engine has two ways of saying "read this with care", and both are facts
 * about the ANALYSIS rather than about the contract:
 *
 *  - `run.classification_notice` — no document family matched, so only the
 *    generic lint ran, and "the findings below may be irrelevant or misleading
 *    for a document that is not a contract";
 *  - `IngestResult.warnings` — what the ingest could and could not READ: a
 *    redline taken as all-changes-accepted, a PDF that fell back to OCR,
 *    pasted text that lost its structure.
 *
 * They are the easiest thing in the tree to leave out, because a surface is
 * built to show findings and a caveat is not one. `IngestResult.warnings` was
 * composed from the beginning and read by NO consumer anywhere until session
 * 29. Session 30 found both missing from the bundle CARD. Session 32 found
 * them missing from three more: the CLI terminal — where a bread recipe
 * printed `[generic-fallback]  1C 2W 1I` and nothing else — the bundle DOCX's
 * per-document subsection, and (as a roll-up) the SARIF.
 *
 * So this is a reach test, not a rendering test. It asserts only that each
 * surface READS both fields; what it does with them is that surface's business
 * and its own tests' subject. A new render surface must join this list, which
 * is the point: the list is where the omission becomes visible.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

/** Every module that turns a run into something a person or a pipeline reads. */
const FINDING_SURFACES: ReadonlyArray<[file: string, what: string]> = [
  ["src/report/json.ts", "the JSON report"],
  ["src/report/docx.ts", "the DOCX report"],
  ["src/report/html.ts", "the standalone HTML report"],
  ["src/report/sarif.ts", "the SARIF (CI) surface"],
  ["src/report/bundle.ts", "the bundle report"],
  ["src/report/exports.ts", "the Markdown fix list"],
  ["tools/cli/run.ts", "the CLI's terminal output"],
  ["src/ui/states.ts", "the in-tab result states"],
];

describe("the honesty caveats reach every findings surface", () => {
  it("each surface reads the classification notice", () => {
    const missing: string[] = [];
    for (const [file, what] of FINDING_SURFACES) {
      const src = readFileSync(join(process.cwd(), file), "utf8");
      if (!/classification_notice/.test(src)) missing.push(`${file} — ${what}`);
    }
    expect(
      missing,
      "a surface renders findings without the notice that says they may not apply",
    ).toEqual([]);
  });

  it("each surface reads the ingest's warnings", () => {
    const missing: string[] = [];
    for (const [file, what] of FINDING_SURFACES) {
      const src = readFileSync(join(process.cwd(), file), "utf8");
      // `warnings` as a property read or a parameter — never a comment.
      const code = src.replace(/\/\*[\s\S]*?\*\/|\/\/[^\n]*/g, "");
      if (!/\bwarnings\b/.test(code)) missing.push(`${file} — ${what}`);
    }
    expect(
      missing,
      "a surface renders findings without saying what the ingest could not read",
    ).toEqual([]);
  });

  it("detects a surface that drops one", () => {
    // The guard is only worth its runtime if it fails on the real shape of the
    // defect. A file that renders findings and mentions neither field is
    // exactly what every one of the four historical misses looked like.
    const src = "export function render(run) { return run.findings.map(f => f.title); }";
    expect(/classification_notice/.test(src)).toBe(false);
    expect(/\bwarnings\b/.test(src)).toBe(false);
  });
});
