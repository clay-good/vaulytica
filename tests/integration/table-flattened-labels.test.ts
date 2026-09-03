/**
 * A label that arrives from a TABLE ROW, not from a typed line.
 *
 * `src/ingest/docx.ts` flattens a table to one paragraph per row with the
 * cells joined by " | ". That is not an edge case: a signature block, an
 * effective-date header and a fee schedule are laid out as two-column tables
 * in a large share of real .docx contracts, and the corpus — 310 hand-typed
 * `.txt` files — contains **not one pipe character**. So every rule that reads
 * "Name:" and not "Name |" was blind to the commonest layout there is, and
 * nothing could have shown it.
 *
 * Retyping the corpus's `Label: value` lines as `Label | value` moved a
 * finding on fifteen specimens. Four sites are fixed here and asserted below:
 *
 *   - **STRUCT-003**'s signature-line and signature-token labels, so a
 *     two-column signature table is a signature block.
 *   - **STRUCT-003**'s publication stamp — "Last updated | February 2, 2026" —
 *     which is what stands in for execution on a policy that is published
 *     rather than signed.
 *   - **STRUCT-002** and `src/extract/dates.ts`, so "Date | April 6, 2026" and
 *     "Effective Date | 2026-01-01" are the date the document adopts. The
 *     STRUCT-002 label already anticipated the pipe on its LEFT, as a cell
 *     boundary, while requiring a colon on its right.
 *   - **STRUCT-013**'s labeled field, so "Date | ____________" is an unsigned
 *     signature line and not an unfilled template placeholder.
 *
 *   - **`src/extract/definitions.ts`**'s label terminator, so "Title | Chief
 *     Executive Officer" is a label and not a Title-Case term the document
 *     forgot to define. The colon had marked a label there since it was
 *     written; the pipe is the cell boundary doing the same job.
 *
 * ── what is NOT fixed, and is recorded rather than hidden ──
 *
 * The design question the last pass left open has been answered, and the
 * answer was yes: a COVER BLOCK defines its terms, and a table row is the same
 * block laid out as cells. "Plan Year | February 1, 2026 through January 31,
 * 2027" defines the Plan Year exactly as "Plan Year: …" does, and the plan's
 * own Plan Year — used throughout its body — was a term it forgot to define.
 * `FIELD_LABEL` and the cover-block value guard both take the pipe now.
 *
 * The sweep is at three specimens, down from fifteen. `dpia-art-35`
 * (STRUCT-006 on a person named in a cover field), `scc-module-3` (DPA-002)
 * and `sow-numbered` (TEMP-002) are what is left, and each still needs its own
 * reading rather than a wider pattern.
 *
 * There is therefore no whole-corpus relation here yet: it would be red, and a
 * red guard teaches nothing. This file asserts what is settled.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { analyzeText } from "../../tools/cli/api.js";
import { loadAccuracyDeps } from "../../tools/accuracy/pipeline.js";
import { extractDates } from "../../src/extract/dates.js";
import { buildTree } from "../../src/extract/_fixtures.js";
import { rule as STRUCT_003 } from "../../src/engine/rules/structural/STRUCT-003.js";
import { rule as STRUCT_013 } from "../../src/engine/rules/structural/STRUCT-013.js";
import { buildContext } from "../../src/engine/_test-fixtures.js";

/** The same block, typed as lines and flattened from a two-column table. */
const DIR = join(process.cwd(), "tests", "fixtures", "specimens");

const SIGNED_TYPED = [
  "Agreement",
  "This Agreement is between Acme Corp. and Globex Inc. Provider shall provide the Services.",
  "By: Jane Ellis",
  "Name: Jane Ellis",
  "Title: Chief Executive Officer",
  "Date: April 6, 2026",
];
const SIGNED_TABLE = SIGNED_TYPED.map((l) => l.replace(/^(By|Name|Title|Date): /, "$1 | "));

describe("a label flattened out of a table row", () => {
  it("the corpus contains no pipe at all, which is why nothing could show this", () => {
    const withPipe = readdirSync(DIR)
      .filter((f) => f.endsWith(".txt"))
      .filter((f) => readFileSync(join(DIR, f), "utf8").includes(" | "));
    expect(withPipe).toEqual([]);
  });

  it("STRUCT-003 reads a two-column signature table as a signature block", () => {
    const typed = STRUCT_003.check(buildContext(SIGNED_TYPED as [string, ...string[]]));
    const table = STRUCT_003.check(buildContext(SIGNED_TABLE as [string, ...string[]]));
    // Whatever the typed form does, the table form must do — they are the same
    // block in two layouts.
    expect(table === null).toBe(typed === null);
  });

  it("STRUCT-003 reads a policy's publication stamp from a table row", () => {
    const stamp = (sep: string): boolean =>
      STRUCT_003.check(
        buildContext([
          "Cookie Notice",
          `Last updated ${sep} February 2, 2026`,
          "We use cookies to operate this site and to measure how it is used.",
          "You may withdraw consent at any time through the preference centre.",
        ]),
      ) === null;
    expect(stamp("|"), "a pipe-separated update stamp").toBe(stamp(":"));
  });

  it("the date extractor reads a table-flattened effective date", () => {
    const anchored = (sep: string): boolean =>
      // The NAMED ANCHOR specifically: the absolute date is found either way,
      // and it is the label that makes it the date the document adopts.
      extractDates(buildTree(["Agreement", `Effective Date ${sep} 2026-01-01`])).some(
        (d) => d.type === "named-anchor",
      );
    expect(anchored("|"), "a pipe-separated Effective Date").toBe(anchored(":"));
  });

  it("a table-flattened label is a label, not a term the document forgot to define", async () => {
    // Asserted on the specimen that showed it, because the bleed needs a real
    // signature block: the Title-Case run picks up the NEXT label as its last
    // word, and a synthetic three-line fixture does not reproduce it. Every
    // label in the document is retyped as a table row; nothing may move.
    const deps = await loadAccuracyDeps({});
    const name = "unilateral-nda.txt";
    const text = readFileSync(join(DIR, name), "utf8");
    const mutated = text.replace(/^([A-Z][A-Za-z /'’-]{2,40}):[ \t]+(?=\S)/gm, "$1 | ");
    expect(mutated, "the specimen has no label to retype").not.toBe(text);
    const ids = async (t: string): Promise<string[]> =>
      [
        ...new Set((await analyzeText(t, name, { deps })).run.findings.map((f) => f.rule_id)),
      ].sort();
    expect(await ids(mutated)).toEqual(await ids(text));
  }, 120_000);

  it("STRUCT-013 reads a blank after a table-flattened label as a signature line", () => {
    const placeholder = (sep: string): boolean =>
      STRUCT_013.check(
        buildContext([
          "Agreement",
          "This Agreement is between Acme Corp. and Globex Inc. Provider shall provide the Services for the fees stated below.",
          "IN WITNESS WHEREOF the parties have executed this Agreement.",
          `Name ${sep} ____________________`,
          `Title ${sep} ____________________`,
          `Date ${sep} ____________________`,
        ]),
      ) !== null;
    // An unsigned signature block is not an unfilled template placeholder, in
    // either layout.
    expect(placeholder("|"), "a pipe-separated signature line").toBe(placeholder(":"));
  });
});
