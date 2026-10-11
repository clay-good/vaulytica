/**
 * A finding's quoted excerpt must contain the language its span points at.
 *
 * Every report says, in `clauseEvidenceSentence`, that findings carrying an
 * excerpt "quote the exact clause text they fired on". That claim has two
 * halves. The excerpt being VERBATIM document text was already true (checked
 * over the corpus: 1,116 of 1,116). The other half was not: rules quoted
 * `truncate(hit.text, N)` — the paragraph's first N characters — while
 * `hit.position` located the match, so whenever the match sat beyond character
 * N the report quoted a clause that did not contain the thing it was flagging.
 * **94 of 1,116 findings, across 17 rules.**
 *
 * 🚨 SARIF is where it did real damage: `region.charOffset` comes from the
 * position and `snippet.text` from the excerpt, and SARIF's own spec says a
 * snippet is the content of its region. A code-scanning annotation highlighted
 * one clause and displayed another.
 *
 * `hitExcerpt` and `matchedSentence` now window the quote around the match.
 * This holds the result at 2 declared exceptions, both benign and named below.
 *
 * 🥇 The offset space is rebuilt from the RUNS' OWN recorded `start`/`end`,
 * never from `flattenText`. Three earlier attempts at this check were wrong
 * rather than the engine: `flattenText` inserts section headings and a newline
 * per paragraph, while `normalize` advances its cursor over a heading plus one
 * newline and over run text only — so slicing the flattened string drifts
 * further the deeper into a document you read, and reports whole-clause
 * "misalignments" that do not exist. Ask the data for its own coordinates.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { analyzeText } from "../../tools/cli/api.js";
import { ingestPaste } from "../../src/ingest/paste.js";
import type { DocumentTree, Section } from "../../src/ingest/types.js";

const DIR = join(process.cwd(), "tests", "fixtures", "specimens");

/**
 * The gap filler, and the reason it is split rather than matched: a NUL
 * inside a regex literal trips `no-control-regex`, and the rule is right that
 * it reads as a typo rather than an intention.
 */
const GAP = "\u0000";

/**
 * The string the engine's offsets index into, assembled from the runs that
 * declare those offsets. Gaps — headings and paragraph separators, which take
 * up offset space but hold no run — are filled with NUL so a span that strays
 * into one is visible rather than silently plausible.
 */
function offsetSpace(tree: DocumentTree): string {
  const runs: { start: number; text: string }[] = [];
  let max = 0;
  const walk = (sections: Section[]): void => {
    for (const s of sections) {
      for (const p of s.paragraphs) {
        for (const r of p.runs) {
          runs.push({ start: r.start, text: r.text });
          max = Math.max(max, r.end);
        }
      }
      walk(s.children);
    }
  };
  walk(tree.sections);
  const buf = new Array<string>(max).fill(GAP);
  for (const { start, text } of runs) {
    for (let i = 0; i < text.length; i += 1) buf[start + i] = text[i]!;
  }
  return buf.join("");
}

const norm = (s: string): string => s.split(GAP).join(" ").replace(/\s+/g, " ").trim();

/**
 * The two surviving disagreements, each benign and each pinned so a third
 * cannot join quietly.
 *
 * - `TEMP-007` on `architect-agreement.txt`: the quote BEGINS at the match and
 *   the match runs past the 240-character window, so the tail is cut and says
 *   so. The quote points at the right language; it is merely shorter than the
 *   span.
 * - `STRUCT-014` on `protective-order.txt`: the excerpt quotes the defined term
 *   in its canonical casing ("Protected Material") while the span points at a
 *   lowercase use of it. A case difference, not a different clause.
 */
const DECLARED = ["STRUCT-014 protective-order.txt", "TEMP-007 architect-agreement.txt"];

describe("a finding's excerpt and its span describe the same language", () => {
  it("agrees on every corpus finding but the declared exceptions", async () => {
    const files = readdirSync(DIR)
      .filter((f) => f.endsWith(".txt"))
      .sort();
    let withExcerpt = 0;
    const disagree: string[] = [];

    for (const file of files) {
      const raw = readFileSync(join(DIR, file), "utf8");
      const space = offsetSpace((await ingestPaste(raw)).tree);
      const result = await analyzeText(raw, file);
      for (const f of result.run.findings) {
        const ex = f.excerpt;
        if (!(ex.text.trim().length > 0 && ex.end_offset > ex.start_offset)) continue;
        withExcerpt += 1;
        const span = norm(space.slice(ex.start_offset, ex.end_offset));
        // `truncate` marks a cut tail; compare what survives it.
        const quoted = norm(ex.text.replace(/…$/, "").replace(/^…/, ""));
        if (span.length === 0 || quoted.length === 0) continue;
        const agrees =
          quoted.includes(span) ||
          span.includes(quoted) ||
          quoted.startsWith(span) ||
          span.startsWith(quoted);
        if (!agrees) disagree.push(`${f.rule_id} ${file}`);
      }
    }

    // Anti-vacuity: a harness that analysed nothing finds nothing to disagree.
    expect(files.length).toBeGreaterThan(300);
    expect(withExcerpt).toBeGreaterThan(1000);

    expect([...new Set(disagree)].sort()).toEqual(DECLARED);
  }, 600_000);
});
