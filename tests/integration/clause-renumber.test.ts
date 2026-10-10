/**
 * A redline that survives renumbering (spec-v51 §9).
 *
 * Insert one clause into a numbered agreement and every clause after it gets a
 * new number. The clause diff carried the number in its match key, so each of
 * those read as REWRITTEN — "4 rewritten · 1 added" for a one-clause insertion
 * — and rewritten clauses were paired by position, "7. Governing Law" against
 * "7. Return or Destruction".
 *
 * The relation, over every specimen with sequential top-level numbering:
 * insert one clause with unique text and renumber what follows. The diff is
 * exactly 1 added and 0 rewritten. Before the fix it held on none of them.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ingestPaste } from "../../src/ingest/paste.js";
import { buildClauseDiff } from "../../src/report/clause-diff.js";
import { buildComparisonJsonObject } from "../../src/report/compare.js";
import { compareFiles } from "../../tools/cli/api.js";
import { formatCompareMarkdown } from "../../tools/cli/compare.js";

const SPECIMENS = join(process.cwd(), "tests", "fixtures", "specimens");
const ZEBRA =
  "Zebra Quarantine. The parties shall keep every zebra in quarantine for forty days after its arrival at the northern paddock.";

/**
 * Insert a clause in the middle of a document whose top-level clauses are
 * numbered 1..n, each opening its own paragraph, and renumber the rest.
 * `null` when the document is not numbered that way.
 */
function insertClause(text: string, renumberReferences = false): string | null {
  const lines = text.split("\n");
  const heads = lines
    .map((line, i) => ({ i, n: /^(\d+)\.\s+\S/.exec(line)?.[1] }))
    .filter((h): h is { i: number; n: string } => h.n !== undefined);
  const numbers = heads.map((h) => Number(h.n));
  if (numbers.length < 3 || !numbers.every((n, k) => n === k + 1)) return null;
  // Each numbered line must open a paragraph: several numbered items joined
  // into one paragraph are one clause to the diff, and an insertion inside it
  // IS a rewrite.
  if (!heads.every((h) => h.i === 0 || lines[h.i - 1]!.trim() === "")) return null;
  const at = heads[Math.floor(heads.length / 2)]!;
  const k = Number(at.n);
  const bump = (n: string): string => String(Number(n) >= k ? Number(n) + 1 : Number(n));
  const out = lines.map((line, i) => {
    let next =
      i >= at.i
        ? line.replace(/^(\d+)\.(\s)/, (_m, n: string, sp: string) => `${bump(n)}.${sp}`)
        : line;
    if (renumberReferences) {
      next = next.replace(
        /\b(Sections?|Articles?|Clauses?)\s+(\d+)\b/g,
        (_m, w: string, n: string) => `${w} ${bump(n)}`,
      );
    }
    return next;
  });
  out.splice(at.i, 0, `${k}. ${ZEBRA}`, "");
  return out.join("\n");
}

const diff = async (base: string, revised: string) =>
  buildClauseDiff((await ingestPaste(base)).tree, (await ingestPaste(revised)).tree);

describe("the clause diff survives renumbering", { timeout: 300_000 }, () => {
  it("an inserted clause is one addition and no rewrite, on every numbered specimen", async () => {
    const wrong: string[] = [];
    let eligible = 0;
    let renumbered = 0;
    for (const name of readdirSync(SPECIMENS)) {
      const base = readFileSync(join(SPECIMENS, name), "utf8");
      const revised = insertClause(base);
      if (!revised) continue;
      eligible++;
      const d = await diff(base, revised);
      renumbered += d.renumbered.length;
      if (d.added.length !== 1 || d.changed.length !== 0 || d.removed.length !== 0) {
        wrong.push(
          `${name}: ${d.added.length} added, ${d.changed.length} rewritten, ${d.removed.length} removed`,
        );
      } else if (!d.added[0]!.text.includes("Zebra Quarantine")) {
        wrong.push(`${name}: the addition is not the inserted clause`);
      }
    }
    expect(wrong).toEqual([]);
    // Anti-vacuity: most of the corpus is numbered this way, and the clauses
    // below the insertion are reported as renumbered, not as unchanged.
    expect(eligible).toBeGreaterThan(240);
    expect(renumbered).toBeGreaterThan(eligible);
  });

  it("when the cross-references move too, every rewritten pair differs only in digits", async () => {
    const wrong: string[] = [];
    let withRewrites = 0;
    for (const name of readdirSync(SPECIMENS)) {
      const base = readFileSync(join(SPECIMENS, name), "utf8");
      const revised = insertClause(base, true);
      if (!revised) continue;
      const d = await diff(base, revised);
      if (d.added.length !== 1) wrong.push(`${name}: ${d.added.length} added`);
      if (d.changed.length > 0) withRewrites++;
      for (const pair of d.changed) {
        const strip = (t: string): string => t.replace(/\d+/g, "#");
        if (strip(pair.base.text) !== strip(pair.revised.text)) {
          wrong.push(
            `${name}: "${pair.base.text.slice(0, 60)}" → "${pair.revised.text.slice(0, 60)}"`,
          );
        }
      }
    }
    expect(wrong).toEqual([]);
    // Anti-vacuity: some specimens do cite a section that moved.
    expect(withRewrites).toBeGreaterThan(10);
  });

  it("reaches the comparison JSON and Markdown, and leaves the comparison hash alone", async () => {
    const base = readFileSync(join(SPECIMENS, "mutual-nda-complete.txt"), "utf8");
    const revised = insertClause(base)!;
    const r = await compareFiles(
      { text: base, filename: "nda.txt" },
      { text: revised, filename: "nda.txt" },
    );
    const json = buildComparisonJsonObject(r.comparison, r.clause_diff);
    expect(json.clause_diff!.renumbered.length).toBeGreaterThan(0);
    expect(json.clause_diff!.added).toHaveLength(1);
    expect(json.clause_diff!.changed).toEqual([]);
    const md = formatCompareMarkdown(r.comparison, r.clause_diff);
    expect(md).toMatch(/0 rewritten · 1 added · 0 removed · \d+ renumbered · \d+ unchanged/);
    // The clause diff is outside the comparison hash: the same pair hashes the
    // same whether or not the redline is attached.
    expect(buildComparisonJsonObject(r.comparison).result_hash).toBe(json.result_hash);
    // And a pair with nothing renumbered does not mention it.
    const same = await compareFiles({ text: base }, { text: base });
    expect(formatCompareMarkdown(same.comparison, same.clause_diff)).not.toContain("renumbered");
  });
});
