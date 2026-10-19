/**
 * "nonrenewal" is "non-renewal", and "sub-contractor" is "subcontractor".
 *
 * Both spellings of a compound are in ordinary use, and recognizers were
 * written with one (9.951.0). Rewriting the corpus each way and diffing:
 *
 *   NON-      dropping the hyphen ("nonrenewal", "noncompete") hid the
 *             renewal-notice window from TEMP-005 and DARK-002 on five
 *             specimens. Recognizers wrote `non-` or `non[- ]`.
 *   SUB-      adding one ("sub-contractor", "sub-license", "sub-processor")
 *             produced four false CRITICALs: a HIPAA BAA's and a US privacy
 *             addendum's subcontractor flow-down, and a construction
 *             subcontract's identification of its parties, all "missing".
 *             Recognizers wrote `subcontract`, `sublicens`, `sublease`.
 *
 * Fixed by a codemod over recognizer source only (the AST-driven
 * `recognizerSources`), so no rule's name or advice text changed. The
 * rewrite also exposed STRUCT-009 reading "sub-contract" as a lower-case use
 * of a defined "Contract"; half of a hyphenated compound is no longer a use.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { analyzeText, loadAccuracyDeps } from "../../tools/cli/api.js";
import { recognizerSources, sourceFiles, DOCUMENT_READING_ROOTS } from "./_recognizer-sources.js";

const DIR = join(process.cwd(), "tests", "fixtures", "specimens");

/** "non-renewal" → "nonrenewal". */
export const withoutNonHyphen = (t: string): string => t.replace(/\b([Nn])on-([a-z])/g, "$1on$2");

/** "subcontractor" → "sub-contractor", and the same for licence, processor, lease, let. */
export const withSubHyphen = (t: string): string =>
  t.replace(/\b([Ss])ub(licen[sc]\w*|contract\w*|process\w*|lease\w*|let\w*)\b/g, "$1ub-$2");

async function movedBy(
  mutate: (t: string) => string,
): Promise<{ moved: string[]; probed: number }> {
  const deps = await loadAccuracyDeps({});
  const moved: string[] = [];
  let probed = 0;
  for (const file of readdirSync(DIR)
    .filter((f) => f.endsWith(".txt"))
    .sort()) {
    const text = readFileSync(join(DIR, file), "utf8");
    const mutated = mutate(text);
    if (mutated === text) continue;
    probed++;
    const before = await analyzeText(text, file, { deps });
    const after = await analyzeText(mutated, file, { deps });
    const ids = (r: typeof before): string[] =>
      [...new Set(r.run.findings.map((f) => `${f.rule_id}|${f.title}`))].sort();
    const lost = ids(before).filter((i) => !ids(after).includes(i));
    const gained = ids(after).filter((i) => !ids(before).includes(i));
    if (lost.length) moved.push(`${file}: lost ${lost.join(",")}`);
    if (gained.length) moved.push(`${file}: gained ${gained.join(",")}`);
  }
  return { moved, probed };
}

describe("a compound spelled the other way", () => {
  it('reads "nonrenewal" as "non-renewal"', async () => {
    const { moved, probed } = await movedBy(withoutNonHyphen);
    expect(probed, "no specimen writes a non- compound").toBeGreaterThan(100);
    expect(moved).toEqual([]);
  }, 1_800_000);

  it('reads "sub-contractor" as "subcontractor"', async () => {
    const { moved, probed } = await movedBy(withSubHyphen);
    expect(probed, "no specimen writes a sub- compound").toBeGreaterThan(40);
    expect(moved).toEqual([]);
  }, 1_800_000);

  it("no recognizer writes a sub- or non- compound one way only", () => {
    const files = DOCUMENT_READING_ROOTS.flatMap((root) => sourceFiles(root)).filter(
      (f) => !f.endsWith(".test.ts"),
    );
    expect(files.length, "no sources found — the walk is broken").toBeGreaterThan(50);
    const blind: string[] = [];
    for (const file of files) {
      for (const { line, text } of recognizerSources(file)) {
        if (
          /[Ss]ub(?:contract|licen|lease|process)|[Nn]on-(?!\?)[a-z]|[Nn]on\[- \](?!\?)/.test(text)
        )
          blind.push(`${file}:${line}  ${text.slice(0, 90)}`);
      }
    }
    expect(blind, `write sub-? and non-? so both spellings read:\n  ${blind.join("\n  ")}`).toEqual(
      [],
    );
  });

  it("rewrites only the compound", () => {
    expect(withoutNonHyphen("notice of non-renewal")).toBe("notice of nonrenewal");
    expect(withSubHyphen("each Subcontractor and sublicensee")).toBe(
      "each Sub-contractor and sub-licensee",
    );
  });
});
