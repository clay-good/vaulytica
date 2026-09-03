/**
 * "will" is how half the profession writes "shall".
 *
 * Plain-language drafting has been moving off "shall" for thirty years — the
 * federal rules were restyled out of it, and a great many house styles now
 * write "Vendor will indemnify" and "the director will not be personally
 * liable". The obligation is the same one. A recognizer that spells only
 * "shall" reads half its corpus.
 *
 * The metamorphic relation found three: GOV-140 could not see expenses that
 * "will be advanced", GOV-028 could not see a director who "will not be
 * personally liable", and MNA-106 could not see a seller who "will not
 * compete". A static sweep then found the same shape in a hundred and ninety
 * recognizers across fifty-one files — most already covered by a sibling
 * alternation, which is why only three showed on the corpus, and all of which
 * were one word from being blind.
 *
 * Both halves, as in `parenthetical-numeral` and `section-sign`: the static
 * ratchet is the cheap one that catches the next recognizer written with only
 * "shall", and the corpus relation is what proves the widening did not change
 * a finding.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import ts from "typescript";
import { analyzeText } from "../../tools/cli/api.js";
import { loadAccuracyDeps } from "../../tools/accuracy/pipeline.js";

const DIR = join(process.cwd(), "tests", "fixtures", "specimens");
const SPECIMENS = readdirSync(DIR).filter((f) => f.endsWith(".txt"));

function sourceFiles(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir, { withFileTypes: true }).sort((a, b) =>
    a.name.localeCompare(b.name, "en"),
  )) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) sourceFiles(path, out);
    else if (entry.name.endsWith(".ts") && !entry.name.includes(".test.")) out.push(path);
  }
  return out;
}

/** "shall" → "will", the whole corpus, both cases. */
const asWill = (s: string): string => s.replace(/\bshall\b/g, "will").replace(/\bShall\b/g, "Will");

describe("shall and will are the same obligation", () => {
  it("no recognizer reads 'shall' without also reading 'will'", () => {
    const files = sourceFiles(join(process.cwd(), "src", "engine", "rules"));
    expect(files.length, "no sources found — the walk is broken").toBeGreaterThan(50);

    const blind: string[] = [];
    for (const file of files) {
      const text = readFileSync(file, "utf8");
      const sf = ts.createSourceFile(file, text, ts.ScriptTarget.ESNext, true);
      const walk = (node: ts.Node): void => {
        if (node.kind === ts.SyntaxKind.RegularExpressionLiteral) {
          const literal = node.getText(sf);
          // NOT `\bshall\b`. The text being searched is regex SOURCE, so the
          // two characters before the word are very often `\b` — and a word
          // boundary between the "b" of that escape and the "s" of "shall"
          // does not exist. The first draft of this guard read only the
          // literals that happened not to anchor the word, which is the same
          // defect `section-sign.test.ts` was written for, one level up.
          if (/shall(?![a-z])/.test(literal) && !/will(?![a-z])/.test(literal)) {
            const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
            blind.push(`${file}:${line}  ${literal.slice(0, 90)}`);
          }
        }
        node.forEachChild(walk);
      };
      walk(sf);
    }
    expect(
      blind,
      `these read only "shall" — write (?:shall|will):\n  ${blind.join("\n  ")}`,
    ).toEqual([]);
  });

  it("writing every 'shall' as 'will' changes no finding", async () => {
    const deps = await loadAccuracyDeps({});
    const broken: string[] = [];
    let probed = 0;
    for (const name of SPECIMENS) {
      const text = readFileSync(join(DIR, name), "utf8");
      const mutated = asWill(text);
      if (mutated === text) continue;
      probed++;
      const before = await analyzeText(text, name, { deps });
      const after = await analyzeText(mutated, name, { deps });
      const ids = (r: typeof before): string[] =>
        [...new Set(r.run.findings.map((f) => f.rule_id))].sort();
      const lost = ids(before).filter((id) => !ids(after).includes(id));
      const gained = ids(after).filter((id) => !ids(before).includes(id));
      if (lost.length || gained.length) {
        broken.push(`${name}: lost ${lost.join(",") || "-"} gained ${gained.join(",") || "-"}`);
      }
    }
    expect(probed).toBeGreaterThan(150);
    expect(broken).toEqual([]);
  }, 300_000);
});
