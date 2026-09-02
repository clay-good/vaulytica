/**
 * `§` is how a lawyer writes "Section", and the engine could not read it.
 *
 * `\b` asserts a boundary between a word character and a non-word one. `§` is
 * a non-word character, so `\b§` can only match where the sign directly
 * follows a letter or digit — which no citation ever does. Every alternation
 * written `\b(?:Section|…|§§?)` therefore had a dead branch, and the
 * cross-reference extractor's was the one that mattered: its own doc comment
 * promises to resolve "`Section 4.2` / `Article III` / `§ 12(b)`", and the
 * third form had never been seen at all.
 *
 * Two guards, because the defect has two halves.
 *
 * The STATIC one is the cheap ratchet: no regex source in `src/` may place
 * `\b` immediately before an alternation whose branch is the section sign.
 * It is a one-line grep, it needed no corpus, and it would have caught this
 * on the day the sign was added to `REF_RE`.
 *
 * The METAMORPHIC one asks what the reader would ask: writing a reference as
 * "§ 8" instead of "Section 8" changes nothing about what a document says, so
 * the finding set must be identical. Over the 175 specimens that name a
 * numbered section it found four rules that read the word and not the sign:
 *
 *   MNA-031  "Appraisal rights / § 262 notice clause missing" — the rule
 *            spells the citation with the sign in its own TITLE and could
 *            only match `section\s+262`.
 *   RISK-016 an insurance minimum "described in § 5" — the locator list ran
 *            Section / Article / Exhibit / Schedule / Annex and stopped.
 *   FIN-005  "any amount you owe under § 4 is due within sixty (60) days" —
 *            the window between the payment noun and its deadline is a
 *            character class, and the sign was not in it.
 *   SET-008  the sharpest: the whistleblower carve-out matched "sec" INSIDE
 *            the word "Section", so a settlement passed on "Ridgeline may
 *            file the stipulated judgment described in SECtion 8" while the
 *            carve-out it actually carries — "This Section does not restrict
 *            either Party from communicating with any government agency" —
 *            was invisible, because the reader wanted the word "nothing".
 *            A true finding held up by an accident is worse than a false one.
 *
 * Headings are left alone: a heading is the outline's own source, not a
 * reference into it, and rewriting one changes what the document means.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { analyzeText } from "../../tools/cli/api.js";
import { loadAccuracyDeps } from "../../tools/accuracy/pipeline.js";

const SPECIMEN_DIR = join(process.cwd(), "tests", "fixtures", "specimens");
const SPECIMENS = readdirSync(SPECIMEN_DIR).filter((f) => f.endsWith(".txt"));

/** Every `.ts` file under `src/`, tests included — a dead branch is dead there too. */
function sourceFiles(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) sourceFiles(path, out);
    else if (entry.name.endsWith(".ts")) out.push(path);
  }
  return out;
}

/** `\b` followed by a group one of whose branches is the section sign. */
const DEAD_BOUNDARY = /\\b\((?:\?:)?[^()]*§[^()]*\)/;

/** A reference to a numbered section, never a heading, rewritten with the sign. */
const asSectionSign = (s: string): string => s.replace(/(?<!^)(?<!\n)\bSection\s+(\d)/gm, "§ $1");

describe("§ is how a lawyer writes Section", () => {
  it("no regex puts a word boundary in front of the section sign", () => {
    const dead: string[] = [];
    for (const path of sourceFiles(join(process.cwd(), "src"))) {
      readFileSync(path, "utf8")
        .split("\n")
        .forEach((line, i) => {
          if (DEAD_BOUNDARY.test(line)) dead.push(`${path}:${i + 1}`);
        });
    }
    expect(dead).toEqual([]);
  });

  it("writing a section reference with the sign changes no finding", async () => {
    const deps = await loadAccuracyDeps({});
    const broken: string[] = [];
    let probed = 0;
    for (const name of SPECIMENS) {
      const text = readFileSync(join(SPECIMEN_DIR, name), "utf8");
      const mutated = asSectionSign(text);
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
