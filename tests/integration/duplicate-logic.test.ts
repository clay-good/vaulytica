/**
 * The general form of `shared-vocabulary.test.ts`: nothing in the semantic
 * layer is written twice.
 *
 * That guard names each shared vocabulary and its owner, which works because a
 * vocabulary is a thing you can name. Duplicated LOGIC is not — nobody sets out
 * to write `findDenial` four times, and the copies never announce themselves.
 * They were found by hashing every function body in the tree and looking for
 * collisions, and what turned up was not decorative:
 *
 *  - **`findDenial`, four times** — in `_regulated-rule.ts`, `v4/_helpers.ts`,
 *    and the BAA and NDA-deep helpers as `findBaaDenial` / `findNdaDenial`,
 *    renamed and otherwise character-for-character identical. A denial is the
 *    predicate deciding whether a clause a document APPEARS to carry has been
 *    disclaimed, so a repair to one copy would change what one rule pack
 *    believes about a sentence and leave three believing the old thing.
 *  - **The bad-pattern scan, twice** — its counterpart, and beside it.
 *  - **The governing-law collector, four times in one function** — the four
 *    shapes differ only in the pattern that finds them, and the
 *    capitalized-name check, the negation guard, the dedupe and the emitted
 *    clause were written out four times each. Consolidating them found a FIFTH
 *    shape whose sibling's comment claimed a guard it does not have.
 *
 * `src/report` is in scope too, and the first sweep of it found the same shape
 * one layer up: `docx.ts`, `compare-docx.ts` and `bundle.ts` each declared
 * their own `MINT = "00A883"`, their own font and body size, and a
 * byte-identical `para`, `headerRow` and `bodyRow` — while `v3/_dx.ts` had
 * been exporting all of them the whole time. Four copies of a brand colour is
 * four chances for one report to be a different green from another, and a
 * heading row styled one way in the bundle report and another way in the
 * single-document report is the kind of difference nobody notices until a
 * client does. They now live in `_docx-primitives.ts`.
 *
 * Twelve lines is the floor. Below it a collision is as often two honest
 * four-line guards that happen to agree as it is a copy.
 */
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import ts from "typescript";
import { describe, expect, it } from "vitest";
import { declaredExceptions, sourceFiles } from "./_recognizer-sources.js";

const ROOTS = ["src/engine", "src/extract", "src/report"];
const MIN_LINES = 12;

interface Body {
  readonly where: string;
  readonly lines: number;
}

function bodies(file: string): Map<string, Body[]> {
  const sf = ts.createSourceFile(file, readFileSync(file, "utf8"), ts.ScriptTarget.ESNext, true);
  const out = new Map<string, Body[]>();
  const walk = (node: ts.Node): void => {
    const isFn =
      ts.isFunctionDeclaration(node) ||
      ts.isMethodDeclaration(node) ||
      ts.isArrowFunction(node) ||
      ts.isFunctionExpression(node);
    if (isFn && node.body) {
      const text = node.body.getText(sf);
      const lines = text.split("\n").length;
      if (lines >= MIN_LINES) {
        // Whitespace-normalized, so an identical body reformatted differently
        // still collides. NAMES are kept: two functions that differ only in
        // which variable they read are not the same function.
        const key = createHash("sha256").update(text.replace(/\s+/g, " ").trim()).digest("hex");
        const name =
          ts.isFunctionDeclaration(node) || ts.isMethodDeclaration(node)
            ? (node.name?.getText(sf) ?? "<anonymous>")
            : "<anonymous>";
        const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
        out.set(key, [...(out.get(key) ?? []), { where: `${file}:${line} ${name}`, lines }]);
      }
    }
    node.forEachChild(walk);
  };
  walk(sf);
  return out;
}

/**
 * What is duplicated on purpose, or not worth the abstraction that would
 * remove it.
 *
 * `renderDisclaimer` reads identically in `bundle.ts` and `compare-docx.ts`,
 * but each calls its OWN `h1`, `h3` and `spacer`, and those three have already
 * diverged between the two files — bundle's `h1` is not compare's `h1`. Moving
 * the shared body would silently impose one file's heading sizes on the other
 * report, which is a change to what a customer sees, not a refactor. The
 * honest fix is to unify the headings first; that is a deliberate design pass,
 * not something this guard should force.
 *
 * The two coherence pairs are the ascending and descending halves of one
 * analysis inside a single file. They are parallel by construction and read
 * better side by side than behind a `direction` parameter.
 */
const DECLARED = declaredExceptions([
  {
    file: "src/report/bundle.ts",
    pattern: "renderDisclaimer",
    why: "identical body, different h1/h3/spacer — unifying it changes the rendered report",
  },
  {
    file: "src/report/compare-docx.ts",
    pattern: "renderDisclaimer",
    why: "the other half of the same pair",
  },
  {
    file: "src/report/coherence-latency.ts",
    pattern: "<anonymous>",
    why: "the two halves of one analysis, parallel by construction",
  },
  {
    file: "src/report/coherence-relapse.ts",
    pattern: "<anonymous>",
    why: "the two halves of one analysis, parallel by construction",
  },
]);

describe("logic in the semantic layer", () => {
  it("is not written twice", () => {
    const files = ROOTS.flatMap((root) => sourceFiles(root));
    expect(files.length, "no sources found — the walk is broken").toBeGreaterThan(50);

    const all = new Map<string, Body[]>();
    let scanned = 0;
    for (const file of files) {
      for (const [key, found] of bodies(file)) {
        scanned += found.length;
        all.set(key, [...(all.get(key) ?? []), ...found]);
      }
    }
    // A floor, so a broken walk cannot pass by hashing nothing.
    expect(scanned, "no function bodies were hashed").toBeGreaterThan(100);

    const duplicated = [...all.values()]
      .filter((group) => group.length > 1)
      .filter((group) => !group.every((g) => DECLARED.exempts(g.where.split(":")[0]!, g.where)))
      .sort((a, b) => (b[0]?.lines ?? 0) - (a[0]?.lines ?? 0))
      .map((group) => `${group[0]!.lines} lines:\n    ${group.map((g) => g.where).join("\n    ")}`);

    expect(DECLARED.unused(), "declared exceptions that match no duplicate").toEqual([]);
    expect(
      duplicated,
      `these bodies are identical — give them one owner:\n  ${duplicated.join("\n  ")}`,
    ).toEqual([]);
  });
});
