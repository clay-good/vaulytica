/**
 * A table that exists four times is a table that will disagree with itself.
 *
 * The through-line of a whole session's repairs: `critical-dates.ts` and
 * `exports.ts` each carried an anchor date parser labelled "mirrors" the other,
 * and neither read a day-first date; STRUCT-003 carried THREE date shapes, two
 * of them writing a month constraint that was inert under the flag it ran with;
 * four files carried the same number-word table and two of them carried
 * byte-identical parsers over it. None of those copies was wrong when it was
 * written. Each was wrong later, because a repair reached one copy and not the
 * rest — and the copies are never listed anywhere, so nobody knows to look.
 *
 * This guard is the list. It names the vocabularies that have a single owner
 * and fails when a second definition appears, so the next repair reaches every
 * consumer by construction rather than by memory.
 *
 * It deliberately checks DEFINITIONS, not uses. A rule that writes
 * `[$€£¥₹₩₽]` inline is not carrying a copy of anything — that class IS the
 * canonical spelling, and `currency-glyph.test.ts` requires exactly it.
 */
import { readFileSync, readdirSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { join, relative } from "node:path";
import { sourceFiles, DOCUMENT_READING_ROOTS } from "./_recognizer-sources.js";

const ROOTS = ["src", "tools"];

interface Vocabulary {
  /** What the shared thing is. */
  readonly what: string;
  /** The single file allowed to define it. */
  readonly owner: string;
  /** A definition of it, distinctive enough that a USE does not match. */
  readonly definition: RegExp;
}

const VOCABULARIES: readonly Vocabulary[] = [
  {
    what: "the number-word table",
    owner: "src/extract/counts.ts",
    definition: /^\s*ninety:\s*90,\s*$/m,
  },
  {
    what: "the scale-word table (hundred / thousand / million …)",
    owner: "src/extract/counts.ts",
    definition: /^\s*trillion:\s*"?1000000000000"?,\s*$/m,
  },
  {
    what: "the month-number table",
    owner: "src/extract/absolute-date.ts",
    definition: /^\s*september:\s*9,\s*$/m,
  },
  {
    what: "the words → Decimal parser for a sum",
    owner: "src/extract/amounts.ts",
    definition: /function parseWord(?:Phrase|s)\s*\(/,
  },
  {
    what: "the first-absolute-date parser",
    owner: "src/extract/absolute-date.ts",
    definition: /function firstAbsoluteIso\s*\(/,
  },
  {
    // Four rules each spelled their own `shall|will|must|…` alternation and
    // the lists stopped at different places, so one synonym cost 30 documents
    // a finding and the next cost 36 (9.596.0 / 9.597.0). This is the registry
    // entry that keeps a fifth copy from being written.
    what: "the obligation-modal vocabulary (shall / must / is required to / undertakes to …)",
    owner: "src/engine/rules/_helpers.ts",
    definition: /export const OBLIGATION_MODAL\s*=/,
  },
  {
    // Two very different questions are answered from the instrument-noun list —
    // "does this document say it is issued under a parent?" and "is a captured
    // date anchor over-extended into a document self-reference?" — and a second
    // copy would let one of them drift. Moved out of `_helpers.ts` into the
    // extract layer in 9.650.0 so the extractor can read it without the rules
    // layer.
    what: "the instrument self-naming nouns (Agreement / Addendum / Statement of Work …)",
    owner: "src/extract/instrument-nouns.ts",
    definition: /export const SELF_NAMED_INSTRUMENT_NOUNS\s*=/,
  },
  {
    // Two rules detect a residuals clause — NDA-D-009 and OBLI-009 — and the
    // repair that taught the first one to read a clause REJECTING residuals
    // reached only that one, so a joint development agreement saying "Nothing
    // in this Agreement grants a residuals right" was still warned that a
    // residuals clause is present (9.645.0).
    // 🚨 Four files each declared their own `PRIVACY_STATEMENT`, all four
    // opening "This analysis was performed entirely inside the user's web
    // browser" — and the CLI and the GitHub Action render the same reports in
    // a Node process on a build machine. They had also already drifted: the
    // bundle's copy dropped the independent-verification sentence and the
    // comparison's dropped the developer's "no record of this analysis" too
    // (9.700.0). This is the section a reader consults precisely because they
    // want the mechanism, so a fifth copy must not be written.
    what: "the privacy statement every report surface prints",
    owner: "src/report/disclaimers.ts",
    definition: /export function privacyStatement\s*\(/,
  },
  {
    what: "the residuals-rejection patterns",
    owner: "src/engine/rules/_helpers.ts",
    definition: /export const RESIDUALS_REJECTED\s*:/,
  },
];

describe("a shared vocabulary", () => {
  it("is defined in exactly one place", () => {
    const files = ROOTS.flatMap((root) => sourceFiles(root)).filter(
      (f) => !f.includes("/node_modules/"),
    );
    expect(files.length, "no sources found — the walk is broken").toBeGreaterThan(100);

    const duplicated: string[] = [];
    const orphaned: string[] = [];
    for (const vocab of VOCABULARIES) {
      const defining = files.filter((f) => vocab.definition.test(readFileSync(f, "utf8")));
      const strays = defining.filter((f) => !f.endsWith(vocab.owner));
      for (const stray of strays) {
        duplicated.push(`${vocab.what}: ${stray} — import it from ${vocab.owner}`);
      }
      // An owner that no longer defines it means the entry is stale, and a
      // stale entry silently stops guarding — the failure mode this repo has
      // now met three times in its declared-exception lists.
      if (!defining.some((f) => f.endsWith(vocab.owner))) {
        orphaned.push(`${vocab.what}: ${vocab.owner} no longer defines it`);
      }
    }
    expect(orphaned, "stale entries — an owner that defines nothing guards nothing").toEqual([]);
    expect(duplicated, `second definitions:\n  ${duplicated.join("\n  ")}`).toEqual([]);
  });
});

/**
 * The sweeps' root list has one owner too.
 *
 * Ten static sweeps each carried their own copy of "which directories read a
 * document", and all ten said the same three and all ten omitted
 * `src/playbooks`. That is the failure this whole file exists to prevent, in
 * the test tree rather than in `src/`: a table written ten times will disagree
 * with itself, and here it disagreed with reality — the playbook interpreter
 * kept the exact blindness those sweeps exist to end, and the attachment sweep
 * was not reading `src/engine/consistency` at all, where a precedence rule
 * enumerated three of the six attachment nouns.
 *
 * `DOCUMENT_READING_ROOTS` in `_recognizer-sources.ts` is now the list. A sweep
 * whose scope is genuinely narrower should derive it from that constant and say
 * why, not write its own.
 */
/**
 * The posture statements a report prints about ITSELF — determinism, privacy,
 * not-legal-advice, and what it says where its timestamp would go.
 *
 * 🚨 All four were copied into `html.ts`, `docx.ts`, `bundle.ts` and
 * `compare-docx.ts`, and all four had DRIFTED: the bundle's privacy copy had
 * dropped the independent-verification sentence, its non-advice copy "the
 * decision … is yours and your counsel's", its determinism copy the pointer to
 * the Audit Trail where the rules that fired NOTHING are listed; and one
 * rendered report said both wordings of the blanked timestamp, a thousand
 * paragraphs apart. They were found and fixed ONE AT A TIME across 9.700.0,
 * 9.706.0 and 9.708.0 — which is why this is a table now rather than a fourth
 * bespoke test.
 *
 * 🚨 The registry above forbids a second DEFINITION; it does not forbid a
 * second copy of the VALUE, which is how every one of these drifted. That is
 * what this checks, and it was proven by pasting a literal back.
 */
type OwnedProse = {
  what: string;
  phrase: string;
  importInstead: string;
  /** Files that say it in their OWN words, on purpose, with the reason. */
  allowed?: Record<string, string>;
};

const OWNED_PROSE: ReadonlyArray<OwnedProse> = [
  {
    what: "the privacy statement",
    phrase: "was transmitted to any server",
    importInstead: "privacyStatement()",
  },
  {
    what: "the not-legal-advice statement",
    phrase: "is a software tool, not a lawyer",
    importInstead: "nonAdviceStatement()",
    allowed: {
      // The court-facing certificate says it in a COMPRESSED form, as the tail
      // of a numbered "Attorney responsibility" statement framed on ABA Formal
      // Opinion 512. Substituting the long report wording there would break a
      // deliberately terse, court-shaped document. Found by this very table —
      // the fifth copy, and the one that is not drift.
      "src/report/certificate.ts": "a numbered court-facing statement, deliberately compressed",
    },
  },
  {
    what: "the determinism statement",
    phrase: "produced by a deterministic process",
    importInstead: "determinismStatement()",
  },
  {
    what: "the blanked-timestamp line",
    phrase: "(omitted from hash",
    importInstead: "EXECUTED_AT_OMITTED",
  },
];

describe("the posture statements a report prints about itself", () => {
  const OWNER = "src/report/disclaimers.ts";

  it.each(OWNED_PROSE)(
    "$what exists as text in exactly one file",
    ({ phrase, importInstead, allowed }) => {
      const offenders: string[] = [];
      for (const root of ["src", "tools"]) {
        for (const file of sourceFiles(join(process.cwd(), root))) {
          const rel = relative(process.cwd(), file).replace(/\\/g, "/");
          if (rel === OWNER) continue;
          // Comments may quote the old wording to explain the repair.
          const code = readFileSync(file, "utf8")
            .replace(/\/\*[\s\S]*?\*\//g, "")
            .replace(/^\s*\/\/.*$/gm, "");
          if (code.includes(phrase) && !(allowed && rel in allowed)) offenders.push(rel);
        }
      }
      expect(offenders, `spelled out outside ${OWNER} — import ${importInstead} instead`).toEqual(
        [],
      );

      // An exception that no longer fires is indistinguishable from a wrong one.
      for (const file of Object.keys(allowed ?? {})) {
        expect(
          readFileSync(join(process.cwd(), file), "utf8"),
          `${file} no longer says it — delete its exception`,
        ).toContain(phrase);
      }
    },
  );
});

describe("the document-reading root list", () => {
  it("is declared in exactly one place", () => {
    const strays: string[] = [];
    // `sourceFiles` deliberately SKIPS `.test.ts`, which is every sweep — so
    // this walks the directory itself. Written the other way first, the guard
    // scanned nothing and passed on a planted copy.
    const dir = join(process.cwd(), "tests", "integration");
    const files = readdirSync(dir)
      .filter((f) => f.endsWith(".ts"))
      .map((f) => join(dir, f));
    expect(files.length, "the walk found no sweeps").toBeGreaterThan(20);
    for (const file of files) {
      if (file.endsWith("_recognizer-sources.ts")) continue;
      const src = readFileSync(file, "utf8");
      // An array literal that opens with the rules root is a copy of the list.
      if (/\[\s*"src\/engine\/rules"/.test(src) || /\[\s*\n\s*"src\/engine\/rules"/.test(src)) {
        strays.push(
          `${file.slice(file.indexOf("tests/"))} — import DOCUMENT_READING_ROOTS instead`,
        );
      }
    }
    expect(strays).toEqual([]);
  });

  it("names every directory whose source reads a document", () => {
    // A directory added under `src/` that reads documents must join the list,
    // or every sweep silently skips it. These five are the ones that do.
    expect([...DOCUMENT_READING_ROOTS].sort()).toEqual([
      "src/delivery",
      "src/engine/consistency",
      "src/engine/rules",
      "src/extract",
      "src/playbooks",
      "src/ui/v3",
    ]);
  });
});
