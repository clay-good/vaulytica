/**
 * The same word, spelled the way the rest of the common-law world spells it.
 *
 * Session after session this repo has found that its recognizers were written
 * by someone reading an American document: "$50", "30 days", "5%". The
 * spelling of the WORDS is the same finding one layer further in. A licence
 * agreement drafted in London grants a licence, an Australian loan is repaid
 * in instalments, a Canadian policy names a compliance programme, and an
 * indemnity anywhere outside the United States covers the cost of the defence.
 * Each is the same clause a recognizer already knows; only the spelling moved.
 *
 * The metamorphic half found one on the corpus: a US Small Business
 * Administration loan whose "one hundred twenty (120) monthly INSTALMENTS"
 * made FIN-005 report that the loan states no payment term at all. One
 * specimen, because all 310 are hand-typed in American spelling — which is
 * exactly the thinness these probes exist to work around, and exactly why the
 * static half matters more here than usual. It found the other 143.
 *
 * The widening is a tolerance, not a change in what any rule MEANS: every
 * pattern still matches everything it matched before, so no rule version is
 * stamped and no fixture moved. See the same reasoning in
 * `apostrophe-tolerance` and `shall-will`.
 *
 * Deliberately NOT in the table:
 *
 *   - **judgment.** English courts spell a court's decision "judgment" too;
 *     "judgement" is the faculty of judgement, a different word.
 *   - **practice / licence as a VERB.** British English splits the noun from
 *     the verb (a solicitor holds a practising certificate and a licence to
 *     practise). Only the noun forms are widened, and "licensed", "licensee",
 *     "licensing" are spelled the same on both sides of the Atlantic.
 *   - **check.** A cheque is the payment instrument; a background check, a
 *     conflicts check and a check-in are not, and they are what the catalog
 *     actually reads.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";
import { maskEscapes, recognizerSources, sourceFiles } from "./_recognizer-sources.js";
import { analyzeText } from "../../tools/cli/api.js";
import { loadAccuracyDeps } from "../../tools/accuracy/pipeline.js";

const DIR = join(process.cwd(), "tests", "fixtures", "specimens");
const SPECIMENS = readdirSync(DIR).filter((f) => f.endsWith(".txt"));

/**
 * The American spelling a recognizer must not read alone, and the pattern that
 * reads both. A source hit is forgiven when the tolerant form is already
 * present, which is what makes this a ratchet rather than a one-off sweep.
 */
const VARIANTS: [word: RegExp, tolerant: string][] = [
  // A stem is as often TRUNCATED as spelled out — `/authoriz/i`, `authoriz\\w+`,
  // `amortiz(?:ed|able)` — and the endings-only lookahead that seemed safe
  // walked straight past EMP-150, the one the corpus then caught.
  [
    /(?<![a-zA-Z])[a-z]{3,}iz(?![a-z])|(?<![a-zA-Z])[a-z]{3,}iz(?=e(?![a-z])|es(?![a-z])|ed(?![a-z])|ing|abl|ation)/,
    "i[sz]",
  ],
  [/(?<![a-zA-Z])(?:sub)?licens(?=es?(?![a-z])|[^a-z])|(?<![a-zA-Z])(?:sub)?licens$/i, "licen[cs]"],
  [/(?<![a-zA-Z])labor(?![a-zA-Z])/, "labou?r"],
  [/(?<![a-zA-Z])defense(?![a-zA-Z])/, "defen[cs]e"],
  [/(?<![a-zA-Z])offense(?![a-zA-Z])/, "offen[cs]e"],
  [/(?<![a-zA-Z])favor(?![a-zA-Z])/, "favou?r"],
  [/(?<![a-zA-Z])honor(?![a-zA-Z])/, "honou?r"],
  [/(?<![a-zA-Z])center(?![a-zA-Z])/, "cent(?:er|re)"],
  [/(?<![a-zA-Z])installments?(?![a-zA-Z])/, "instal?lment"],
  [/(?<![a-zA-Z])enrollment(?![a-zA-Z])/, "enrol?lment"],
  [/(?<![a-zA-Z])acknowledgment(?![a-zA-Z])/, "acknowledge?ment"],
  [/(?<![a-zA-Z])program(?![a-zA-Z])/, "programme?"],
];

/**
 * A hit that is NOT a spelling variant, keyed by `path:line`.
 *
 * The one kind there is: a US statute's PROPER NAME. California's Labor Code
 * is spelled "Labor Code" in London too — it is the name of a thing, not a
 * word the drafter chose a spelling for — so widening it to `labou?r` would
 * make the recognizer match a statute that does not exist.
 */
const NOT_A_VARIANT: Readonly<Record<string, string>> = {
  "src/engine/rules/v4/settlement/rules.ts:527": "California Labor Code — a statute's proper name",
};

// `\bauthorize` has the letter "b" immediately in front of "authorize", so a
// lookbehind for a letter — written to keep "capsize" and "citizen" out —
// silently skips every anchored recognizer there is. That is the `\b§` defect
// of the last session in a new costume, and it is why `maskEscapes` exists.
describe("a word spelled the way the rest of the common law spells it", () => {
  it("no recognizer reads only the American spelling", () => {
    const files = [
      ...sourceFiles(join(process.cwd(), "src", "engine", "rules")),
      ...sourceFiles(join(process.cwd(), "src", "extract")),
    ];
    expect(files.length, "no sources found — the walk is broken").toBeGreaterThan(50);

    const blind: string[] = [];
    const usedExceptions = new Set<string>();
    for (const file of files) {
      for (const { line, text } of recognizerSources(file)) {
        const masked = maskEscapes(text);
        for (const [word, tolerant] of VARIANTS) {
          if (!word.test(masked) || text.includes(tolerant)) continue;
          const key = `${relative(process.cwd(), file).replace(/\\/g, "/")}:${line}`;
          if (key in NOT_A_VARIANT) {
            usedExceptions.add(key);
            continue;
          }
          blind.push(`${key}  ${text.slice(0, 90)}`);
        }
      }
    }
    expect(blind).toEqual([]);

    // An exception that no longer fires is indistinguishable from a wrong one,
    // and a path-keyed set silently stops applying on Windows unless something
    // asserts it was USED. (`sourceFiles` returns POSIX separators for exactly
    // this reason; the relative path is normalized again here.)
    expect(
      Object.keys(NOT_A_VARIANT).filter((k) => !usedExceptions.has(k)),
      "these NOT_A_VARIANT entries no longer fire — delete them",
    ).toEqual([]);
  });

  it("rewriting the corpus into Commonwealth spelling changes no finding", async () => {
    const deps = await loadAccuracyDeps({});
    // ALL-CAPS stays ALL-CAPS, Capitalised stays Capitalised.
    const carryCase = (src: string, out: string): string => {
      if (src === src.toUpperCase() && src !== src.toLowerCase()) return out.toUpperCase();
      if (src[0] === src[0]!.toUpperCase() && src[0] !== src[0]!.toLowerCase()) {
        return out[0]!.toUpperCase() + out.slice(1);
      }
      return out;
    };
    const british = (s: string): string =>
      s
        .replace(
          /\b(auth|recogn|organ|real|minim|maxim|util|analy|summar|penal|jeopard|character|special|prior|standard|harmon|amort|equal|final|formal|general|legal|local|normal|optim|public|stabil|subsid|capital|memor|author|itemi|notar|saniti|hospitali)iz(e|es|ed|ing|ation|ations|able)\b/gi,
          (_m, stem: string, tail: string) => `${stem}is${tail}`,
        )
        .replace(/\b(D|d)efense\b/g, "$1efence")
        .replace(/\b(O|o)ffense(s?)\b/g, "$1ffence$2")
        .replace(/\b(L|l)abor\b/g, "$1abour")
        .replace(/\b(F|f)avor(s|ed|ing|able|ably)?\b/g, (_m, c: string, t = "") => `${c}avour${t}`)
        .replace(/\b(H|h)onor(s|ed|ing|able)?\b/g, (_m, c: string, t = "") => `${c}onour${t}`)
        .replace(/\b(I|i)nstallment(s?)\b/g, "$1nstalment$2")
        .replace(/\b(E|e)nrollment(s?)\b/g, "$1nrolment$2")
        .replace(/\b(A|a)cknowledgment(s?)\b/g, "$1cknowledgement$2")
        // The noun. British English splits it from the verb — a solicitor
        // holds a licence and is licensed to practise — so only the noun
        // forms move, exactly as the static table above reads them.
        //
        // ALL-CAPS included, unlike every rewriting above it. The title is
        // where routing is decided and a title is written "TRADEMARK LICENSE
        // AGREEMENT"; a rewriting that moves the body and leaves the heading
        // is not the same document, and with the heading left alone this
        // relation could not see a single one of the four playbook re-routes
        // that were live when it was widened.
        //
        // The case must be CARRIED, not flattened. A first pass that wrote
        // "2. licence Grant." for "2. License Grant." stopped the heading
        // looking like a heading, unregistered the section, and reported
        // STRUCT-007 against a reference to it — a defect manufactured by the
        // probe, in the same family as the "capitalizeed" one above.
        .replace(/\blicense(s?)\b/gi, (m: string, tail: string) => carryCase(m, `licence${tail}`))
        .replace(/\bcenter(s?)\b/gi, (m: string, tail: string) => carryCase(m, `centre${tail}`));

    const broken: string[] = [];
    let probed = 0;
    for (const name of SPECIMENS) {
      const text = readFileSync(join(DIR, name), "utf8");
      const mutated = british(text);
      if (mutated === text) continue;
      probed++;
      const before = await analyzeText(text, name, { deps });
      const after = await analyzeText(mutated, name, { deps });
      // Which playbook the document ROUTED to, checked before the findings.
      // A re-route is the worse failure and it hides behind the finding diff:
      // the report is not thin, it is about a different document. Four of
      // these were live — a trade mark licence read as a copyright licence, a
      // patent licence as a EULA, a EULA as a copyright licence, an HIPAA
      // notice acknowledgement as the notice itself — and every finding this
      // relation would have reported traced back to one of them, not to a
      // rule. They were invisible here because `british` did not turn a
      // license into a licence. `matcher.ts` now folds the spellings the way
      // it already folds apostrophes, hyphens and the attachment nouns.
      if (before.playbook_id !== after.playbook_id) {
        broken.push(`${name}: routed ${before.playbook_id} -> ${after.playbook_id}`);
      }
      const ids = (r: typeof before): string[] =>
        [...new Set(r.run.findings.map((f) => f.rule_id))].sort();
      const lost = ids(before).filter((id) => !ids(after).includes(id));
      const gained = ids(after).filter((id) => !ids(before).includes(id));
      if (lost.length || gained.length) {
        broken.push(`${name}: lost ${lost.join(",") || "-"} gained ${gained.join(",") || "-"}`);
      }
    }
    // The corpus is hand-typed in American spelling, so the reverse direction
    // has nothing to turn back and is not asserted. The floor is what keeps
    // this relation from passing on an empty sweep.
    expect(probed, "the corpus never carries an American-only spelling").toBeGreaterThanOrEqual(
      150,
    );
    expect(broken).toEqual([]);
  }, 300_000);
});
