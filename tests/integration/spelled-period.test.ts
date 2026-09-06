/**
 * "thirty days" is the third spelling of "thirty (30) days".
 *
 * `parenthetical-numeral.test.ts` established the first two: a drafted
 * instrument writes "sixty (60) days", and a recognizer that requires the
 * digits to be preceded by a space reads only the rarer bare-numeral form. But
 * the numeral in that convention is a CHECK on the words, and the
 * plain-language style guides — the ones every consumer notice and a growing
 * share of commercial drafting now follow — drop it: "thirty days' written
 * notice", "a thirty-day cure period", "we will notify you within seventy-two
 * hours". The words alone are the third spelling, and `(\d{1,3})\)?\s+days`
 * cannot see any of it.
 *
 * The relation below rewrites both numeric spellings as the words-only one —
 * the same period, said the way a plain-language drafter says it — and diffs
 * the findings. On the first run 48 of 225 specimens moved:
 *
 *  - **TERM-001** lost the convenience-termination notice period on 24 of them,
 *    and **TEMP-008/009** the cure period on 14 more. Both print the number
 *    they read, so a blind pattern is not a near miss — the whole finding
 *    disappears.
 *  - Where a presence rule went blind an ABSENCE finding took its place, which
 *    is the expensive half: an incident-response template that promises
 *    notification "within seventy-two hours" was told at `critical` that it
 *    states no GDPR Art. 33 deadline (PRV-039), a franchise disclosure
 *    document was told it carries no 14-day delivery window (COMM-145), and a
 *    medical-director agreement with a stated three-year term was told it
 *    fails the Anti-Kickback safe harbor's one-year minimum (HC-108).
 *
 * Twelve rules read the count as a value and are wired to {@link PERIOD_COUNT}
 * / {@link countValue}; four more (COMM-145, PRV-039, HC-108) test a specific
 * statutory number rather than parsing one, and those got that number's own
 * spelling instead of the general fragment — "seventy-two hours" is the words
 * for 72, and no other count satisfies Art. 33.
 *
 * Asserted by equality with an EMPTY list: unlike the hyphen-wrap debt in
 * `format-invariance.test.ts`, nothing here is undecidable, so a divergence is
 * a defect and not a cost.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { analyzeText } from "../../tools/cli/api.js";
import { loadAccuracyDeps } from "../../tools/accuracy/pipeline.js";
import { PERIOD_COUNT, countValue } from "../../src/extract/counts.js";
import {
  declaredExceptions,
  recognizerSources,
  sourceFiles,
  DOCUMENT_READING_ROOTS,
} from "./_recognizer-sources.js";

const WORDS: Record<number, string> = {
  1: "one",
  2: "two",
  3: "three",
  4: "four",
  5: "five",
  6: "six",
  7: "seven",
  8: "eight",
  9: "nine",
  10: "ten",
  11: "eleven",
  12: "twelve",
  14: "fourteen",
  15: "fifteen",
  20: "twenty",
  21: "twenty-one",
  24: "twenty-four",
  30: "thirty",
  45: "forty-five",
  60: "sixty",
  72: "seventy-two",
  90: "ninety",
  120: "one hundred twenty",
  180: "one hundred eighty",
};

const NOUN = "(?:business\\s+days?|calendar\\s+days?|days?|hours?|weeks?|months?|years?)";

/** "thirty (30) days" → "thirty days", and "30 days" → "thirty days". */
const wordsOnly = (s: string): string =>
  s
    .replace(new RegExp(`\\b([a-z-]+)\\s+\\((\\d{1,3})\\)(?=\\s+${NOUN}\\b)`, "gi"), "$1")
    .replace(new RegExp(`(?<![\\w(.$,-])(\\d{1,3})(?=\\s+${NOUN}\\b)`, "g"), (m, d: string) => {
      const word = WORDS[Number(d)];
      return word ?? m;
    });

describe("the period count", () => {
  it("reads the same number in all three spellings", () => {
    const re = new RegExp(`^(${PERIOD_COUNT})$`, "i");
    for (const [raw, want] of [
      ["30", 30],
      ["(30)", 30],
      ["thirty", 30],
      ["thirty (30)", 30],
      ["Thirty", 30],
      ["twenty-four", 24],
      ["forty five", 45],
      ["seventy-two", 72],
      ["one hundred twenty", 120],
      ["one hundred and eighty", 180],
      ["hundred", 100],
    ] as const) {
      const m = re.exec(raw);
      expect(m, `"${raw}" is not a period count`).not.toBeNull();
      expect(countValue(m![1]!), raw).toBe(want);
    }
  });

  it("does not read a word that merely ends in a number word", () => {
    // Without the `\b` each spelled alternative carries, "of|ten days" is a
    // ten-day period and "wri|three days" a three-day one.
    const re = new RegExp(`(${PERIOD_COUNT})\\s+days`, "i");
    expect(re.test("often days")).toBe(false);
    expect(re.test("we often wait ten days")).toBe(true);
  });

  it("yields 0 for a span it cannot have produced", () => {
    expect(countValue("")).toBe(0);
    expect(countValue("umpteen")).toBe(0);
  });
});

describe("a period spelled in words alone", () => {
  it("changes no finding on any specimen", async () => {
    const dir = join(process.cwd(), "tests", "fixtures", "specimens");
    const deps = await loadAccuracyDeps({});
    const broken: string[] = [];
    let probed = 0;
    let registered = 0;
    for (const name of readdirSync(dir).filter((f) => f.endsWith(".txt"))) {
      const text = readFileSync(join(dir, name), "utf8");
      const mutated = wordsOnly(text);
      if (mutated === text) continue;
      probed++;
      const opts = { deps, criticalDates: true } as const;
      const before = await analyzeText(text, name, opts);
      const after = await analyzeText(mutated, name, opts);
      registered += before.critical_dates?.register.length ?? 0;
      const ids = (r: typeof before): string[] =>
        [...new Set(r.run.findings.map((f) => f.rule_id))].sort();
      const lost = ids(before).filter((id) => !ids(after).includes(id));
      const gained = ids(after).filter((id) => !ids(before).includes(id));
      // The register, not only the findings. A period the deadline extractor
      // cannot read does not remove a finding; it drops or downgrades a
      // computed date on a surface that ships its own hash — and comparing
      // findings alone is blind to all of it. That is how the numeral, of all
      // spellings, turned out to be the unread one in the single-bound branch:
      // the words-only mutant GAINED register entries.
      const register = (r: typeof before): string[] =>
        (r.critical_dates?.register ?? [])
          // Neither the trigger nor the anchor: both are clause text, and this
          // transform rewrites both by construction — an unresolvable anchor
          // is sometimes "hire or 1 year after separation", the count included.
          // What must hold is the DEADLINE: its family and the date computed.
          .map((e) => `${e.kind}|${e.computed_date ?? "unresolved"}`)
          .sort();
      const regLost = register(before).filter((x) => !register(after).includes(x));
      const regGained = register(after).filter((x) => !register(before).includes(x));
      if (lost.length || gained.length || regLost.length || regGained.length) {
        broken.push(
          `${name}: lost ${lost.join(",") || "-"} gained ${gained.join(",") || "-"}` +
            ` | register lost ${regLost.length} gained ${regGained.length}`,
        );
      }
    }
    // A floor, so this cannot pass by finding no period to respell.
    expect(probed, "the corpus states no period in digits").toBeGreaterThanOrEqual(200);
    expect(registered, "no specimen produced a critical date").toBeGreaterThanOrEqual(200);
    expect(broken).toEqual([]);
  }, 300_000);
});

/**
 * The corpus proves what the corpus contains. Sixteen rules moved above; a
 * static sweep of the same shape then found fifty-two more, none of them
 * exercised by any of the 312 specimens — which is the whole reason a ratchet
 * sits beside every relation in this repo.
 *
 * The population is narrow on purpose: a recognizer that accepts ANY count
 * (`\d+`, `\d{1,3}`) is making no statement about the number, so a spelling
 * of it that the pattern cannot read is unambiguously a gap. A recognizer that
 * names a SPECIFIC number is excluded — "180 days" in a bankruptcy preference
 * clause is a statutory figure, and whether the words for it are worth reading
 * is a judgment about that statute, not a fold of presentation.
 */
const ANY_COUNT_ROOTS = DOCUMENT_READING_ROOTS;

/** A digit run of unbounded value, bound to a period noun. */
const BLIND_ANY_COUNT = new RegExp(
  String.raw`\\d(?:\{1,[0-9]\}|\+|\*)[^|]{0,26}?(?:days?|hours?|weeks?|months?|years?)`,
);

/** A pattern that already reads a count in words, by any means. */
const READS_WORDS =
  /PERIOD_COUNT|NUM_WORDS|thirty|sixty|ninety|twelve|fourteen|seventy|forty|fifteen|twenty|eighteen|five|six|seven|eight|nine|ten|eleven|one|two|three|four|\\w\+\(\?:/;

/**
 * The one exception, and it is not a period at all: FIN-004 reads a late-fee
 * INTEREST RATE — "1.5% per month" — where the digits are a percentage and the
 * period noun is the rate's denominator. No drafter writes "one point five
 * percent per month" as a count to parse.
 *
 * There used to be a second, and its removal is the point of the scanner
 * change that came with it: FIN-005 reads the words via an interpolated
 * `NUM_WORDS`, and the per-CHUNK scanner saw only the tail, which looks blind.
 * `recognizerSources` now takes a template expression whole, so the
 * interpolated name is itself the evidence and the exception is gone.
 */
const DECLARED_ANY_COUNT = declaredExceptions([
  {
    file: "src/engine/rules/financial/FIN-004.ts",
    pattern: String.raw`%\s*(?:per`,
    why: "a late-fee interest RATE — the digits are a percentage, the period noun its denominator",
  },
]);

describe("a recognizer that accepts any count", () => {
  it("reads that count in words too", () => {
    const files = ANY_COUNT_ROOTS.flatMap((root) => sourceFiles(root));
    expect(files.length, "no sources found — the walk is broken").toBeGreaterThan(50);

    const blind: string[] = [];
    for (const file of files) {
      for (const { line, text } of recognizerSources(file)) {
        if (!BLIND_ANY_COUNT.test(text) || READS_WORDS.test(text)) continue;
        if (DECLARED_ANY_COUNT.exempts(file, text)) continue;
        blind.push(`${file}:${line}  ${text.slice(0, 90)}`);
      }
    }
    // A declared exception that matches nothing is a stale one, and the same
    // failure mode `parenthetical-numeral` shipped with.
    expect(DECLARED_ANY_COUNT.unused(), "declared exceptions that match no recognizer").toEqual([]);
    expect(
      blind,
      `these accept any count but read only its digits — interpolate \${PERIOD_COUNT}:\n  ${blind.join("\n  ")}`,
    ).toEqual([]);
  });
});
