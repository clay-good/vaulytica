/**
 * The words a real contract carries that this corpus does not.
 *
 * Every probe in this repo so far has REWRITTEN a specimen into another
 * spelling of the same thing. This one goes the other way, because of a
 * measurement: **not one of 310 specimens says "including but not limited
 * to"**, and none says "provided, however, that". They are hand-written in
 * plain modern style, and a real commercial contract is full of both. The
 * corpus cannot be rewritten out of a phrase it does not contain — so the
 * phrase is put in, and the question becomes which recognizer a few extra
 * words inside a clause knock over.
 *
 * That question has one answer over and over in this codebase: a bounded
 * window between two anchors. `[^.]{0,80}` is a bet on how much drafting fits
 * between a noun and its verb, and an appositive, a parenthetical or a
 * boilerplate formula is exactly what loses the bet.
 *
 * ── the one that matters ──
 *
 * **"limited" is not a cap when it is "not limited to".** An ordinary
 * indemnity opens "any and all claims … losses, damages, LIABILITIES, fines,
 * penalties, judgments, settlements, and expenses, including, but not LIMITED
 * to, reasonable attorneys' fees" — and the sixty-five characters between
 * "liabilities" and "limited" fit inside RISK-015's cap window. So the
 * commonest phrase in commercial English read as a liability cap, and both
 * RISK-015 and RISK-005 went silent on documents that state no cap at all.
 * Four specimens showed it the moment the phrase was put in; no specimen could
 * ever have shown it before.
 *
 * TERM-002 and ADDENDA-009 were windows a few characters too short — the gap
 * between a default and the termination verb is where a sentence lists the
 * remedies, and the gap between a penetration test and its cadence is where it
 * states the scope.
 *
 * ── what is NOT injected ──
 *
 * "up to and including termination" is a fixed idiom; "but not limited to"
 * does not go there, and putting it there makes text no drafter writes. That
 * is the same discipline the other probes reached from the other direction:
 * an injection that produces an unreal document produces unreal defects.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { analyzeText } from "../../tools/cli/api.js";
import { loadAccuracyDeps } from "../../tools/accuracy/pipeline.js";

const DIR = join(process.cwd(), "tests", "fixtures", "specimens");
const SPECIMENS = readdirSync(DIR).filter((f) => f.endsWith(".txt"));

/** Each insertion, and the number of specimens it must actually reach. */
const INJECTIONS: Record<string, [(s: string) => string, number]> = {
  "the illustrative list gains its boilerplate": [
    (s) =>
      s.replace(
        /(?<!\bup\s+to\s+and\s+)\bincluding\b(?!,?\s+(?:but|without))/g,
        "including, but not limited to,",
      ),
    150,
  ],
  "a proviso gains its interruption": [
    (s) => s.replace(/\bprovided\s+that\b/g, "provided, however, that"),
    20,
  ],
  "a defined term gains its back-reference": [
    (s) => s.replace(/\bthe Services\b(?!\s*\()/g, "the Services (as defined in Section 1)"),
    10,
  ],
};

describe("the boilerplate a real contract carries", () => {
  it.each(Object.keys(INJECTIONS))(
    "%s changes no finding",
    async (label) => {
      const [inject, floor] = INJECTIONS[label]!;
      const deps = await loadAccuracyDeps({});
      const broken: string[] = [];
      let probed = 0;
      for (const name of SPECIMENS) {
        const text = readFileSync(join(DIR, name), "utf8");
        const mutated = inject(text);
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
      expect(probed, `${label}: the corpus never carries this shape`).toBeGreaterThanOrEqual(floor);
      expect(broken).toEqual([]);
    },
    300_000,
  );

  it("no cap detector reads 'not limited to' as a cap", () => {
    // The static half, and the cheap one: a window that ends on "limited" or
    // "capped" must refuse the negated form outright, not merely happen to sit
    // far enough away from it in the specimens that exist today.
    const clause =
      "Indemnitor shall indemnify Indemnitee against all claims, losses, damages, liabilities, " +
      "and expenses, including, but not limited to, reasonable attorneys' fees.";
    for (const re of [
      /\bliabilit(?:y|ies)\b[^.]{0,80}?\b(?:shall|will|is|are|may)?\s*(?:be\s+)?(?<!\bnot\s)(?:limited|capped)/i,
      /\bliabilit(?:y|ies)\b[^.]{0,160}?\b(?<!\bnot\s)(?:capped|limited)\s+(?:at|to)\b/i,
    ]) {
      expect(re.test(clause), `${re} reads an indemnity's own preamble as a cap`).toBe(false);
    }
    // …and still reads a real one.
    expect(
      /\bliabilit(?:y|ies)\b[^.]{0,80}?\b(?:shall|will|is|are|may)?\s*(?:be\s+)?(?<!\bnot\s)(?:limited|capped)/i.test(
        "Each party's total liability under this Agreement shall be limited to the fees paid.",
      ),
    ).toBe(true);
  });
});
