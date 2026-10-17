/**
 * A sum written with its ISO code is a sum.
 *
 * Rule patterns hand-copied the glyph class `[$€£¥₹₩₽]`, so "USD 1,000,000" —
 * how a cross-border contract writes money — was no money at all: a promissory
 * note for USD 1,000,000 drew BNK-001's CRITICAL "Maker / payee / principal
 * clause missing", a construction bond its CRITICAL "Penal sum clause missing".
 * A sweep that ran all 1,936 rules over the same clause in seven spellings found
 * nineteen that disagreed. They now share `CURRENCY_MARK` from
 * `src/extract/amounts.ts`.
 *
 * Three relations hold it:
 *   1. the token's own contract — in `src/extract/amounts.test.ts`, so a
 *      mutation run counts its kills (this file is too slow to be in it);
 *   2. behaviour — every rule gives the same answer for "$" and "USD" spellings
 *      of the same clause;
 *   3. a static ratchet — a rule source may not copy the bare glyph class again
 *      except where it is listed below with its reason.
 */
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  LAUNCH_RULES,
  V3_RULES,
  V4_RULES,
  V5_RULES,
  V6_RULES,
  V7_RULES,
  type Rule,
} from "../../src/engine/index.js";
import { buildContext } from "../../src/engine/_test-fixtures.js";
import { sourceFiles } from "./_recognizer-sources.js";

const RULES: readonly Rule[] = [
  ...LAUNCH_RULES,
  ...V3_RULES,
  ...V4_RULES,
  ...V5_RULES,
  ...V6_RULES,
  ...V7_RULES,
] as readonly Rule[];

const FRAMES = [
  "In no event shall either party's aggregate liability under this Agreement exceed @.",
  "Supplier shall maintain commercial general liability insurance with limits of not less than @ per occurrence.",
  "Tenant shall deposit @ with Landlord as a security deposit.",
  "The Purchase Price is @, payable at Closing.",
  "Licensee shall pay Licensor a one-time license fee of @.",
  "The principal amount of this Note is @.",
  "The Surety is bound in the penal sum of @.",
];

/**
 * POL-050 looks for the specific statutory gift figures "$20" / "$50" and is
 * written to the federal gift rules, not to any sum.
 */
const NOT_ANY_SUM = new Set(["POL-050"]);

function verdict(rule: Rule, text: string): string {
  const f = rule.check(buildContext(["Terms", text]));
  return (Array.isArray(f) ? f : f ? [f] : [])
    .map((x) => `${x.severity}:${x.title.replace(/(?:US)?\$?[\d,.]+/g, "#")}`)
    .sort()
    .join("|");
}

describe("every rule reads 'USD 1,000,000' as it reads '$1,000,000'", () => {
  it("over seven money clauses", () => {
    const disagree: string[] = [];
    for (const frame of FRAMES) {
      const dollar = frame.replace("@", () => "$1,000,000");
      const iso = frame.replace("@", () => "USD 1,000,000");
      for (const rule of RULES) {
        if (NOT_ANY_SUM.has(rule.id)) continue;
        const a = verdict(rule, dollar);
        const b = verdict(rule, iso);
        if (a !== b)
          disagree.push(`${rule.id} | ${frame.slice(0, 50)} | $:${a || "-"} USD:${b || "-"}`);
      }
    }
    expect(disagree).toEqual([]);
  }, 120_000);
});

/**
 * Where the bare class may stay. Each line either already lists the ISO codes
 * beside it, or deliberately reads only glyphs for a reason given here.
 */
const ALLOWED: ReadonlyArray<{ file: string; why: string }> = [
  // Words-vs-numeral mismatch: the glyph inside "(…)" is optional already.
  {
    file: "src/engine/rules/financial/FIN-001.ts",
    why: "optional glyph inside the numeral restatement",
  },
  // A FINDING-raising sublimit pattern; widening it would add findings, and it
  // has not been measured on ISO-coded certificates.
  {
    file: "src/engine/rules/v4/insurance/rules.ts",
    why: "finding-raising sublimit test, unmeasured on ISO codes",
  },
];

describe("no rule copies the bare currency glyph class", () => {
  it("routes money through CURRENCY_MARK", () => {
    const offenders: string[] = [];
    for (const file of sourceFiles("src/engine/rules")) {
      if (file.endsWith(".test.ts")) continue;
      const rel = file.replace(/^.*?(src\/engine\/rules\/)/, "$1");
      if (ALLOWED.some((a) => a.file === rel)) continue;
      readFileSync(file, "utf8")
        .split("\n")
        .forEach((line, i) => {
          if (line.includes("[$€£¥₹₩₽]") && !/\bUSD\b/.test(line))
            offenders.push(`${rel}:${i + 1}`);
        });
    }
    expect(offenders).toEqual([]);
  });
});
