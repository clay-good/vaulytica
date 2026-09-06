/**
 * The negotiation ladder must not move when only the document's FORMAT does.
 *
 * The posture is a second surface: it is computed from the document text by
 * `custom-interpreter.ts`, not projected from `run.findings`, and it carries
 * its own `posture_hash` outside `result_hash`. So none of the format
 * relations over the finding set constrain it, and until this file it had no
 * relation at all — the same blind spot that let the interpreter ship unable
 * to read "thirty (30) days", the dominant way a contract states a period.
 *
 * What makes this surface worth its own relation is the shape of its failure.
 * A metric that locates no value is reported **unevaluable**, and an
 * unevaluable dimension does not appear as a wrong answer — it silently drops
 * off the ladder the negotiator reads. A relation over findings cannot see
 * that, because the posture is not a finding.
 *
 * The ladder is the shipped `saas-buyer` example playbook, so this exercises
 * the same positions a real team would load: three numeric metrics (liability
 * cap multiple, notice period, cure period), an uptime percentage, a
 * governing-law set, and a clause-mutuality check.
 *
 * The probe has teeth, which is the part worth checking before trusting a
 * green: across the corpus the baseline produces real, VARIED verdicts — 180
 * specimens draw a governing-law tier, 92 an indemnification tier, spread
 * across ideal / acceptable / below-acceptable. A relation whose baseline is a
 * constant proves nothing, which is the lesson `boilerplate-satisfaction`
 * taught the hard way.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ingestPaste } from "../../src/ingest/paste.js";
import { extractAll } from "../../src/extract/index.js";
import { evaluateNegotiationPosture } from "../../src/playbooks/custom-interpreter.js";
import type { NegotiationPosition } from "../../src/playbooks/custom-playbook.js";

const ROOT = process.cwd();
const DIR = join(ROOT, "tests", "fixtures", "specimens");
const SPECIMENS = readdirSync(DIR)
  .filter((f) => f.endsWith(".txt"))
  .sort();

const POSITIONS: NegotiationPosition[] = JSON.parse(
  readFileSync(join(ROOT, "docs", "v6", "examples", "saas-buyer.playbook.json"), "utf8"),
).negotiation_positions;

/** The verdict per dimension — never the guidance prose, which is playbook text. */
async function ladder(text: string): Promise<string> {
  const ingest = await ingestPaste(text);
  const posture = await evaluateNegotiationPosture(POSITIONS, {
    tree: ingest.tree,
    extracted: extractAll(ingest.tree),
  });
  return posture.positions.map((p) => `${p.dimension}=${p.tier}`).join("|");
}

const cleanCache = new Map<string, string>();
async function clean(name: string, text: string): Promise<string> {
  const hit = cleanCache.get(name);
  if (hit !== undefined) return hit;
  const value = await ladder(text);
  cleanCache.set(name, value);
  return value;
}

/** Blank lines gone, as a PDF copy-paste produces. */
const stripBlankLines = (t: string): string =>
  t
    .split("\n")
    .filter((l) => l.trim().length > 0)
    .join("\n");

/** Windows line endings, as half the world's files have. */
const crlf = (t: string): string => t.replace(/\n/g, "\r\n");

/** A blank line between every line, as a double-spaced export produces. */
const doubleSpaced = (t: string): string => t.split("\n").join("\n\n");

/** Hard-wrapped at 62 columns, as a mail client or a justified column produces. */
function hardWrap(text: string, width = 62): string {
  const out: string[] = [];
  for (const line of text.split("\n")) {
    if (line.trim().length === 0) {
      out.push("");
      continue;
    }
    let rest = line.trim();
    while (rest.length > width) {
      const slice = rest.slice(0, width + 1);
      const cut = Math.max(slice.lastIndexOf(" "), slice.lastIndexOf("-"));
      if (cut <= 0) break;
      out.push(rest.slice(0, cut + (slice[cut] === "-" ? 1 : 0)).trimEnd());
      rest = rest.slice(cut + 1).trimStart();
    }
    out.push(rest);
  }
  return out.join("\n");
}

/**
 * The same periods, said the way a plain-language drafter says them:
 * "thirty (30) days" and "30 days" both become "thirty days".
 *
 * This is the transform with PROVEN teeth, and the reason it is here rather
 * than only in `spelled-period.test.ts`, which diffs findings. Before the
 * interpreter learned to read all three spellings, this rewrite turned an
 * `ideal` verdict and three `below-acceptable` ones into `unevaluable` on four
 * specimens — a walk-away signal vanishing from the ladder. The four
 * format transforms above were green throughout, so they would not have caught
 * it: they say the surface is stable, this one says it is READ.
 */
const NOUN = "(?:business\\s+days?|calendar\\s+days?|days?|hours?|weeks?|months?|years?)";
const WORDS: Record<number, string> = {
  1: "one",
  2: "two",
  3: "three",
  5: "five",
  7: "seven",
  10: "ten",
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
const wordsOnly = (t: string): string =>
  t
    .replace(new RegExp(`\\b([a-z-]+)\\s+\\((\\d{1,3})\\)(?=\\s+${NOUN}\\b)`, "gi"), "$1")
    .replace(
      new RegExp(`(?<![\\w(.$,-])(\\d{1,3})(?=\\s+${NOUN}\\b)`, "g"),
      (m, d: string) => WORDS[Number(d)] ?? m,
    );

const TRANSFORMS: Array<[string, (t: string) => string]> = [
  ["blank lines stripped", stripBlankLines],
  ["CRLF line endings", crlf],
  ["double-spaced", doubleSpaced],
  ["hard-wrapped at 62 columns", hardWrap],
  ["periods respelled in words", wordsOnly],
];

describe("the negotiation ladder is not a function of the format", () => {
  it("no transform moves a verdict on any specimen", async () => {
    const broken: string[] = [];
    for (const name of SPECIMENS) {
      const text = readFileSync(join(DIR, name), "utf8");
      const base = await clean(name, text);
      for (const [label, fn] of TRANSFORMS) {
        const mutated = fn(text);
        if (mutated === text) continue;
        const after = await ladder(mutated);
        if (after === base) continue;
        const b = base.split("|");
        const a = after.split("|");
        const moved = b
          .map((x, i) => (x === a[i] ? null : `${x} -> ${a[i]?.split("=")[1]}`))
          .filter(Boolean);
        broken.push(`${name} [${label}]: ${moved.join("; ")}`);
      }
    }
    expect(broken).toEqual([]);
  }, 900_000);

  it("the baseline is varied, so a green above is not vacuous", async () => {
    const tally = new Map<string, number>();
    for (const name of SPECIMENS) {
      const base = await clean(name, readFileSync(join(DIR, name), "utf8"));
      for (const cell of base.split("|")) tally.set(cell, (tally.get(cell) ?? 0) + 1);
    }
    const evaluable = [...tally].filter(([k]) => !k.endsWith("=unevaluable"));
    const tiers = new Set(evaluable.map(([k]) => k.split("=")[1]!));
    const dimensions = new Set(evaluable.map(([k]) => k.split("=")[0]!));
    // A relation whose baseline is one constant value cannot fail. Require
    // real verdicts, across more than one dimension and more than one tier.
    expect(tiers, "every verdict is the same tier — the relation proves nothing").toEqual(
      new Set(["ideal", "acceptable", "below-acceptable"]),
    );
    expect(dimensions.size, "only one dimension is ever evaluable").toBeGreaterThanOrEqual(4);
    const verdicts = evaluable.reduce((n, [, v]) => n + v, 0);
    expect(verdicts, "too few real verdicts to constrain anything").toBeGreaterThan(200);
  }, 900_000);
});
