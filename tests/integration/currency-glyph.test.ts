/**
 * The same figure, in the currency the rest of the world states it in.
 *
 * Session 28 gave the rule layer the extractor's own `CURRENCY_TOKEN` after
 * finding forty documents whose insurance minimum, written "USD 2,000,000",
 * was not read as a coverage limit. This is the other half of that: the
 * GLYPH. A liability cap of £5,000,000 is a liability cap, a settlement of
 * €425,000 is a settlement, and twenty-nine recognizers could see neither.
 *
 * FIN-005 is the one the corpus caught, on seven documents and identically for
 * both glyphs. Its clause windows list the characters a payment sentence may
 * contain on the way to its deadline — `[\s\w,()$."'“”’…]` — so "shall pay
 * £425,000 … within thirty (30) days" ended the window at the pound sign and
 * the rule reported that no payment term was stated. A character CLASS is the
 * one place a rule cannot use `CURRENCY_TOKEN`, which is an alternation; hence
 * `CURRENCY_GLYPHS`, which the token is itself built from, so there is still
 * one answer and not a fortieth.
 *
 * ── what is deliberately NOT widened ──
 *
 * A LITERAL amount is a US statutory threshold and stays a dollar figure
 * wherever it is read: the $100,000 ISO limit of IRC § 422(d), the $10,000
 * currency-transaction report, the $20 and $50 federal gift rules, the $25,000
 * de minimis. A recognizer that reads a digit CLASS reads whatever figure the
 * document happens to carry, and only that one must admit the other glyphs.
 * Same discipline as `clause-numbering`, and as session 28's rule for
 * statutory section numbers: **suppress on the numbering, not on a list.**
 *
 * The escape-a-string-for-a-regex idiom (`/[.*+?^${}()|[\]\\]/g`) carries a
 * dollar too. It is not reading a document at all.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { CURRENCY_GLYPHS } from "../../src/extract/amounts.js";
import { analyzeText } from "../../tools/cli/api.js";
import { loadAccuracyDeps } from "../../tools/accuracy/pipeline.js";
import { recognizerSources, sourceFiles } from "./_recognizer-sources.js";

const DIR = join(process.cwd(), "tests", "fixtures", "specimens");
const SPECIMENS = readdirSync(DIR).filter((f) => f.endsWith(".txt"));

/** The one spelling a recognizer may use, and it is the extractor's own set. */
const CANONICAL = `[${CURRENCY_GLYPHS}]`;

/**
 * `src/extract/amounts.ts` defines the set, and its `C$` / `A$` / `R$` prefix
 * branch is a dollar on purpose — there is no such thing as a Canadian euro.
 */
const DECLARED = new Set(["src/extract/amounts.ts"]);

const swap =
  (glyph: string, word: string) =>
  (s: string): string =>
    s
      .replace(/\$(?=[\d(])/g, glyph)
      .replace(/\b(?:U\.?S\.?\s*)?dollars?\b/gi, (m) =>
        m === m.toUpperCase() ? word.toUpperCase() : word,
      )
      .replace(/\bUSD\b/g, glyph === "£" ? "GBP" : "EUR");

describe("a figure stated in another currency", () => {
  it("no recognizer that reads an arbitrary amount admits only the dollar", () => {
    const files = [
      ...sourceFiles(join(process.cwd(), "src", "engine", "rules")),
      ...sourceFiles(join(process.cwd(), "src", "extract")),
      ...sourceFiles(join(process.cwd(), "src", "engine", "consistency")),
    ];
    expect(files.length, "no sources found — the walk is broken").toBeGreaterThan(50);

    const blind: string[] = [];
    for (const file of files) {
      if (DECLARED.has(file.slice(file.indexOf("src/")))) continue;
      for (const { line, text } of recognizerSources(file)) {
        const isEscapeHelper = /\[\.\*\+\?\^\$\{\}/.test(text.replace(/\\/g, ""));
        const readsAnyAmount =
          /\\+\$(?:\\+s\*)?(?:\\+d|\[[\\d0-9,]|[|)])/.test(text) ||
          /\[[^\]]*\$[^\]]*\]/.test(text);
        if (readsAnyAmount && !isEscapeHelper && !text.includes(CANONICAL)) {
          blind.push(`${file}:${line}  ${text.slice(0, 90)}`);
        }
      }
    }
    expect(
      blind,
      `these read only the dollar glyph — write ${CANONICAL}:\n  ${blind.join("\n  ")}`,
    ).toEqual([]);
  });

  it.each([
    ["£", "pounds"],
    ["€", "euro"],
  ])("restating the corpus in %s changes no finding", async (glyph, word) => {
    const deps = await loadAccuracyDeps({});
    const mutate = swap(glyph, word);
    const broken: string[] = [];
    let probed = 0;
    for (const name of SPECIMENS) {
      const text = readFileSync(join(DIR, name), "utf8");
      const mutated = mutate(text);
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
    // The rewriting must be TOTAL. An earlier draft left "DOLLARS" in an
    // all-caps guaranty standing next to the pound signs it had just written,
    // and FIN-003 correctly reported a document in two currencies — nine
    // divergences that were not defects, for the same reason the first
    // `clause-numbering` draft produced nine of its own.
    expect(probed, "the corpus never states a figure").toBeGreaterThanOrEqual(150);
    expect(broken).toEqual([]);
  }, 300_000);
});
