/**
 * The critical-dates register is not presentation.
 *
 * `format-invariance.test.ts` proves the FINDINGS survive every fold a PDF
 * paste, a Word export or a mail client applies. It says nothing about the
 * register, which is a second published surface with its own
 * `critical_dates_hash` — and the register is where dates live, so it is the
 * surface most exposed to exactly these transforms. Two extractor defects found
 * this session were invisible to a findings-level diff and obvious against the
 * register, which is the argument for this file.
 *
 * Eight folds hold on every specimen. The ninth is recorded rather than fixed.
 *
 * DOUBLE-SPACING moves two, and the reason is structural: a blank line between
 * every line is a paragraph break, and `classifyDeadline` reads the PARAGRAPH
 * around a reference to choose the deadline's family. Split the paragraph and
 * the word that named the family — "cure", "renewal", "terminate" — is no
 * longer beside the date, so `security-incident-response-plan.txt`'s
 * cure-window becomes the default notice-period, and
 * `saas-order-form-fields.txt` resolves an anchor it could not reach before.
 *
 * Not repaired, and no longer on the strength of an argument. The obvious fix
 * — classify from the SECTION when the paragraph yields nothing — was built
 * and measured: it reclassifies **308 of the corpus's 519 distinct register entries**.
 * An 83(b) election's filing deadline becomes an "auto-renewal-notice"; an
 * acceptable-use policy's becomes one too; an insertion order's three become
 * "cure-window". A cure clause five paragraphs away names a family it has
 * nothing to do with, exactly as predicted, and at that scale.
 *
 * So the paragraph stays authoritative, and the two entries below are the
 * price. Recorded by equality so the debt cannot grow, and so a repair cannot
 * land unnoticed.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { analyzeText } from "../../tools/cli/api.js";
import { loadAccuracyDeps } from "../../tools/accuracy/pipeline.js";

const DIR = join(process.cwd(), "tests", "fixtures", "specimens");

/** The folds that must move nothing, each already proved lossless for findings. */
const LOSSLESS: Array<[string, (t: string) => string]> = [
  ["CRLF line endings", (t) => t.replace(/\n/g, "\r\n")],
  ["fullwidth parentheses", (t) => t.replace(/\(/g, "（").replace(/\)/g, "）")],
  ["the HYPHEN a PDF emits", (t) => t.replace(/(?<=[A-Za-z])-(?=[A-Za-z])/g, "‐")],
  ["the ligatures a PDF emits", (t) => t.replace(/fi/g, "ﬁ").replace(/fl/g, "ﬂ")],
  ["the minus sign a PDF emits", (t) => t.replace(/(\d)\s*-\s*(\d)/g, "$1−$2")],
  ["Word smart quotes", (t) => t.replace(/"/g, "“").replace(/'/g, "’")],
  ["one sentence per line", (t) => t.replace(/\. (?=[A-Z])/g, ".\n")],
  ["the numero sign", (t) => t.replace(/\bNo\.\s*(?=\d)/g, "№ ")],
];

/** What double-spacing still moves, and only that. */
const DOUBLE_SPACED_DEBT: readonly string[] = [
  "saas-order-form-fields.txt: lost - gained notice-period|2028-05-01",
  "security-incident-response-plan.txt: lost cure-window|unresolved gained notice-period|unresolved",
];

/**
 * The deadline itself — its family and the date computed for it. NOT the
 * trigger or the anchor: both are clause text, and a fold that rewrites a
 * hyphen or a quote rewrites them with it.
 */
const deadlines = (r: Awaited<ReturnType<typeof analyzeText>>): string[] =>
  (r.critical_dates?.register ?? [])
    .map((e) => `${e.kind}|${e.computed_date ?? "unresolved"}`)
    .sort();

async function moved(mutate: (t: string) => string): Promise<{ moved: string[]; entries: number }> {
  const deps = await loadAccuracyDeps({});
  const out: string[] = [];
  let entries = 0;
  for (const name of readdirSync(DIR).filter((f) => f.endsWith(".txt"))) {
    const text = readFileSync(join(DIR, name), "utf8");
    const mutated = mutate(text);
    if (mutated === text) continue;
    const opts = { deps, criticalDates: true } as const;
    const before = await analyzeText(text, name, opts);
    const after = await analyzeText(mutated, name, opts);
    entries += before.critical_dates?.register.length ?? 0;
    const lost = deadlines(before).filter((x) => !deadlines(after).includes(x));
    const gained = deadlines(after).filter((x) => !deadlines(before).includes(x));
    if (lost.length || gained.length) {
      out.push(`${name}: lost ${lost.join(";") || "-"} gained ${gained.join(";") || "-"}`);
    }
  }
  return { moved: out, entries };
}

describe("the critical-dates register", () => {
  it.each(LOSSLESS)(
    "survives %s",
    async (_label, mutate) => {
      const { moved: broken, entries } = await moved(mutate);
      // A floor, so a fold cannot pass by reaching no document that has a
      // deadline. It is per-FOLD and therefore modest: the numero sign and the
      // minus sign reach only the specimens that write "No. 3" or "10-15", and
      // demanding the broad folds' corpus-wide count would make the narrow ones
      // unpassable rather than honest.
      expect(entries, "this fold reached no specimen with a deadline").toBeGreaterThanOrEqual(50);
      expect(broken).toEqual([]);
    },
    600_000,
  );

  it("moves only the two specimens double-spacing is still owed", async () => {
    const { moved: broken, entries } = await moved((t) => t.split("\n").join("\n\n"));
    expect(entries).toBeGreaterThanOrEqual(200);
    expect(broken).toEqual([...DOUBLE_SPACED_DEBT]);
  }, 600_000);
});
