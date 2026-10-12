/**
 * An excerpt with a span is EVIDENCE, and evidence is text the document says.
 *
 * A finding carries three things a reader acts on: a title, a span the report
 * highlights, and an excerpt it prints beside it. An ABSENCE finding has no
 * span — it is zero-width, and its excerpt is rule-authored marker text saying
 * the clause is not there. Every other finding points at a range and quotes
 * from it, and the quote has to be findable in the document, or the reader is
 * sent to a passage that does not say what they were told it says.
 *
 * STRUCT-005 printed a comma-joined list of every unused defined term as its
 * excerpt while pointing at the paragraph that defines the first one. Three
 * specimens carried that. The list belongs in the description.
 *
 * The sweep runs the whole specimen corpus, so it covers every rule any of the
 * hundred-plus documents reaches.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { analyzeText } from "../../tools/cli/api.js";
import { excerptNeedle } from "./_excerpt.js";

const DIR = join(process.cwd(), "tests", "fixtures", "specimens");
const SPECIMENS = readdirSync(DIR)
  .filter((f) => f.endsWith(".txt"))
  .sort();

/** Whitespace is normalized on both sides: ingest rewraps, the document does not. */
const flat = (s: string) => s.replace(/\s+/g, " ").trim();

/** Does SOME occurrence of the quote begin (and, unless truncated, end) on a word edge? */
function wordAligned(haystack: string, needle: string, truncated: boolean): boolean {
  const word = (c: string | undefined) => c !== undefined && /\w/.test(c);
  for (let at = haystack.indexOf(needle); at >= 0; at = haystack.indexOf(needle, at + 1)) {
    const startOk = !(word(haystack[at - 1]) && word(needle[0]));
    const endOk =
      truncated || !(word(haystack[at + needle.length]) && word(needle[needle.length - 1]));
    if (startOk && endOk) return true;
  }
  return false;
}

/**
 * 🚨 HOW MANY EXCERPTS THIS FILE ACTUALLY INSPECTED. Without it the sweep has
 * two ways to report green having checked nothing: `it.each([])` registers ZERO
 * tests if the listing comes back empty, and a specimen whose findings carry no
 * `excerpt.text` skips the inner loop entirely, so `bad` is empty because
 * nothing was looked at. The repo met the same shape in its browser suite,
 * where a third of the specs passed against a different application.
 */
let inspected = 0;

describe("an excerpt with a span is text the document contains", () => {
  it("has a corpus to sweep", () => {
    expect(SPECIMENS.length).toBeGreaterThan(300);
  });

  it.each(SPECIMENS)(
    "%s",
    async (name) => {
      const text = readFileSync(join(DIR, name), "utf8");
      const haystack = flat(text);
      const result = await analyzeText(text, name);
      const bad: string[] = [];
      const endCut: string[] = [];
      for (const finding of result.run.findings) {
        const excerpt = finding.excerpt as unknown as
          | { text?: string; start_offset?: number; end_offset?: number }
          | undefined;
        if (!excerpt?.text) continue;
        // Zero-width: an absence finding, whose excerpt is a marker.
        if ((excerpt.start_offset ?? 0) === (excerpt.end_offset ?? 0)) continue;
        const raw = flat(excerpt.text);
        // 🚨 A TRAILING ELLIPSIS IS A MARK, NOT A QUOTE. Rules cut a long
        // clause to a display length, and 196 of the corpus's 1,445 excerpts
        // used to end mid-word with nothing to say they had been cut — the
        // report quoting the client's contract and stopping at "…remove
        // Halcyon bran". `truncate()` marks the cut, and the mark is not
        // document text, so it comes off before the containment check.
        //
        // The constraint is TIGHTENED, not relaxed: the ellipsis may appear
        // only at the very end. One in the middle would mean a spliced quote —
        // two passages joined into a sentence the document never says — which
        // is the failure this whole file exists to prevent.
        const { needle, spliced } = excerptNeedle(raw);
        if (spliced)
          bad.push(`${finding.rule_id}: spliced quote — ${JSON.stringify(raw.slice(0, 100))}`);
        // A very short excerpt matches too easily to mean anything.
        if (needle.length < 8) continue;
        if (!haystack.includes(needle)) {
          bad.push(`${finding.rule_id}: ${JSON.stringify(needle.slice(0, 100))}`);
          continue;
        }
        // 🚨 A QUOTE STARTS AND ENDS ON A WORD. FIN-009 sliced a raw 30
        // characters back from its match and quoted four specimens from the
        // middle of a word — "ys after its due date bears a late charge" —
        // while `excerptWindow` sat in `_helpers.ts`. Every occurrence is
        // tried, because a term's first occurrence may sit inside its plural
        // ("Covered Claim" in "Covered Claims") while a later one stands
        // alone.
        const truncated = flat(excerpt.text) !== needle;
        if (!wordAligned(haystack, needle, truncated))
          bad.push(`${finding.rule_id}: cut mid-word — ${JSON.stringify(needle.slice(0, 60))}`);
        inspected++;

        // 🚨 This used to say "a truncated quote's END is the ellipsis's
        // business", and that sentence was the hole. The START boundary was
        // guarded in all three excerpt paths; the END was guarded in none, so
        // `architect-agreement.txt` put SEVEN OF NINE quotes in front of a
        // reader ending mid-word — "…conditioned on payment of the fees ea…",
        // "…expenses incurred through t…". An ellipsis says the quote was
        // shortened; it does not excuse shortening it through the middle of a
        // word.
        //
        // ⚠️ A quote whose last word genuinely continues in the document is the
        // same text read two ways, so the test is: the character AFTER the
        // quote's final word, in the document, must not be a word character.
        if (truncated) {
          const body = flat(excerpt.text).replace(/…+$/, "").trimEnd();
          const at = haystack.indexOf(body);
          if (at >= 0) {
            const next = haystack.charAt(at + body.length);
            if (/\w/.test(next))
              endCut.push(
                `${finding.rule_id}: ellipsis mid-word — ${JSON.stringify(body.slice(-40))}`,
              );
          }
        }
      }
      expect(bad, `${name} quotes text it does not contain:\n  ${bad.join("\n  ")}`).toEqual([]);
      expect(endCut, `${name} ends a quote inside a word:\n  ${endCut.join("\n  ")}`).toEqual([]);
    },
    120_000,
  );

  // Runs last, after every case above. See `inspected`: this is what makes the
  // greens above mean something.
  it("inspected the excerpts it claims to have checked", () => {
    expect(inspected).toBeGreaterThan(1_000);
  });
});
