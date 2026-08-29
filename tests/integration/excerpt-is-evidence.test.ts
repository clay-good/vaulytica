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

const DIR = join(process.cwd(), "tests", "fixtures", "specimens");
const SPECIMENS = readdirSync(DIR)
  .filter((f) => f.endsWith(".txt"))
  .sort();

/** Whitespace is normalized on both sides: ingest rewraps, the document does not. */
const flat = (s: string) => s.replace(/\s+/g, " ").trim();

describe("an excerpt with a span is text the document contains", () => {
  it.each(SPECIMENS)(
    "%s",
    async (name) => {
      const text = readFileSync(join(DIR, name), "utf8");
      const haystack = flat(text);
      const result = await analyzeText(text, name);
      const bad: string[] = [];
      for (const finding of result.run.findings) {
        const excerpt = finding.excerpt as unknown as
          | { text?: string; start_offset?: number; end_offset?: number }
          | undefined;
        if (!excerpt?.text) continue;
        // Zero-width: an absence finding, whose excerpt is a marker.
        if ((excerpt.start_offset ?? 0) === (excerpt.end_offset ?? 0)) continue;
        const needle = flat(excerpt.text);
        // A very short excerpt matches too easily to mean anything.
        if (needle.length < 8) continue;
        if (!haystack.includes(needle))
          bad.push(`${finding.rule_id}: ${JSON.stringify(needle.slice(0, 100))}`);
      }
      expect(bad, `${name} quotes text it does not contain:\n  ${bad.join("\n  ")}`).toEqual([]);
    },
    120_000,
  );
});
