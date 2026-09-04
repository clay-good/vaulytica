/**
 * A finding QUOTES the document. The quote must be real.
 *
 * Every finding carries an `excerpt`, and the report, the DOCX, the HTML and
 * the SARIF all show it to the reader as the words the tool is objecting to.
 * A quote that is not in the document is the worst failure this tool has: it
 * looks exactly like evidence, and a reviewer would go looking in their own
 * copy for a sentence that was never there.
 *
 * This is the invariant, checked across the whole corpus. It holds today at
 * 858 of 858, and it is pinned here so an extraction or offset regression
 * cannot quietly break it.
 *
 * What this test deliberately does NOT assert, because it is a real and
 * correct design rather than a defect:
 *
 *   - `excerpt.text` is READABLE CONTEXT and may be wider than the span. The
 *     offsets locate the matched phrase; the text gives the reader the sentence
 *     around it. Asserting `flat.slice(start, end) === text` fails on 594 of
 *     858 findings, and every one of those is the design working.
 *   - The two may point at DIFFERENT OCCURRENCES of a phrase when that is the
 *     finding's whole point. STRUCT-014 ("defined terms used in lowercase")
 *     shows the defined form "Protected Material" while its span points at the
 *     lowercase slip "protected material". The quote and the location disagree
 *     on purpose.
 *   - An ABSENCE finding has nothing to quote, so it carries a zero-width
 *     excerpt holding a synthetic label ("indemnification obligation"). 368
 *     findings do this. They are excluded here rather than asserted about.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { analyzeText } from "../../tools/cli/api.js";
import { flattenText } from "../../src/ingest/types.js";

const DIR = join(process.cwd(), "tests", "fixtures", "specimens");
const SPECIMENS = readdirSync(DIR)
  .filter((f) => f.endsWith(".txt"))
  .sort();

describe("a finding's quote is really in the document", () => {
  it("every excerpt that carries a span quotes text the document contains", async () => {
    const broken: string[] = [];
    let quoted = 0;
    let labels = 0;

    for (const name of SPECIMENS) {
      const raw = readFileSync(join(DIR, name), "utf8");
      const result = await analyzeText(raw, name);
      const flat = flattenText(result.ingest.tree);
      for (const f of result.run.findings) {
        const ex = f.excerpt;
        if (!ex) continue;
        // A zero-width excerpt is an absence finding's label, not a quote.
        if (ex.end_offset <= ex.start_offset) {
          labels += 1;
          continue;
        }
        quoted += 1;
        if (!flat.includes(ex.text)) {
          broken.push(`${name} ${f.rule_id}: ${JSON.stringify(ex.text.slice(0, 80))}`);
        }
        // The span must at least be inside the document it indexes.
        if (ex.end_offset > flat.length) {
          broken.push(
            `${name} ${f.rule_id}: span ends at ${ex.end_offset}, past the document's ${flat.length}`,
          );
        }
      }
    }

    // Floors, so the assertion cannot pass by finding nothing to check.
    expect(quoted, "no finding carried a span-bearing excerpt").toBeGreaterThanOrEqual(700);
    expect(labels, "no absence finding carried a label excerpt").toBeGreaterThanOrEqual(200);
    expect(broken).toEqual([]);
  }, 600_000);
});
