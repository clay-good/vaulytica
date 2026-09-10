/**
 * A citation's URL must point at the instrument the citation NAMES.
 *
 * The bibliography is the list of authorities an attorney checks, and a
 * finding that rests on drafting practice rather than law says so instead of
 * borrowing authority it does not have — the whole citation apparatus in this
 * repo exists to keep that honest. A link that resolves to the wrong
 * instrument breaks it just as effectively as a missing one, and more quietly,
 * because the line still LOOKS cited.
 *
 * Found by rendering the clean deal room's bundle report and reading its
 * bibliography, where entries 11, 14 and 15 read
 *
 *   Commission Implementing Decision (EU) 2021/914, Clause 14
 *     — https://eur-lex.europa.eu/eli/reg/2016/679/oj
 *
 * naming the Standard Contractual Clauses and linking to the GDPR, while entry
 * 18 linked the same instrument correctly. `dpa-gdpr`'s `cite_for` returned one
 * constant URL for all 55 of its citations, 5 of which name a different
 * instrument. Every other `cite_for` in the tree that spans more than one
 * instrument branches on the citation.
 *
 * The check runs over the citations the ENGINE ACTUALLY EMITS, not over the
 * rule source, because the finding is where a reader meets them.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { analyzeText } from "../../tools/cli/api.js";

const DIR = join(process.cwd(), "tests", "fixtures", "specimens");

/**
 * Instruments distinct enough that naming one and linking another is a
 * mistake rather than a judgment call. Each entry: how the citation names the
 * instrument, and the fragment its URL must contain.
 *
 * Deliberately narrow. A citation to a US code section may honestly link to
 * Cornell, the eCFR, or a state legislature, and choosing among those is
 * editorial. Confusing two EU instruments with their own ELIs is not.
 */
const INSTRUMENTS: ReadonlyArray<{
  readonly name: string;
  readonly names: RegExp;
  /** The URL must contain one of these. */
  readonly urls: readonly string[];
}> = [
  {
    // The narrow, unambiguous case: two EU instruments, each with its own ELI.
    name: "EU Standard Contractual Clauses",
    names: /2021\/914/,
    urls: ["dec_impl/2021/914"],
  },
  {
    // The broad case, and deliberately broad. An EU regulation has several
    // legitimate URLs — the ELI, the CELEX consolidated text, a Commission
    // guidance page for the topic the article governs — and choosing among
    // them is editorial. What is NOT editorial is linking an EU instrument to
    // a US standards body, which is what a fall-through default did for the
    // GDPR right to erasure. So the assertion is the DOMAIN, not the path.
    name: "an EU instrument",
    names:
      /^GDPR\b|Regulation \(EU\) 2016\/679|^EU (AI Act|Digital Content|Consumer Rights)|^EDPB\b/,
    urls: ["europa.eu"],
  },
];

describe("every citation links the instrument it names", () => {
  it("over every specimen the engine analyzes", async () => {
    const files = readdirSync(DIR)
      .filter((f) => f.endsWith(".txt"))
      .sort();
    const wrong = new Set<string>();
    let checked = 0;

    for (const file of files) {
      const r = await analyzeText(readFileSync(join(DIR, file), "utf8"), file);
      for (const f of r.run.findings) {
        for (const c of f.source_citations ?? []) {
          for (const inst of INSTRUMENTS) {
            if (!inst.names.test(c.source)) continue;
            checked += 1;
            if (!inst.urls.some((u) => c.source_url.includes(u))) {
              wrong.add(`${inst.name}: "${c.source}" → ${c.source_url}`);
            }
            break; // first match wins; SCC is listed before GDPR on purpose
          }
        }
      }
    }

    // Anti-vacuity: a run that emitted no citation at all, or a table whose
    // patterns match nothing, would pass with an empty `wrong` set.
    // 63 citations across the corpus match the table as measured 2026-09-10.
    expect(checked).toBeGreaterThan(50);
    expect([...wrong].sort()).toEqual([]);
  }, 300_000);
});
