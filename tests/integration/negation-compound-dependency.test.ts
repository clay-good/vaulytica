/**
 * Which findings depend on a NEGATED adjective?
 *
 * A hyphen is a word boundary, so a `\b`-anchored recognizer for "exclusive"
 * opens inside "non-exclusive" — and there the compound means the opposite of
 * the word the pattern was written for. 9.653.0 fixed the same shape one layer
 * down, where the `\b` of `MODAL_RE` opened inside "at-will" and read the
 * "will" as an obligation modal, producing 22 nonsense rows in the obligations
 * ledger. This file asks the question of the whole rule engine instead of one
 * extractor.
 *
 * The transform strips the negation: `non-exclusive` becomes `exclusive`,
 * `non-binding` becomes `binding`. That INVERTS the document's meaning, so
 * this is not an invariance relation and movement is not automatically a
 * failure. It is a DEPENDENCY probe, and the number it pins answers a question
 * no other guard here asks: how much of the finding set turns on one of these
 * words?
 *
 * Today the answer is **none of it**, over the 51 specimens that carry such a
 * compound — and that was checked rather than assumed. The sharpest candidate
 * for a false read is `subcontract-complete.txt`, whose dispute clause sends
 * disputes to "non-binding mediation administered by the American Arbitration
 * Association": a rule matching a bare "binding" plus "arbitration" would call
 * that a mandatory-arbitration clause. `CHOICE-006` requires the two words
 * together and correctly stays silent; rewrite the phrase to "binding
 * arbitration" and it fires. So the zero is correctness, not blindness.
 *
 * **When this number moves, that is the signal to act on, not the failure.** A
 * rule whose outcome now turns on one of these adjectives has just been added,
 * and the author owes an answer to one question: does it read the `non-`, or
 * only the adjective? If it reads the negation correctly, raise the number and
 * say which rule and why. If it does not, the rule is reading documents
 * backwards.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { analyzeText } from "../../tools/cli/api.js";

const DIR = join(process.cwd(), "tests", "fixtures", "specimens");

/**
 * Adjectives whose `non-` compound means the OPPOSITE. Deliberately not
 * "non-disclosure", "non-compete" or "non-solicitation": those name a KIND of
 * clause rather than negating one, and a rule that matches "disclosure" inside
 * "non-disclosure agreement" is reading the document correctly.
 */
const INVERTING = [
  "exclusive",
  "binding",
  "transferable",
  "assignable",
  "revocable",
  "refundable",
  "conforming",
  "recurring",
  "terminable",
  "cancellable",
  "negotiable",
];

const NEGATED = new RegExp(String.raw`\bnon[-‐‑ ]?(${INVERTING.join("|")})`, "gi");

/** Rule id + severity. Never the excerpt, which the rewrite edits by design. */
async function findingSet(text: string, name: string): Promise<string> {
  const r = await analyzeText(text, name);
  return r.run.findings
    .map((f) => `${f.rule_id}@${f.severity}`)
    .sort()
    .join("|");
}

/**
 * Specimens whose findings change when the negation is stripped. Committed by
 * equality — see the header for what to do when it moves.
 */
const DEPENDENT: string[] = [];

/** Specimens carrying at least one inverting `non-` compound. Anti-vacuity. */
const CARRIERS = 51;

describe("findings that depend on a negated adjective", () => {
  it("names every specimen whose finding set turns on a non- compound", async () => {
    const moved: string[] = [];
    let carriers = 0;
    let baselineFindings = 0;

    for (const file of readdirSync(DIR)
      .filter((f) => f.endsWith(".txt"))
      .sort()) {
      const text = readFileSync(join(DIR, file), "utf8");
      const stripped = text.replace(NEGATED, (_m, word: string) => word);
      if (stripped === text) continue;
      carriers += 1;
      const before = await findingSet(text, file);
      baselineFindings += before === "" ? 0 : before.split("|").length;
      if (before !== (await findingSet(stripped, file))) moved.push(file);
    }

    // A transform that matched nothing, or a corpus that drew no findings,
    // makes "zero movers" mean nothing at all. Both are asserted.
    expect(carriers).toBe(CARRIERS);
    expect(baselineFindings).toBeGreaterThan(100);

    expect(moved).toEqual(DEPENDENT);
  }, 300_000);
});
