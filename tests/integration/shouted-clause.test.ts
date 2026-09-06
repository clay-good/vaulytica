/**
 * THE TWO CLAUSES A DRAFTER SHOUTS.
 *
 * A warranty disclaimer and a limitation of liability are set in capitals by
 * convention and, in a few states, by statute — UCC § 2-316(2) asks for a
 * merchantability disclaimer that is "conspicuous", and generations of
 * drafters have answered it with capitals. An indemnity travels with them. Not
 * one of the 312 specimens does it, which is exactly why no ordinary rewriting
 * of the corpus could find what follows: the shape had to be INJECTED, by
 * upper-casing the paragraphs that carry those clauses and leaving the rest
 * alone.
 *
 * Two defects, both of a kind a `/i` flag hides rather than causes:
 *
 *  - **RISK-002 went blind on seven specimens.** It anchored on `[A-Z]` for
 *    the sentence start and spelled its operative verb in lower case with no
 *    flag, so "SHALL INDEMNIFY AND HOLD HARMLESS" matched nothing at all — the
 *    asymmetry rule for the single most conventionally-capitalised clause in a
 *    contract. Carrying the flag AND an explicit `/^[A-Z]/` check at the
 *    consumer is the shape `inert-case-anchor.test.ts` asks for: under `i` a
 *    bare `[A-Z]` means nothing, so a sentence-start anchor has to be TESTED,
 *    not spelled.
 *  - **An ALL-CAPS heading registered no label**, so every reference into it
 *    read as broken and STRUCT-007 reported cross-references the document had
 *    not broken. `LEADING_SECTION_ROMAN_RE` already carried both spellings,
 *    which is the tell that its four siblings should have.
 *
 * The residue is recorded rather than chased. Upper-casing a paragraph is not
 * a pure fold: it erases the capitalisation that a defined term, a party name
 * and a heading all carry meaning in, so a document where every noun shouts is
 * genuinely a document that says less. Those are the entries below.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { analyzeText } from "../../tools/cli/api.js";
import { loadAccuracyDeps } from "../../tools/accuracy/pipeline.js";

const DIR = join(process.cwd(), "tests", "fixtures", "specimens");

/** Upper-case only the paragraphs a drafter conventionally shouts. */
const shout =
  (topic: RegExp) =>
  (t: string): string =>
    t
      .split("\n")
      .map((line) => (topic.test(line) && line.trim().length > 60 ? line.toUpperCase() : line))
      .join("\n");

/**
 * What upper-casing still moves, and why each is the transform's doing.
 *
 * STRUCT-006 names a term the document never defined, and STRUCT-017/018 read
 * an attachment's title line — both of which read CAPITALISATION as meaning.
 * A paragraph in which every noun shouts genuinely carries less of it.
 * OBLI-002's obligor is a party NAME, found the same way. The STRUCT-007
 * entries are the remaining heading shapes, each a different layout, and
 * `warrant.txt` is the extreme case: a warrant's own "Warrant" is both its
 * name and the word this transform matches, so upper-casing takes the
 * document's identity with it.
 *
 * The RISK-002 GAINS are the same erasure read forwards. That rule anchors on
 * a capital for the sentence START, and in a paragraph where every letter is a
 * capital the anchor matches everywhere — so the match may begin at a
 * different word and credit the indemnity to a different party. There is no
 * repair for it that does not amount to inferring sentence boundaries in text
 * that has thrown them away.
 */
const DISCLAIMER_DEBT: readonly string[] = [
  "assignment-and-assumption-agreement.txt: lost STRUCT-018 gained -",
  "franchise.txt: lost STRUCT-006 gained -",
  "net-lease.txt: lost STRUCT-018 gained -",
  "stock-purchase-agreement.txt: lost - gained STRUCT-005",
  "warrant.txt: lost STRUCT-006 gained CHOICE-004,CHOICE-009,CHOICE-012",
];

const LIABILITY_DEBT: readonly string[] = [
  "articles-org.txt: lost - gained STRUCT-007",
  "assignment-of-claim.txt: lost STRUCT-018 gained -",
  "cohabitation-agreement.txt: lost STRUCT-018 gained -",
  "commercial-indemnity-agreement.txt: lost - gained RISK-002",
  "distribution.txt: lost - gained OBLI-002",
  "insurance-endorsement-additional-insured.txt: lost - gained STRUCT-007",
  "insurance-endorsement.txt: lost - gained STRUCT-007",
  "joint-venture.txt: lost STRUCT-017 gained -",
  "master-purchase-agreement.txt: lost - gained OBLI-002",
  "msa-customer-side.txt: lost - gained RISK-002",
  "net-lease.txt: lost STRUCT-006 gained -",
  "ny-good-guy-guaranty.txt: lost STRUCT-006 gained -",
  "partnership-agreement.txt: lost OBLI-002 gained -",
  "sweepstakes.txt: lost STRUCT-006 gained -",
];

const INDEMNITY_DEBT: readonly string[] = [
  "commercial-indemnity-agreement.txt: lost - gained RISK-002",
  "indemnification-agreement.txt: lost STRUCT-009 gained -",
  "investor-rights.txt: lost - gained OBLI-002",
  "net-lease.txt: lost STRUCT-006 gained -",
  "revolving-credit-agreement.txt: lost - gained RISK-002",
];

async function moved(mutate: (t: string) => string): Promise<{ moved: string[]; probed: number }> {
  const deps = await loadAccuracyDeps({});
  const out: string[] = [];
  let probed = 0;
  for (const name of readdirSync(DIR).filter((f) => f.endsWith(".txt"))) {
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
      out.push(`${name}: lost ${lost.join(",") || "-"} gained ${gained.join(",") || "-"}`);
    }
  }
  return { moved: out, probed };
}

describe("a clause set in the capitals a drafter uses", () => {
  it("moves only what is owed on a warranty disclaimer", async () => {
    const { moved: broken, probed } = await moved(
      shout(/\b(warrant|disclaim|as is|merchantab|fitness for)/i),
    );
    expect(probed, "the corpus disclaims nothing").toBeGreaterThanOrEqual(50);
    expect(broken).toEqual([...DISCLAIMER_DEBT]);
  }, 600_000);

  it("moves only what is owed on a limitation of liability", async () => {
    const { moved: broken, probed } = await moved(
      shout(/\b(liabilit|liable|consequential|indirect damages)/i),
    );
    expect(probed).toBeGreaterThanOrEqual(100);
    expect(broken).toEqual([...LIABILITY_DEBT]);
  }, 600_000);

  it("moves only what is owed on an indemnity", async () => {
    const { moved: broken, probed } = await moved(shout(/\bindemnif/i));
    expect(probed).toBeGreaterThanOrEqual(50);
    expect(broken).toEqual([...INDEMNITY_DEBT]);
  }, 600_000);
});
