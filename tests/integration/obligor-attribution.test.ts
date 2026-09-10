/**
 * Who does the obligations ledger say owes the duty?
 *
 * `obligor_exclusion` shipped with a doc comment stating its purpose ("the
 * excluded role/party, so the obligor is not read as a bare 'each party'"),
 * two unit tests behind a hand-made fixture, and a **100% false-positive rate
 * on every real document.** All eleven corpus rows that populated it were
 * `except` used as a SUBORDINATOR rather than a preposition, and the field
 * recorded the conjunction and whatever followed it: "that Bank", "AS THOSE",
 * "as provided in a", "by".
 *
 * It was invisible for the reason a dead field usually is — nothing reads it,
 * so nothing could disagree with it. But the field was not the defect; it was
 * the SYMPTOM. Resolving the obligor stripped `except …` off the subject
 * whenever the field fired, which for a proviso deletes the clause's own
 * subject and leaves the `endsWith` match to land on whoever the clause
 * BEFORE happened to name:
 *
 *   "OEM may label the OEM Products under OEM's own brand and need not
 *    identify Supplier, except that OEM shall not remove or obscure any
 *    Supplier notice embedded in the firmware."
 *
 * printed **obligor: Supplier** — a duty not to remove Supplier's own notice,
 * attributed to the party it is owed TO. Eight of the eleven named the wrong
 * party, and the obligations ledger is a CSV a lawyer reads.
 *
 * The two assertions below are what would have shown all eleven on the day
 * they shipped, and neither needs a reader for the field:
 *
 *   1. **A base rate**, in the shape of `v3-extractor-base-rate.test.ts`: how
 *      much of the corpus does this claim? Committed by EQUALITY, so a
 *      specimen that genuinely carves a party out has to raise it on purpose.
 *   2. **A sample of what it actually holds.** A base rate alone says a
 *      detector fires eleven times; it cannot say that all eleven are junk.
 *      An exclusion has one job — name a party — so the values are checked
 *      against the parties the same document declares.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ingestPaste } from "../../src/ingest/paste.js";
import { extractAll } from "../../src/extract/index.js";

const DIR = join(process.cwd(), "tests", "fixtures", "specimens");

/**
 * Specimens in which an obligation carries a scope exclusion. Measured
 * 2026-09-10 over the 327-specimen corpus.
 *
 * **Zero is the honest number, not a dead detector.** "Each party except the
 * Provider shall …" is a rare construction and no specimen uses it; the unit
 * tests in `src/extract/obligations.test.ts` are what keep the code alive.
 * Before 9.689.0 this read ELEVEN, every one a false positive — which is the
 * whole reason the number is pinned here rather than bounded.
 */
const EXCLUSION_SPECIMENS = 0;

/**
 * Duties that exist only because a proviso gets its own clause. Each was
 * absorbed into the preceding clause's `qualifier` before 9.690.0 — present in
 * the raw text, absent from the ledger, and invisible to any check that
 * compares an extracted obligor against what a clause says.
 */
const RECOVERED: ReadonlyArray<[file: string, obligor: string, action: string]> = [
  ["merger-agreement.txt", "Parent", "pay all filing fees under the HSR Act"],
  ["source-code-escrow.txt", "Depositor", "bear the cost of any verification"],
  ["physician-employment.txt", "Physician", "bear one-half of the cost of the tail"],
  ["contingency-fee-agreement.txt", "the Firm", "waive unreimbursed costs"],
  ["joint-development.txt", "the parties", "share equally the cost"],
  ["sow.txt", "Supplier's technical lead", "be on site at Client's Hartford facility"],
];

describe("obligor attribution over the specimen corpus", () => {
  it("records a scope exclusion only where a document states one", async () => {
    const files = readdirSync(DIR)
      .filter((f) => f.endsWith(".txt"))
      .sort();
    // Anti-vacuity: a harness that ingested nothing reports zero exclusions,
    // which is indistinguishable from the fix working.
    expect(files.length).toBeGreaterThan(300);

    let obligations = 0;
    let provisos = 0;
    const exclusions: string[] = [];
    const misattributed: string[] = [];
    const byFile = new Map<string, { obligor: string; action: string }[]>();

    for (const file of files) {
      const ingest = await ingestPaste(readFileSync(join(DIR, file), "utf8"));
      const extracted = extractAll(ingest.tree);
      byFile.set(file, extracted.obligations);
      for (const o of extracted.obligations) {
        obligations += 1;
        if (o.obligor_exclusion) exclusions.push(`${file}: "${o.obligor_exclusion}"`);

        // The proviso case, checked directly: when a duty comes from an
        // `except that <X> <modal>` clause, the obligor IS X. The expected
        // answer is read out of the raw text, which is the one place it is
        // not taken from the code under test.
        const head = o.action.slice(0, 20);
        if (head.length < 8) continue;
        const at = o.raw_text.indexOf(head);
        if (at < 0) continue;
        // The nearest proviso that OPENS before the action this row reports.
        let hit: RegExpExecArray | null = null;
        for (const m of o.raw_text.matchAll(
          /\bexcept\s+that\s+([^,;]{1,60}?)\s+(?:shall|will|must|may)\b/gi,
        )) {
          if (m.index < at) hit = m as RegExpExecArray;
        }
        if (!hit) continue;
        // …and that has not already CLOSED. A clause boundary between the
        // proviso and the action means a further coordinated clause supplies
        // its own subject, and that subject is the obligor, not the proviso's:
        // "…, except that the Parties shall share equally the cost of the
        // third-party testing described in the SOW, and Ridgemont shall
        // invoice Halvorsen for Halvorsen's share" owes the invoice to
        // Ridgemont.
        if (/,\s+and\s+|;\s+/.test(o.raw_text.slice(hit.index + hit[0].length, at))) continue;
        const stated = hit[1]!.trim();
        // A pronoun subject ("except that it shall…") is one the extractor is
        // free to RESOLVE, and resolving it to the party is an improvement,
        // not a mismatch. Only a named subject is checked against the ledger.
        if (!/^(?:the\s+)?[A-Z][A-Za-z]/.test(stated)) continue;
        provisos += 1;
        const a = stated.toLowerCase();
        const b = o.obligor.toLowerCase();
        // Containment either way: the extractor normalises articles and the
        // party list can supply a longer canonical name than the clause used.
        if (!a.includes(b) && !b.includes(a)) {
          misattributed.push(`${file}: clause says "${stated}", ledger says "${o.obligor}"`);
        }
      }
    }

    expect(obligations).toBeGreaterThan(3000);
    expect(exclusions, "an except-CLAUSE is being recorded as an excluded PARTY").toEqual([]);
    expect(exclusions.length).toBe(EXCLUSION_SPECIMENS);

    // Anti-vacuity for the second assertion: the corpus must actually contain
    // provisos, or the loop above proves nothing about them.
    // Anti-vacuity: the corpus must actually contain provisos the splitter
    // gave their own clause, or the loop above proves nothing about them.
    expect(provisos, "no specimen carries an `except that … shall` proviso").toBeGreaterThan(8);
    expect(
      misattributed,
      "a proviso's duty is attributed to a party other than the one the proviso names",
    ).toEqual([]);

    // 🚨 The other half, and the one a mismatch check cannot make: a duty
    // that is not extracted at all cannot be misattributed. `, except that`
    // was not a boundary in the splitter's CONJ, so an affirmative proviso
    // was merged into the clause before it — QUALIFIER_RE then recorded the
    // whole proviso as that clause's `qualifier`, and the duty inside it
    // never became a row. Every assertion above passed in that state.
    for (const [file, obligor, action] of RECOVERED) {
      const row = byFile
        .get(file)
        ?.find((o) => o.obligor === obligor && o.action.startsWith(action));
      expect(row, `${file}: "${obligor} … ${action}" is not in the ledger`).toBeDefined();
    }
  }, 300_000);
});
