/**
 * Does the linter say one thing twice?
 *
 * A report whose top two lines make the same statement about the same
 * sentence spends the reader's attention on the tool's own bookkeeping. Step
 * 288 found one such pair by hand — RISK-004 "Indemnity carved out of the
 * liability cap" directly above RISK-015 "Indemnification carved out of
 * liability cap", on five specimens and a golden fixture — and no guard saw
 * it, which is the signal to mechanise the question rather than to keep
 * reading reports for it.
 *
 * The mechanical form of "twice" is: two DIFFERENT rules, the same severity,
 * and excerpt spans that OVERLAP. That is a candidate, not a defect. Two rules
 * routinely have separate things to say about one clause — a limitation of
 * liability has both a carve-out count and a consequential-damages waiver in
 * it, and the reader wants both. What is a defect is SUBSUMPTION: one rule
 * states a fact and the other states the same fact plus a judgment about it,
 * so the first is the second's opening words repeated.
 *
 * Three such pairs came off at 9.369.0, all the same shape — a presence note
 * restated by the assessment of the very clause it noted:
 *
 *   TEMP-006 "Survival clause present"    / TEMP-007 "Survival list may be
 *                                           missing categories: …"   (21 docs)
 *   TEMP-008 "Cure period: 90 days"       / TEMP-009 "Cure period of 90 days
 *                                           is unusual"               (1 doc)
 *   OBLI-004 "'Best efforts' standard used" / OBLI-008 `Efforts standard
 *                                           "best efforts" undefined` (2 docs)
 *
 * In each the sibling carrying the judgment keeps the finding and the bare
 * presence note stands down, deferring on the sibling's OWN exported predicate
 * rather than on a second guess at it — the deference and the finding then
 * cannot drift apart. Each presence rule keeps every case its sibling cannot
 * see: a cure period inside the customary band, a survival list with no gap,
 * an efforts standard the document does define.
 *
 * One pair is a REAL duplicate and is on the worklist rather than fixed, in
 * `SUBSUMED_BUT_UNSETTLED` below. The suppression that removes it removes the
 * rule: OBLI-004 fires on a bare "best efforts", OBLI-008 on any efforts
 * standard the document never defines, and standing OBLI-004 down where they
 * coincide left it firing on ZERO of 308 specimens. That is rule deletion by
 * stealth, and deleting a rule from a published catalog is a decision to take
 * openly — with the catalog counts, the site's rule index, and the coverage
 * ledger — not a side effect of a one-line deference. Filed, not fixed.
 *
 * The pinned lists below are a RATCHET in both directions. A new pair fails
 * here, and a pair that has been settled must come OFF the list — without the
 * second assertion a duplicate fixed in one step and reintroduced in the next
 * looks clean, which is how this class survived the whole catalog.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { analyzeText, loadAccuracyDeps } from "../../tools/cli/api.js";

const DIR = join(process.cwd(), "tests", "fixtures", "specimens");

/**
 * Rule pairs that overlap on purpose: each says something the other does not.
 *
 * DARK-002 + TEMP-004 is the one worth reading twice. "Auto-renewal clause
 * present" IS restated by "Auto-renewal with notice window buried or long",
 * and standing the presence note down looks right until you follow it: the
 * portfolio view reads TEMP-004 directly, and reports "No auto-renew" for any
 * run in which the rule did not fire. Suppressing it on the abusive documents
 * would make the portfolio say the OPPOSITE of what those documents do, which
 * is a worse failure than a line of duplication. The presence finding is
 * load-bearing, so the pair stays.
 */
const OVERLAPS_ON_PURPOSE: ReadonlySet<string> = new Set([
  // A limitation of liability has both a carve-out inventory and a
  // consequential-damages waiver in it. Two facts, one clause.
  "RISK-006 + RISK-007 [info]",
  // Whether the indemnity is capped and how many carve-outs the cap has are
  // different questions about the same sentence.
  "RISK-003 + RISK-006 [info]",
  "RISK-003 + RISK-007 [info]",
  // One reports that the indemnity runs one way; the other that nothing caps
  // it. Either can be true without the other.
  "RISK-002 + RISK-015 [warning]",
  // A covenant count and an ambiguous trigger inside one of the covenants.
  "OBLI-003 + OBLI-005 [info]",
  "OBLI-005 + PERS-002 [info]",
  "OBLI-005 + RISK-010 [info]",
  // The presence note is read by the portfolio view — see above.
  "DARK-002 + TEMP-004 [warning]",
  // One says the post-termination obligations are enumerated; the other that
  // the enumeration omits categories the document has.
  "TEMP-007 + TERM-007 [info]",
]);

/**
 * Pairs where one rule really does subsume the other, and the fix is larger
 * than a suppression. Each entry is a defect on the worklist, not a licence.
 */
const SUBSUMED_BUT_UNSETTLED: ReadonlySet<string> = new Set([
  // OBLI-004 "'Best efforts' standard used" is OBLI-008 `Efforts standard
  // "best efforts" undefined` without the phrase, the case law, or the
  // recommendation. But OBLI-008 fires on every undefined efforts standard,
  // so deferring to it silences OBLI-004 on the entire specimen corpus. The
  // honest resolution is to fold OBLI-004 into OBLI-008 and retire the id,
  // which is a catalog change; the dishonest one is to call this pair
  // complementary. It is not.
  "OBLI-004 + OBLI-008 [info]",
]);

const deps = await loadAccuracyDeps({});
const files = readdirSync(DIR)
  .filter((f) => f.endsWith(".txt"))
  .sort();

const seen = new Map<string, { docs: string[]; titles: string }>();
for (const file of files) {
  const run = await analyzeText(readFileSync(join(DIR, file), "utf8"), file, { deps });
  const findings = run.run.findings;
  for (let i = 0; i < findings.length; i += 1) {
    for (let j = i + 1; j < findings.length; j += 1) {
      const a = findings[i];
      const b = findings[j];
      if (!a || !b) continue;
      if (a.rule_id === b.rule_id) continue;
      if (a.severity !== b.severity) continue;
      const overlaps =
        a.excerpt.start_offset < b.excerpt.end_offset &&
        b.excerpt.start_offset < a.excerpt.end_offset;
      if (!overlaps) continue;
      const key = `${[a.rule_id, b.rule_id].sort().join(" + ")} [${a.severity}]`;
      const entry = seen.get(key) ?? {
        docs: [],
        titles: `${a.rule_id}: ${a.title} || ${b.rule_id}: ${b.title}`,
      };
      entry.docs.push(file);
      seen.set(key, entry);
    }
  }
}

describe("no two rules make the same statement about the same sentence", () => {
  it("the sweep ran over the whole specimen corpus", () => {
    expect(files.length).toBeGreaterThan(300);
  });

  it("no new rule pair reports the same span at the same severity", () => {
    const fresh = [...seen.entries()]
      .filter(([key]) => !OVERLAPS_ON_PURPOSE.has(key) && !SUBSUMED_BUT_UNSETTLED.has(key))
      .map(([key, v]) => `${key} on ${v.docs.length} (e.g. ${v.docs[0]})\n    ${v.titles}`)
      .sort();
    expect(
      fresh,
      `these rule pairs now report the same span at the same severity — check whether one subsumes the other:\n  ${fresh.join("\n  ")}`,
    ).toEqual([]);
  });

  it("every listed overlap is still live — settled ones come off the list", () => {
    const stale = [...OVERLAPS_ON_PURPOSE, ...SUBSUMED_BUT_UNSETTLED]
      .filter((key) => !seen.has(key))
      .sort();
    expect(
      stale,
      `these overlaps no longer occur — remove them from OVERLAPS_ON_PURPOSE / SUBSUMED_BUT_UNSETTLED:\n  ${stale.join("\n  ")}`,
    ).toEqual([]);
  });
});
