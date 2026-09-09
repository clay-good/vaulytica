/**
 * "will" is how half the profession writes "shall".
 *
 * Plain-language drafting has been moving off "shall" for thirty years — the
 * federal rules were restyled out of it, and a great many house styles now
 * write "Vendor will indemnify" and "the director will not be personally
 * liable". The obligation is the same one. A recognizer that spells only
 * "shall" reads half its corpus.
 *
 * The metamorphic relation found three: GOV-140 could not see expenses that
 * "will be advanced", GOV-028 could not see a director who "will not be
 * personally liable", and MNA-106 could not see a seller who "will not
 * compete". A static sweep then found the same shape in a hundred and ninety
 * recognizers across fifty-one files — most already covered by a sibling
 * alternation, which is why only three showed on the corpus, and all of which
 * were one word from being blind.
 *
 * Both halves, as in `parenthetical-numeral` and `section-sign`: the static
 * ratchet is the cheap one that catches the next recognizer written with only
 * "shall", and the corpus relation is what proves the widening did not change
 * a finding.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { recognizerSources, sourceFiles, DOCUMENT_READING_ROOTS } from "./_recognizer-sources.js";
import { analyzeText } from "../../tools/cli/api.js";
import { loadAccuracyDeps } from "../../tools/accuracy/pipeline.js";

const DIR = join(process.cwd(), "tests", "fixtures", "specimens");
const SPECIMENS = readdirSync(DIR).filter((f) => f.endsWith(".txt"));

/** "shall" → "will", the whole corpus, both cases. */
const asWill = (s: string): string => s.replace(/\bshall\b/g, "will").replace(/\bShall\b/g, "Will");

/** "shall" → "must", the third spelling of the same obligation. */
const asMust = (s: string): string => s.replace(/\bshall\b/g, "must").replace(/\bShall\b/g, "Must");

/**
 * What "must" still costs, and the size of the pass that would clear it.
 *
 * "must" is the third spelling, and the one the plain-language style guides
 * actually recommend — the restyled Federal Rules use it, and so does every
 * house style that dropped "shall" rather than swapping it for "will". The
 * corpus relation found RISK-015 blind to it on TEN specimens: an indemnity
 * written "Vendor must indemnify" was not an indemnity at all, so the rule
 * that checks whether it is capped never ran.
 *
 * The four this relation first found were the same defect surfacing the other
 * way round: an ABSENCE finding appearing because the clause it looks for is
 * written with "must" — the presence detector misses it, the suppression
 * lifts, and the document is told it lacks a clause it has. All four were one
 * word from being right (`(?:shall|will)` → `(?:shall|will|must)` in
 * ADDENDA-015, GOV-028, MNA-038 and MNA-106) and the list below is now EMPTY.
 *
 * A static sweep puts the remaining exposure at **354 recognizers across 83
 * files** that read "shall" and not "must". That is not a codemod: the shapes
 * are too varied for one — the commonest accounts for 10 of the 354 — and each
 * site needs a judgment about where in its alternation the word belongs. It is
 * a dedicated pass, and this relation is what will measure it. The list stays
 * because the assertion is what holds it empty.
 */
const MUST_DEBT: readonly string[] = [];

describe("shall and will are the same obligation", () => {
  it("no recognizer reads 'shall' without also reading 'will'", () => {
    // The EXTRACTORS read the document too, and were outside the first draft's
    // reach: `src/extract/jurisdictions.ts` could read "Delaware law shall
    // govern" and not "Delaware law will govern", which is the governing-law
    // clause of any contract drafted in a plain-language house style.
    const files = [...DOCUMENT_READING_ROOTS.flatMap((r) => sourceFiles(join(process.cwd(), r)))];
    expect(files.length, "no sources found — the walk is broken").toBeGreaterThan(50);

    const blind: string[] = [];
    for (const file of files) {
      for (const { line, text } of recognizerSources(file)) {
        // NOT `\bshall\b`. The text being searched is regex SOURCE, so the
        // two characters before the word are very often `\b` — and a word
        // boundary between the "b" of that escape and the "s" of "shall"
        // does not exist. The first draft of this guard read only the
        // literals that happened not to anchor the word, which is the same
        // defect `section-sign.test.ts` was written for, one level up.
        if (/shall(?![a-z])/.test(text) && !/will(?![a-z])/.test(text)) {
          blind.push(`${file}:${line}  ${text.slice(0, 90)}`);
        }
      }
    }
    expect(
      blind,
      `these read only "shall" — write (?:shall|will):\n  ${blind.join("\n  ")}`,
    ).toEqual([]);
  });

  /**
   * The same guard for the third spelling, held as a COUNT rather than a list.
   *
   * 297 of the 347 recognizers that read "shall" and not "must" carried an
   * adjacent `shall|will` alternation, where adding the word is mechanical and
   * needs no judgment: it only ADDS an alternative to a list that already
   * spells both synonyms. Those were widened in one pass, and every one of the
   * 811 golden assertions still holds — a tolerance changes what a pattern can
   * read, never what it means.
   *
   * A second mechanical shape followed: `shall\s+be|will\s+be`, the same
   * argument one word longer, in 11 more recognizers. Those went too, again
   * with every golden assertion unchanged.
   *
   * Fourteen of the 39 were then widened one at a time, each a judgment about
   * the SITE rather than a rule about the word: the prohibitions, where "must
   * not" is standard plain-language drafting (`must not solicit`, `must not
   * compete`, `must not include`, the privacy-notice negation lists), plus
   * RISK-015's indemnity forms.
   *
   * The 25 left are not debt — they are correct as written, and the reason is
   * nameable in each case rather than a shrug: "no employee MUST discuss" is
   * not English; "employment MUST BE at-will" is not how anyone drafts it;
   * `"Term" MUST MEAN` is not a definition; and "we MUST NOT represent" turns
   * a lawyer's statement of intent in an engagement letter into an obligation.
   * A word that does not belong is not a gap.
   *
   * What remains of the original 39 that DOES need judgment. Their shapes are all different — a
   * `shall\s+not` inside a longer prohibition list, a negation alternation
   * with eight members, a `shall` sitting alone in a clause where "must" may
   * not be idiomatic at all — and where the word belongs in each is a decision
   * per site, not a rewrite rule.
   *
   * A count, not a list of `path:line`: line numbers move under every edit
   * above them, and a stale exception is indistinguishable from a wrong one.
   * Equality, not `<=`, so that fixing one means lowering this number on
   * purpose — a ceiling nobody has to lower is a ceiling that drifts.
   */
  const MUST_BLIND = 25;

  it("the recognizers that read 'shall' without 'must' can only get fewer", () => {
    const files = [...DOCUMENT_READING_ROOTS.flatMap((r) => sourceFiles(join(process.cwd(), r)))];
    expect(files.length, "no sources found — the walk is broken").toBeGreaterThan(50);

    const blind: string[] = [];
    for (const file of files) {
      for (const { line, text } of recognizerSources(file)) {
        if (/shall(?![a-z])/.test(text) && !/must(?![a-z])/.test(text)) {
          blind.push(`${file}:${line}  ${text.slice(0, 90)}`);
        }
      }
    }
    // A NEW recognizer written with only "shall" raises this and fails here.
    expect(
      blind.length,
      blind.length > MUST_BLIND
        ? `a recognizer reads "shall" without "must" — write (?:shall|will|must):\n  ${blind.join("\n  ")}`
        : `${MUST_BLIND - blind.length} of these are fixed — lower MUST_BLIND to ${blind.length}`,
    ).toBe(MUST_BLIND);
    // And none of them may carry the mechanical shape, which was cleared
    // wholesale: a fresh `(?:shall|will)` is exactly what this catches.
    expect(
      blind.filter((b) => /shall\|will|will\|shall/.test(b)),
      'this reads "shall|will" — adding "must" to that alternation needs no judgment',
    ).toEqual([]);
  });

  it("writing every 'shall' as 'will' changes no finding", async () => {
    const deps = await loadAccuracyDeps({});
    const broken: string[] = [];
    let probed = 0;
    for (const name of SPECIMENS) {
      const text = readFileSync(join(DIR, name), "utf8");
      const mutated = asWill(text);
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
    expect(probed).toBeGreaterThan(150);
    expect(broken).toEqual([]);
  }, 300_000);
  /**
   * The fourth spelling, and the first that is not a modal at all.
   *
   * A plain-language house style writes "Vendor **is required to** indemnify".
   * The obligation EXTRACTOR has read that form for a long time — it is in
   * `MODALS` — but two indemnity rules matched on their own alternation and
   * that alternation spelled `shall|will|must|agrees to` and stopped. Measured
   * 2026-09-08 over the 185 specimens that write an obligation: **30 lost a
   * finding**, RISK-011 on 26 documents and RISK-015 on 10. That is RISK-015's
   * "must" blindness recurring for the next synonym, and the fix was the same
   * mechanical shape — one more alternative in a list that already spells the
   * others.
   *
   * 🚨 **The first measurement of this was wrong and would have sent a fix to
   * the wrong file.** Rewriting *every* `shall` produced "is required to not
   * disclose", which no drafter writes, and OBLI-005 "lost" nine documents
   * because its negation filter reasonably does not match that. The mutation
   * leaves `shall not` alone now — plain language writes that as "must not" or
   * "is prohibited from" — and OBLI-005's loss disappeared entirely. A
   * mutation that produces English nobody writes measures nothing.
   *
   * DARK-003 was the last one and the same shape again: its `VERB` constant
   * spelled `shall|must|agrees to|will`. The debt list is empty.
   *
   * The GAINS this rewrite produces (CHOICE-003 on 43 documents, FIN-005 on
   * 24, and six others) are artifacts of the rewrite itself, not of any rule
   * change: they were measured as identical before and after the fix. Only
   * losses are asserted here, for that reason.
   */

  /**
   * Every spelling the obligation extractor reads, not just the one that was
   * measured first.
   *
   * Fixing `is required to` in three rules left the identical hole open for the
   * next synonym: `is obligated to` lost the same 30 documents, `undertakes to`
   * and `covenants to` 36 each — the same four rules every time, because each
   * carried its own alternation and they stopped at different places. The
   * vocabulary has one owner now (`OBLIGATION_MODAL`), and this relation is
   * parameterized so a new spelling is one entry here rather than a new test.
   *
   * ⚠️ `is responsible for` is deliberately absent. It does not take a bare
   * infinitive — a drafter writes "responsible for indemnify**ing**" — so
   * substituting it for `shall` produces English nobody writes, and the loss it
   * "measured" was an artifact of the mutation. Same trap as rewriting
   * `shall not` to `is required to not`, which is what made OBLI-005 look
   * broken when it was not.
   *
   * ONE spelling is probed across the corpus, not five. Before the shared
   * constant they were five independent alternations and each needed its own
   * measurement; now they are one, and running five 85-second corpus sweeps to
   * exercise a single constant five times buys nothing. The rest of the class
   * is held by the static guard below, which is instant and catches the actual
   * regression — a rule going back to a private alternation.
   */
  const OBLIGATION_SPELLINGS = ["is obligated to"] as const;

  for (const spelling of OBLIGATION_SPELLINGS) {
    it(`writing a positive 'shall' as '${spelling}' loses no finding`, async () => {
      const deps = await loadAccuracyDeps({});
      const broken: string[] = [];
      let probed = 0;
      const Capital = spelling[0]!.toUpperCase() + spelling.slice(1);
      for (const name of SPECIMENS) {
        const text = readFileSync(join(DIR, name), "utf8");
        const mutated = text
          .replace(/\bshall\b(?!\s+not\b)/g, spelling)
          .replace(/\bShall\b(?!\s+not\b)/g, Capital);
        if (mutated === text) continue;
        probed++;
        const before = await analyzeText(text, name, { deps });
        const after = await analyzeText(mutated, name, { deps });
        const ids = (r: typeof before): string[] =>
          [...new Set(r.run.findings.map((f) => f.rule_id))].sort();
        const lost = ids(before).filter((id) => !ids(after).includes(id));
        if (lost.length) broken.push(`${name}: lost ${lost.join(",")}`);
      }
      expect(probed, "the corpus never writes an obligation").toBeGreaterThan(150);
      // Only LOSSES. The gains this rewrite produces (CHOICE-003 on 43
      // documents, FIN-005 on 24) are artifacts of the rewrite itself: they
      // were measured identical before and after the rules changed.
      expect(broken).toEqual([]);
    }, 300_000);
  }

  /**
   * The regression this needs to catch: a rule going back to a private
   * alternation.
   *
   * These four each carried their own `shall|will|must|…` list, and the lists
   * stopped at different places — which is why one synonym cost 30 documents
   * and the next cost 36. They read the shared vocabulary now, and this is
   * instant where a corpus sweep per spelling is 85 seconds each.
   *
   * 🚨 A first draft also flagged any line spelling `shall` beside `will` or
   * `must` in these files, and it was WRONG on four of five hits: RISK-015
   * carries a repeated-modal *sequence* (`(?:hereby\s+|agrees?\s+to\s+|shall\s+…)*`,
   * a different construct), a liability-cap slot (`(?:shall|will|must|is|are|may)?`
   * before "be limited"), and a negation (`(?:do|does|shall|will|must)\s+not\s+apply`).
   * None is an obligation-modal slot, and a guard that cannot tell them apart
   * gets silenced rather than obeyed. The precise half is kept; the corpus
   * relation above is what catches a rule that actually stops reading a
   * spelling, because it starts losing findings again.
   */
  it("the rules that match an obligation modal use the one shared vocabulary", () => {
    for (const rel of [
      "src/engine/rules/risk-allocation/RISK-011.ts",
      "src/engine/rules/risk-allocation/RISK-015.ts",
      "src/engine/rules/risk-allocation/RISK-016.ts",
      "src/engine/rules/dark-patterns/DARK-003.ts",
    ]) {
      // 🚨 Import lines are stripped first. Without that, replacing the only
      // USE of the constant with a hand-written alternation left the import
      // behind and this passed — proven by trying it. A name in an import is
      // not evidence of using it, which is the same defect
      // `cap-caveat-reach.test.ts` was fixed for the same day.
      const src = readFileSync(join(process.cwd(), rel), "utf8").replace(
        /^import\s[\s\S]*?from\s+"[^"]+";$/gm,
        "",
      );
      expect(src, `${rel} no longer reads the shared obligation vocabulary`).toContain(
        "OBLIGATION_MODAL",
      );
    }
  });

  /**
   * The prohibition, spelled the other ways.
   *
   * The positive obligation had five spellings and four rules that stopped at
   * different places. The NEGATIVE has the same shape: "Employee **is not
   * permitted to** disclose" is the identical restriction as "Employee **shall
   * not** disclose", and OBLI-005's own comment had named the gap — the
   * obligation extractor did not capture the form at all, so widening the rule's
   * filter alone would not have surfaced it.
   *
   * Measured 2026-09-08 over the 121 specimens that write a prohibition:
   * **66 lost OBLI-005 entirely**. Both halves landed together (`MODALS` to
   * capture it, `NEG` to classify it) and the loss went to zero.
   *
   * `must not` and `may not` were already clean. `is prohibited from` is NOT
   * probed here: it does not take a bare infinitive — a drafter writes
   * "prohibited from disclos**ing**" — so substituting it for `shall not`
   * produces English nobody writes, the same trap as `is responsible for`.
   *
   * RISK-003 and PERS-002 were the last two, and they were NOT the private-list
   * shape the positive side had. Neither reads a modal at all: PERS-002 matches
   * `not\s+(?:to\s+)?solicit` and RISK-003 `not\s+exceed` — an adjacency
   * between "not" and the verb. Letting anything sit in that gap would also
   * match "not **required** to solicit", which says the opposite, so the
   * plain-language form is admitted BY NAME (`permitted\s+to\s+`) instead. The
   * debt list is empty.
   */
  const PROHIBITION_DEBT: readonly string[] = [];

  it("writing 'shall not' as 'is not permitted to' loses only what is declared", async () => {
    const deps = await loadAccuracyDeps({});
    const lost = new Set<string>();
    let probed = 0;
    for (const name of SPECIMENS) {
      const text = readFileSync(join(DIR, name), "utf8");
      const mutated = text
        .replace(/\bshall not\b/g, "is not permitted to")
        .replace(/\bShall not\b/g, "Is not permitted to");
      if (mutated === text) continue;
      probed++;
      const before = await analyzeText(text, name, { deps });
      const after = await analyzeText(mutated, name, { deps });
      const ids = (r: typeof before): string[] =>
        [...new Set(r.run.findings.map((f) => f.rule_id))].sort();
      for (const id of ids(before).filter((i) => !ids(after).includes(i))) lost.add(id);
    }
    expect(probed, "the corpus never writes a prohibition").toBeGreaterThan(100);
    expect([...lost].sort()).toEqual([...PROHIBITION_DEBT]);
  }, 300_000);

  it("writing every 'shall' as 'must' moves a finding on only the documents still owed", async () => {
    const deps = await loadAccuracyDeps({});
    const broken: string[] = [];
    let probed = 0;
    for (const name of SPECIMENS) {
      const text = readFileSync(join(DIR, name), "utf8");
      const mutated = asMust(text);
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
    expect(probed, "the corpus never writes an obligation").toBeGreaterThan(150);
    // NOTHING may be LOST: a rule going silent because the obligation is
    // spelled "must" is the failure RISK-015 was, and it is not owed, it is
    // a bug. The gains are the declared debt.
    expect(broken.filter((b) => !b.includes("lost -"))).toEqual([]);
    expect(broken).toEqual([...MUST_DEBT]);
  }, 300_000);
});
