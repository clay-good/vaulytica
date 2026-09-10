/**
 * Does the obligations ledger say WHEN?
 *
 * The ledger has one column a lawyer scans to answer "when does this bite?",
 * and **258 of the corpus's 3,688 obligations left it empty while their own
 * sentence opened with the answer.** "If my wishes are unknown, my agent shall
 * make decisions consistent with …" reached the CSV, the HTML table and the
 * DOCX report with a blank trigger.
 *
 * The cause was one word: `TRIGGER_RE` was run over the **predicate**. A
 * FRONTED condition lives in the SUBJECT, and `stripFrontedAdverbial` — a few
 * lines away — already identifies exactly that material to keep it out of the
 * obligor, then throws it away.
 *
 * 🥇 **Nothing could see this from the findings.** Obligations are a report
 * surface, not a rule input: no rule reads `Obligation.trigger`, so no golden,
 * no `result_hash` and no metamorphic relation in the suite moves whether the
 * column is full or empty. It was found by generating the artifact a user
 * receives and reading it — the same way `critical-dates` was found to be
 * running a deadline from an anchor called "end".
 *
 * The number below is committed by EQUALITY so that narrowing where a trigger
 * is looked for has to be done on purpose.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ingestPaste } from "../../src/ingest/paste.js";
import { extractAll } from "../../src/extract/index.js";

const DIR = join(process.cwd(), "tests", "fixtures", "specimens");

/** A sentence that opens with a subordinate clause and closes it with a comma. */
const FRONTED =
  /^\s*(?:If|When|Unless|Upon|Should|Where|In the event|Promptly after|Within)\b[^.;]{3,120}?,\s/i;

/**
 * Obligations whose sentence opens with a fronted condition and whose trigger
 * is STILL empty. Measured 2026-09-10; **258 before 9.692.0**, 60 after it,
 * and 48 once 9.693.0 stopped reading a modal inside the protasis as the duty
 * — those rows had the condition in the ACTION, so they were counted as
 * having no trigger and were right to be.
 *
 * Sixty is not zero because the trigger VOCABULARY is `TRIGGER_RE`'s and was
 * deliberately not widened here: `Where …`, `Unless …` and `Should …` are not
 * triggers to this extractor on the predicate side either, and making them one
 * is a separate decision with its own measurement. Widening WHERE a trigger is
 * looked for and widening WHAT counts as one are different changes.
 */
const FRONTED_WITHOUT_TRIGGER = 48;

describe("the obligations ledger says when", () => {
  it("reads a fronted condition as the trigger", async () => {
    const files = readdirSync(DIR)
      .filter((f) => f.endsWith(".txt"))
      .sort();
    expect(files.length).toBeGreaterThan(300);

    let obligations = 0;
    let fronted = 0;
    let empty = 0;
    let fromSubject = 0;

    for (const file of files) {
      const ingest = await ingestPaste(readFileSync(join(DIR, file), "utf8"));
      for (const o of extractAll(ingest.tree).obligations) {
        obligations += 1;
        if (!FRONTED.test(o.raw_text)) continue;
        fronted += 1;
        if (!o.trigger) {
          empty += 1;
          continue;
        }
        // A trigger the predicate did not supply: it opens before the action
        // in the source sentence, and the action does not contain it.
        const at = o.raw_text.indexOf(o.action.slice(0, 18));
        const tat = o.raw_text.indexOf(o.trigger);
        if (!o.action.includes(o.trigger) && tat >= 0 && at > tat) fromSubject += 1;
      }
    }

    // Anti-vacuity: a harness that extracted nothing reports zero empties,
    // which is indistinguishable from every trigger being present.
    expect(obligations).toBeGreaterThan(3000);
    expect(fronted).toBeGreaterThan(200);
    // …and the fix must actually be the thing supplying them. A trigger count
    // that rose because the PREDICATE matched more would leave this at zero.
    expect(fromSubject, "no trigger is being read out of a fronted clause").toBeGreaterThan(150);

    expect(empty).toBe(FRONTED_WITHOUT_TRIGGER);
  }, 300_000);
});
