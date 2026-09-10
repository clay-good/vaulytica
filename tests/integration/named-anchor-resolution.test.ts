/**
 * The calendar told a lawyer to go and check a date the tool had already
 * resolved.
 *
 * `msa-complete.txt` opens "made as of **March 16, 2026** (the "Effective
 * Date")" and says in §3.1 "This Agreement begins on the Effective Date". The
 * `.ics` a user imports carried:
 *
 *     SUMMARY:Verify manually: Effective Date
 *     DESCRIPTION:Verify manually — named anchor — no concrete date attached
 *     DTSTART;VALUE=DATE:20200101
 *
 * on the sentinel date — while `buildAnchorMap`, built four lines above the
 * branch that wrote it from the document's own definitions, held
 * `effective date → 2026-03-16`. The named-anchor case fell straight through
 * to the catch-all and never looked. **154 references across 46 specimens.**
 *
 * 🚨 **The second test is the load-bearing one.** The extractor records
 * `anchor: "Effective Date"` for "the effective date **of termination**" too —
 * a date the document does not fix and cannot. Resolving by anchor NAME alone
 * would put 2026-03-16 in the calendar against a termination that has not
 * happened: a **wrong date**, which is worse than the honest "verify manually"
 * it replaced. The match is therefore case-exact, on the drafting convention
 * that a defined term is capitalised.
 *
 * Found by generating the artifact and reading it — nobody had printed one.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ingestPaste } from "../../src/ingest/paste.js";
import { extractAll } from "../../src/extract/index.js";
import { collectDeadlines, buildDeadlinesIcs } from "../../src/report/exports.js";

const DIR = join(process.cwd(), "tests", "fixtures", "specimens");

/**
 * Named-anchor references resolved to the date the document defines.
 * Measured 2026-09-10; **0 before 9.694.0**, when every one was published as
 * "no concrete date attached".
 */
const RESOLVED_NAMED_ANCHORS = 154;

/**
 * References whose anchor resolves but whose own text is NOT the defined term
 * — every one "the effective date of termination". These must stay
 * unresolved. Lowering this by "improving" the match is how a wrong date gets
 * into a calendar.
 */
const HELD_BACK = 5;

async function extracted(file: string) {
  return extractAll((await ingestPaste(readFileSync(join(DIR, file), "utf8"))).tree);
}

describe("a named anchor the document defines is not unresolved", () => {
  it("resolves the defined term and holds back everything else", async () => {
    const files = readdirSync(DIR)
      .filter((f) => f.endsWith(".txt"))
      .sort();
    expect(files.length).toBeGreaterThan(300);

    let resolved = 0;
    let held = 0;
    let unresolvedTotal = 0;

    for (const file of files) {
      const ex = await extracted(file);
      const { events, unresolved } = collectDeadlines(ex);
      unresolvedTotal += unresolved.length;
      // The anchors this document DID resolve, so "held back" means the date
      // was available and was deliberately not used — not merely that the
      // document defines no such term.
      const resolvedNames = new Set<string>();
      for (const d of ex.dates) {
        if (d.type !== "named-anchor" || !d.anchor) continue;
        if (d.raw_text.trim() !== d.anchor.trim()) continue;
        if (events.some((e) => e.raw_text === d.raw_text)) resolvedNames.add(d.anchor.trim());
      }
      for (const d of ex.dates) {
        if (d.type !== "named-anchor" || !d.anchor) continue;
        const isExact = d.raw_text.trim() === d.anchor.trim();
        const shown = events.some((e) => e.raw_text === d.raw_text && e.summary === d.raw_text);
        if (isExact && shown) resolved += 1;
        else if (
          !isExact &&
          resolvedNames.has(d.anchor.trim()) &&
          unresolved.some((u) => u.raw_text === d.raw_text)
        ) {
          held += 1;
        }
      }
    }

    // Anti-vacuity: an "improvement" that resolved everything would empty the
    // verify-manually list, and that list is the honest half of this artifact.
    expect(unresolvedTotal).toBeGreaterThan(500);
    expect(resolved).toBe(RESOLVED_NAMED_ANCHORS);
    expect(held, "a lowercase reference is being resolved to the defined term").toBe(HELD_BACK);
  }, 300_000);

  it("puts the Effective Date in the calendar and leaves termination alone", async () => {
    const ics = buildDeadlinesIcs(await extracted("msa-complete.txt"));
    // The document defines it; the calendar states it.
    expect(ics).toContain("SUMMARY:Date: Effective Date");
    expect(ics).toMatch(
      /DTSTART;VALUE=DATE:20260316\r\nDTEND;VALUE=DATE:20260317\r\nSUMMARY:Date: Effective Date/,
    );
    // 🚨 "the effective date of termination" is a different date and the
    // document does not fix it. It stays a verify-manually item.
    expect(ics).toContain("SUMMARY:Verify manually: effective date");
    expect(ics).not.toContain("SUMMARY:Verify manually: Effective Date");
  });
});
