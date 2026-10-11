/**
 * A rule whose own fix does not satisfy its check is a broken rule.
 *
 * Every presence check ships a `recommendation`, and it is the only thing a
 * reader is given to act on. Where that recommendation QUOTES drafting —
 * "remise, release, and forever quitclaim", "Lessee's obligation to pay Rent
 * is absolute and unconditional" — the quoted clause is a promise: write this
 * and the finding goes away. A rule that would still fire on its own quoted
 * fix is telling the reader to do something that does not work.
 *
 * This is the third question in the reachability family, and it is not asked
 * by the other two. `v34-title-vacuity` and `title-vacuity` ask whether a
 * check can ever FIRE; `boilerplate-satisfaction` asks whether it can ever be
 * SATISFIED by any document at all. Neither asks whether it is satisfied by
 * the specific document the rule itself asks for.
 *
 * The probe is the quoted drafting under the rule's own name as a heading.
 * The heading matters: most of these checks are conjunctions, and a
 * recommendation usually quotes the ONE pillar a reader would get wrong while
 * leaving the other to the section it is telling them to write. Probing the
 * quote alone reported three rules, and two of the three were the probe's
 * fault rather than the rule's.
 *
 * 🚨 **For most of its life this looked at about fifteen rules** while its
 * header said "every ungated presence check". It extracted quotes with a
 * DOUBLE-quote pattern, and the v3 and v4 packs quote their drafting in
 * single quotes — "Add: 'This Agreement is not intended to create … a
 * precedent'". It also walked only the rules registered in two id sets, which
 * no v3 rule is in. So `NDA-D-019` told a reader to add a sentence its own
 * pattern did not match, `ADDENDA-007` did the same, and nothing noticed.
 *
 * It now reads both quote styles and walks every rule in every wave. What
 * makes a rule a candidate is behaviour, not registration: it FIRES on a
 * document with no legal content and its finding carries a recommendation
 * that quotes drafting.
 *
 * Three things a quote can be that are NOT a promise, each found by reading a
 * failure by hand (spec-v51 §8):
 *
 *  - a SECTION TITLE — 'Election and Term', 'Release of Claims'. Title Case
 *    throughout: the advice is "add a section headed this", not "write this";
 *  - a COUNTER-EXAMPLE — which sections survive, "naming them by number, not
 *    'the provisions that by their nature survive'";
 *  - a TEMPLATE with a blank — 'Response Required by [date]'. The blank is
 *    filled the way a drafter would fill it before the probe is run.
 */

import { describe, expect, it } from "vitest";
import { buildContext } from "../../src/engine/_test-fixtures.js";
import {
  LAUNCH_RULES,
  V3_RULES,
  V4_RULES,
  V5_RULES,
  V6_RULES,
  V7_RULES,
} from "../../src/engine/index.js";
import { V3_GATED_PRESENCE_RULE_IDS } from "../../src/engine/rules/v3/_regulated-rule.js";
import { V4_GATED_PRESENCE_RULE_IDS } from "../../src/engine/rules/v4/_helpers.js";
import { GATED_PACK_RULE_IDS } from "../../src/engine/rules/v5/_pack.js";

/** A quoted phrase of at least this many words is drafting, not a section name. */
const DRAFTING_WORDS = 3;

const MINOR = new Set([
  "a",
  "an",
  "and",
  "as",
  "at",
  "by",
  "for",
  "in",
  "of",
  "on",
  "or",
  "the",
  "to",
  "with",
]);

/** Every substantive word capitalized: a heading to add, not a sentence to write. */
function isSectionTitle(quote: string): boolean {
  const words = quote.split(/[\s/—–-]+/).filter((w) => /[A-Za-z]/.test(w));
  return words.every((w) => MINOR.has(w.toLowerCase()) || /^[^a-z]*[A-Z]/.test(w));
}

/** Fill a template's blanks the way a drafter would. */
function fillBlanks(quote: string): string {
  return quote
    .replace(/\[date\]/gi, "March 15, 2026")
    .replace(/\[([^\]/]+?)\s*\/[^\]]*\]/g, "$1") // [first / second] → first
    .replace(/[[\]]/g, "");
}

/** The drafting a recommendation quotes — double or single quotes — as a promise. */
export function quotedDrafting(recommendation: string): string[] {
  const out: string[] = [];
  const quotes = [
    ...recommendation.matchAll(/["“]([^"”]{12,})["”]/g),
    // A single quote opens after a non-letter and closes before one, so the
    // apostrophe in "party's" neither opens nor closes it.
    ...recommendation.matchAll(/(?<![A-Za-z])['‘]([^'’]{12,}?)['’](?![A-Za-z])/g),
  ];
  for (const m of quotes) {
    const quote = m[1]!.trim();
    if (quote.split(/\s+/).length < DRAFTING_WORDS) continue;
    if (isSectionTitle(quote)) continue;
    // "…, not 'the provisions that by their nature survive'" is what to avoid.
    if (/\b(?:not|rather\s+than|instead\s+of|avoid)\s*$/i.test(recommendation.slice(0, m.index))) {
      continue;
    }
    out.push(fillBlanks(quote));
  }
  return out;
}

const GATED = (id: string): boolean =>
  V3_GATED_PRESENCE_RULE_IDS.has(id) ||
  V4_GATED_PRESENCE_RULE_IDS.has(id) ||
  GATED_PACK_RULE_IDS.has(id);

describe("a check is satisfied by the drafting its own recommendation quotes", () => {
  it("reads both quote styles, and tells drafting from a title, a counter-example and a blank", () => {
    expect(quotedDrafting("Add: 'This Agreement is not intended to create a precedent.'")).toEqual([
      "This Agreement is not intended to create a precedent.",
    ]);
    expect(quotedDrafting('Add "Lessee\'s obligation to pay Rent is absolute."')).toHaveLength(1);
    expect(quotedDrafting("Add a 'Release of Claims' section.")).toEqual([]);
    expect(quotedDrafting("Name them, not 'the provisions that by their nature survive'.")).toEqual(
      [],
    );
    expect(quotedDrafting("Add 'response is required by [date] in writing'.")).toEqual([
      "response is required by March 15, 2026 in writing",
    ]);
    expect(
      quotedDrafting("Include 'in lieu of a [meeting of the Board / stockholder vote]'."),
    ).toEqual(["in lieu of a meeting of the Board"]);
  });

  it("holds across every rule that fires on an empty document", () => {
    const failed: string[] = [];
    let probed = 0;
    let fired = 0;
    const probedWaves = new Set<string>();

    const waves = {
      launch: LAUNCH_RULES,
      v3: V3_RULES,
      v4: V4_RULES,
      v5: V5_RULES,
      v6: V6_RULES,
      v7: V7_RULES,
    };
    for (const [wave, rules] of Object.entries(waves)) {
      for (const r of rules) {
        // A gated check is supposed to stay silent on a document that does not
        // show the shape it looks for, so its recommendation is not a promise
        // about this probe.
        if (GATED(r.id)) continue;
        const pb = { id: (r.applies_to_playbooks ?? ["generic-fallback"])[0]!, version: "1.0.0" };
        const bare = {
          ...buildContext(["Agreement", "The parties met on a Tuesday and discussed the weather."]),
          playbook: pb,
        };
        const rec = r.check(bare)?.recommendation;
        if (!rec) continue;
        fired += 1;

        const drafting = quotedDrafting(rec);
        if (drafting.length === 0) continue;
        probed += 1;
        probedWaves.add(wave);

        const written = {
          ...buildContext([r.name, ...drafting, "Executed as of the date first written above."]),
          playbook: pb,
        };
        if (r.check(written) !== null) {
          failed.push(`${r.id}  ${r.name}\n      → ${drafting.join(" | ")}`);
        }
      }
    }

    expect(fired, "the sweep found no firing rules — it is broken").toBeGreaterThan(1000);
    // Measured on 9.863.0: 116 recommendations quote drafting once titles,
    // counter-examples and short phrases are set aside. The double-quote
    // extractor reached 16 of them.
    expect(probed, "the extraction is not reading single-quoted drafting").toBeGreaterThan(100);
    // …across the waves the old sweep never walked.
    expect([...probedWaves].sort()).toEqual(expect.arrayContaining(["v3", "v4"]));
    expect(
      failed.sort(),
      `these rules still fire on the drafting their own recommendation quotes:\n  ${failed.sort().join("\n  ")}`,
    ).toEqual([]);
  }, 300_000);
});
