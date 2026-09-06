/**
 * What a paginated, executed document carries besides its words.
 *
 * `format-invariance.test.ts` folds the furniture that REPEATS — a running
 * header, a page number, a Bates stamp, a privilege legend on every page.
 * A legend that appears ONCE is deliberately not folded, and the reason is
 * sound: the first one may be the document's own. But "once, above the title"
 * is exactly where a legend actually sits on an executed agreement, and
 * nothing had ever asked what it costs.
 *
 * Injected here because no specimen carries one. Four stamps, and the two
 * defects they found:
 *
 *  - **The legend became the title.** STRUCT-006 excuses a term that appears
 *    in the document's TITLE — "this Written Consent" is not a term an ACTION
 *    BY WRITTEN CONSENT forgot to define — and it read the first line. Stamp
 *    "EXECUTION VERSION" above the name and the document's own name is an
 *    undefined term. The matcher has answered this question correctly since
 *    `titleCorpus` was written; `dropLegends` is now shared rather than
 *    reimplemented.
 *  - **The legend became an obligation.** TEMP-007 audits a survival list only
 *    for categories the document actually HAS — "an obligation the document
 *    does not have cannot be missing from its list" — and decided that by
 *    testing `/confidential/i` against every paragraph. A one-word
 *    "CONFIDENTIAL" stamp is not a confidentiality obligation, and on six
 *    specimens it turned a complete survival list into an incomplete one,
 *    replacing TEMP-006's "Survival clause present" with TEMP-007's "may be
 *    missing categories".
 *
 * Routing never moved, on any stamp, on any specimen — `titleCorpus` had that
 * covered, and this pins it.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { analyzeText } from "../../tools/cli/api.js";
import { loadAccuracyDeps } from "../../tools/accuracy/pipeline.js";

const DIR = join(process.cwd(), "tests", "fixtures", "specimens");

/** A filler line every 40 lines, where a paginated document puts one. */
const interleave =
  (marker: string) =>
  (t: string): string => {
    const out: string[] = [];
    t.split("\n").forEach((line, i) => {
      out.push(line);
      if (i > 0 && i % 40 === 0) out.push("", marker, "");
    });
    return out.join("\n");
  };

const stamp =
  (legend: string) =>
  (t: string): string =>
    `${legend}\n\n${t}`;

/**
 * The two documents where the stamp is genuinely content rather than
 * furniture, and both are the case the single-legend rule was written for.
 * SET-030 asks a litigation hold notice to carry exactly that caption, and
 * `disclosure-schedules.txt` is an attachment whose own header is its
 * identification. A stamp above either does not repeat the document's legend —
 * it displaces it.
 */
const CONFIDENTIAL_DEBT: readonly string[] = [
  "disclosure-schedules.txt: lost MNA-045 gained -",
  "litigation-hold-notice.txt: lost SET-030 gained -",
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
    const routed = before.run.playbook_id !== after.run.playbook_id ? " ROUTED" : "";
    if (lost.length || gained.length || routed) {
      out.push(`${name}: lost ${lost.join(",") || "-"} gained ${gained.join(",") || "-"}${routed}`);
    }
  }
  return { moved: out, probed };
}

describe("the furniture an executed document carries", () => {
  it.each([
    [
      "[REMAINDER OF PAGE INTENTIONALLY LEFT BLANK] between pages",
      interleave("[REMAINDER OF PAGE INTENTIONALLY LEFT BLANK]"),
    ],
    ["[SIGNATURE PAGE FOLLOWS] at the end", (t: string) => `${t}\n\n[SIGNATURE PAGE FOLLOWS]\n`],
    ["an EXECUTION VERSION stamp above the title", stamp("EXECUTION VERSION")],
    ["a page number above the title", stamp("Page 1 of 12")],
  ])(
    "%s moves no finding",
    async (_label, mutate) => {
      const { moved: broken, probed } = await moved(mutate);
      expect(probed, "the transform reached no specimen").toBeGreaterThanOrEqual(200);
      expect(broken).toEqual([]);
    },
    600_000,
  );

  /**
   * A DRAFT stamp SATISFIES a presence pillar, which is the more expensive
   * direction: the finding it silences is an absence finding. PRV-003 asks a
   * cookie notice for a per-cookie disclosure — name, provider, purpose,
   * duration — and "FOR DISCUSSION PURPOSES ONLY" supplies the word "purpose".
   *
   * Not repaired here, and the reason is that the repair is not local. TEMP-007
   * could skip legend paragraphs because it walks paragraphs itself; a
   * `presence()` rule runs its patterns over the whole document through a
   * shared helper, and teaching THAT to ignore furniture changes every presence
   * rule in the catalog at once. That is a measured change with its own corpus
   * pass, not a footnote to this one.
   */
  it("a DRAFT stamp moves only the pillar its own words satisfy", async () => {
    const { moved: broken, probed } = await moved(stamp("DRAFT — FOR DISCUSSION PURPOSES ONLY"));
    expect(probed).toBeGreaterThanOrEqual(200);
    expect(broken).toEqual(["cookie-notice.txt: lost PRV-003 gained -"]);
  }, 600_000);

  it("a CONFIDENTIAL stamp moves only the two documents it is the caption of", async () => {
    const { moved: broken, probed } = await moved(stamp("CONFIDENTIAL"));
    expect(probed).toBeGreaterThanOrEqual(200);
    expect(broken).toEqual([...CONFIDENTIAL_DEBT]);
  }, 600_000);
});
