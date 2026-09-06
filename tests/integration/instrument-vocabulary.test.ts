/**
 * What a contract calls ITSELF, and what it calls its attachments.
 *
 * `INSTRUMENT_NOUN` and `ATTACHMENT_KIND` already exist because a recognizer
 * that names one noun reads one file. This asks the same question of the
 * highest-leverage surface there is — ROUTING — by restating each specimen's
 * vocabulary and diffing.
 *
 *  - **Exhibit → Schedule and Exhibit → Appendix move nothing.**
 *    `foldAttachmentNouns` has folded those in the matcher for some time, and
 *    this pins it.
 *  - **Agreement → Contract re-routed 36 of 221 specimens**, and not to near
 *    neighbours: a processor DPA became a set of document requests, a marketing
 *    services agreement became a DPA, an SBA loan agreement became a revocable
 *    living trust, a UK facility agreement became a unilateral NDA. The
 *    playbook decides the entire rule set, so the instrument noun in a title is
 *    the highest-leverage synonym in the product. `foldInstrumentNouns` folds
 *    that one pair — and only that pair, since Lease, Deed, Note and SOW name
 *    distinct instruments with playbooks of their own.
 *
 * The fold immediately found a second defect, which is why the count is one
 * and not zero: `employment-at-will-us` declares both "employment agreement"
 * and "employment contract" as its own names, and once folded they were the
 * same string counted twice — so it read two title keywords where
 * `executive-employment` read one, and out-scored it on its own name. Credit
 * now goes to the NAME, not to the number of ways the catalog spells it.
 *
 * The debt below is the residue, asserted by equality.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { analyzeText } from "../../tools/cli/api.js";
import { loadAccuracyDeps } from "../../tools/accuracy/pipeline.js";

const DIR = join(process.cwd(), "tests", "fixtures", "specimens");

/** Carries case: a heading is written "EXHIBIT A", a title "MUTUAL AGREEMENT". */
const rename =
  (from: string, to: string, plural: string) =>
  (t: string): string =>
    t.replace(new RegExp(`\\b${from}(s?)\\b`, "gi"), (m, s: string) => {
      const word = s ? plural : to;
      return m === m.toUpperCase() ? word.toUpperCase() : word;
    });

/**
 * What renaming the instrument still moves.
 *
 * `ca-employment-arbitration.txt` is titled "MUTUAL AGREEMENT TO ARBITRATE
 * CLAIMS", where the noun is inside an idiom rather than naming the instrument
 * — "Mutual Contract to Arbitrate" is not something anyone writes, so the
 * transform is producing a document that does not exist.
 *
 * The STRUCT-006 entries are a document telling itself that its own name is an
 * undefined term: the rule excuses a term that appears in the TITLE, and these
 * specimens define `this "Agreement"` under a title that never says it
 * ("SECURED PROMISSORY NOTE"). Renaming the body noun does not change that
 * relationship — it changes WHICH word is missing from the title — so the
 * finding is correct in the mutant and was correct in the original for a
 * different term. A transform artifact, not a routing defect.
 */
const INSTRUMENT_DEBT: readonly string[] = [
  "arbitration-demand.txt: lost - gained SET-123",
  "ca-employment-arbitration.txt: lost CHOICE-003,CHOICE-006,OBLI-005 gained - routed arbitration-agreement-employment->generic-fallback",
  "il-secured-promissory-note.txt: lost - gained STRUCT-006",
  "ma-restrictive-covenant.txt: lost - gained STRUCT-006",
  "ppm-narrative.txt: lost - gained STRUCT-006",
  "promissory-note-secured.txt: lost - gained STRUCT-006",
  "promissory-note.txt: lost - gained STRUCT-006",
  "stock-purchase.txt: lost - gained EQT-135",
  "tolling-agreement-standstill.txt: lost - gained STRUCT-006",
  "ucc-1.txt: lost - gained BNK-050",
  "uk-master-services-agreement.txt: lost - gained MSA-026",
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
    const routed =
      before.run.playbook_id !== after.run.playbook_id
        ? ` routed ${before.run.playbook_id}->${after.run.playbook_id}`
        : "";
    if (lost.length || gained.length || routed) {
      out.push(`${name}: lost ${lost.join(",") || "-"} gained ${gained.join(",") || "-"}${routed}`);
    }
  }
  return { moved: out, probed };
}

describe("a document that names its instrument differently", () => {
  it("reads the same when its Exhibits are Schedules", async () => {
    const { moved: broken, probed } = await moved(rename("Exhibit", "Schedule", "Schedules"));
    expect(probed, "the corpus attaches nothing").toBeGreaterThanOrEqual(50);
    expect(broken).toEqual([]);
  }, 600_000);

  it("reads the same when its Exhibits are Appendices", async () => {
    const { moved: broken, probed } = await moved(rename("Exhibit", "Appendix", "Appendices"));
    expect(probed).toBeGreaterThanOrEqual(50);
    expect(broken).toEqual([]);
  }, 600_000);

  it("routes the same when it is a Contract rather than an Agreement", async () => {
    const { moved: broken, probed } = await moved(rename("Agreement", "Contract", "Contracts"));
    expect(probed, "no specimen calls itself an Agreement").toBeGreaterThanOrEqual(150);
    expect(broken).toEqual([...INSTRUMENT_DEBT]);
  }, 600_000);
});
