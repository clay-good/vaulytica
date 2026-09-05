/**
 * "Seller shall indemnify Buyer" and "Buyer shall be indemnified by Seller"
 * are the same allocation of the same risk.
 *
 * The passive is ordinary legal drafting, not an edge case — "each Indemnitee
 * shall be indemnified and held harmless by the Company" is how a charter, an
 * LLC agreement and a construction contract write it. **Not one of the 312
 * specimens uses it**, which is exactly why no rewriting of the corpus could
 * have found this: a relation can only rewrite what the corpus already
 * contains, so this one had to be INJECTED, the same way the "including but
 * not limited to" probe was.
 *
 * What it found is worse than a miss. RISK-002 reads DIRECTION — it compares
 * each party's indemnity scope and reports the asymmetry — and it took the
 * indemnitor to be the party standing closest before the verb. In the passive
 * that party is the indemnitEE, so a one-sided indemnity drafted that way was
 * not merely invisible: it was scored BACKWARDS, and the report named the
 * protected party as the one bearing the risk.
 *
 * The rule now reads the party after "by" when the sentence is passive.
 *
 * ── Why only "indemnify" ────────────────────────────────────────────────
 *
 * Six further obligation verbs were probed the same way — provide, pay,
 * maintain, deliver, reimburse, protect — and across thirteen specimens
 * **nothing was lost**. That is a real reassurance about the engine and it is
 * recorded here so nobody re-runs it.
 *
 * They are not asserted, because the DITRANSITIVE ones do not passivize with
 * a party-to-party pattern. "Client shall pay Contractor $18,000" becomes
 * "Contractor shall be paid $18,000 BY Client" in English; the naive rewrite
 * produces "Contractor shall be paid by Client $18,000", which no drafter
 * would write. FIN-005 duly reported that sentence as stating no payment
 * term, and it was right to — the defect was in the probe. A relation whose
 * rewriting is not something a lawyer would actually type measures itself.
 *
 * "Indemnify" is plainly transitive — "A indemnifies B" → "B is indemnified
 * by A" — which is why it is the one asserted.
 *
 * ── Declared, and not fixed here ────────────────────────────────────────
 *
 * OBLI-002 ("reciprocity asymmetry") still moves on one specimen. It reads
 * its obligors through `src/extract/obligations.ts`, and widening that
 * extractor is a decision with a measured blast radius — an earlier repair to
 * its obligor handling added a finding to 55% of the corpus and was declined
 * as a product decision, not an oversight. Fixing a directional RULE is
 * cheap; changing what the extractor considers an obligor is not, and it does
 * not belong in a session that found this by accident.
 */

import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { analyzeText } from "../../tools/cli/api.js";
import { loadAccuracyDeps } from "../../tools/accuracy/pipeline.js";

const DIR = join(process.cwd(), "tests", "fixtures", "specimens");
const SPECIMENS = readdirSync(DIR).filter((f) => f.endsWith(".txt"));

/** The party surfaces a contract actually uses before "shall indemnify". */
const ACTORS =
  "Vendor|Provider|Supplier|Contractor|Consultant|Licensor|Licensee|Company|Customer|Client|" +
  "Employer|Employee|Tenant|Landlord|Seller|Buyer|Purchaser|Borrower|Lender|Party|" +
  "Disclosing Party|Receiving Party";

const ACTIVE_INDEMNITY = new RegExp(
  `\\b(the\\s+)?(${ACTORS})\\s+shall\\s+indemnify\\s+(the\\s+)?(${ACTORS})\\b`,
  "g",
);

/** "X shall indemnify Y" → "Y shall be indemnified by X". */
export function passiveIndemnity(text: string): string {
  return text.replace(
    ACTIVE_INDEMNITY,
    (_all, a = "", actor: string, b = "", object: string) =>
      `${b}${object} shall be indemnified by ${a}${actor}`,
  );
}

/**
 * OBLI-002 reads its obligors through the obligations extractor; see the
 * header. The list may only SHRINK.
 */
const PASSIVE_DEBT: readonly string[] = ["trademark-license-food.txt: gained OBLI-002"];

describe("the passive voice allocates the same risk", () => {
  it("rewrites an active indemnity into the passive", () => {
    expect(passiveIndemnity("Seller shall indemnify the Buyer for any Losses.")).toBe(
      "the Buyer shall be indemnified by Seller for any Losses.",
    );
    // A capitalised article is not part of the match (the pattern is
    // case-sensitive, so "The" is not "the"), and is simply left standing —
    // "The Buyer shall be indemnified by Seller" is still the same sentence
    // with the same two parties in the same roles, which is all the relation
    // needs. Pinned so the looseness is a choice rather than a surprise.
    expect(passiveIndemnity("The Seller shall indemnify Buyer for any Losses.")).toBe(
      "The Buyer shall be indemnified by Seller for any Losses.",
    );
    // A sentence with no active indemnity is untouched.
    expect(passiveIndemnity("The parties agree to arbitrate.")).toBe(
      "The parties agree to arbitrate.",
    );
  });

  it("loses no finding when the indemnity is written in the passive", async () => {
    const deps = await loadAccuracyDeps({});
    const broken: string[] = [];
    let probed = 0;
    for (const name of SPECIMENS) {
      const text = readFileSync(join(DIR, name), "utf8");
      const mutated = passiveIndemnity(text);
      if (mutated === text) continue;
      probed++;
      const before = await analyzeText(text, name, { deps });
      const after = await analyzeText(mutated, name, { deps });
      const ids = (r: typeof before): string[] =>
        [...new Set(r.run.findings.map((f) => f.rule_id))].sort();
      const lost = ids(before).filter((id) => !ids(after).includes(id));
      const gained = ids(after).filter((id) => !ids(before).includes(id));
      // A LOSS is unambiguous: the clause is there and the rule stopped
      // reading it. Gains are declared above.
      if (lost.length) broken.push(`${name}: lost ${lost.join(",")}`);
      for (const id of gained) {
        const entry = `${name}: gained ${id}`;
        if (!PASSIVE_DEBT.includes(entry)) broken.push(entry);
      }
    }
    expect(probed, "no specimen writes an active indemnity").toBeGreaterThan(3);
    expect(broken).toEqual([]);
  }, 300_000);
});
