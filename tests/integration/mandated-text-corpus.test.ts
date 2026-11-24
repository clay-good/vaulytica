/**
 * The mandated-text rules against every specimen (task 7's standing half).
 *
 * `TEXT-001` (a prescribed notice, altered), `TEXT-002` (not in the required
 * bold face or point size) and `TEXT-003` (a merchantability disclaimer in
 * plain type) are all ABSENCE-shaped in the way that matters: each fires on a
 * document that ALREADY carries the thing, and says it is wrong. A false hit
 * is therefore a statement to an attorney that their notice is defective when
 * it is not, which is the most expensive kind of wrong this product can be.
 *
 * `add-mandated-text-conformance`'s task 3 records that the matching threshold
 * was chosen by measuring the corpus — "no false hit on the 363 specimens".
 * That measurement was taken ONCE and written into a task list. Nothing held
 * it. The same gap existed for `READ-003` until 9.1003.0, and when the sweep
 * was made standing it failed three times in a row on real caption styles the
 * detector could not read. A number in a task list is not a guard.
 *
 * So this is the standing version. It is deliberately a REACH test as well as
 * a false-positive test: each rule must be shown able to fire, or "zero hits
 * across 363 specimens" is indistinguishable from a rule that is switched off.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { analyzeText, loadAccuracyDeps } from "../../tools/cli/api.js";
import { MANDATED_TEXTS } from "../../src/engine/rules/text/mandated-texts.js";

const SPECIMENS = join(process.cwd(), "tests", "fixtures", "specimens");
const TEXT_RULES = ["TEXT-001", "TEXT-002", "TEXT-003"] as const;

/**
 * The FTC Holder Rule notice, as 16 C.F.R. § 433.2(a) prints it — the passage
 * the altered-text rule measures against.
 */
const HOLDER_NOTICE = MANDATED_TEXTS.find((r) => r.id === "ftc-holder-notice")!.variants[0]!.text;

const CREDIT_CONTRACT = (notice: string): string => `RETAIL INSTALLMENT CONTRACT

Seller: Harbour Lane Appliances, Inc.  Buyer: Nadia Osei

1. Goods. Seller sells the Buyer one washer-dryer set, model HL-220.

2. Price and Payments. The cash price is $1,480. The Buyer will pay $62 a month for twenty-four months, beginning April 1, 2026.

3. Security Interest. The Buyer grants the Seller a security interest in the goods until the Buyer has paid in full.

4. Notice.

${notice}

5. Governing Law. This contract is governed by the law of the State of Ohio.
`;

describe("the mandated-text rules over the corpus", () => {
  it("draw nothing on any specimen", async () => {
    const names = readdirSync(SPECIMENS).filter((n) => n.endsWith(".txt") || n.endsWith(".md"));
    expect(names.length, "no specimens found — the sweep would be vacuous").toBeGreaterThan(300);
    const deps = await loadAccuracyDeps({});
    const hits: string[] = [];
    for (const name of names) {
      const r = await analyzeText(readFileSync(join(SPECIMENS, name), "utf8"), name, { deps });
      for (const f of r.run.findings) {
        if ((TEXT_RULES as readonly string[]).includes(f.rule_id)) {
          hits.push(`${name}: ${f.rule_id} — ${f.title}`);
        }
      }
    }
    expect(
      hits,
      `a mandated-text rule called a specimen's notice defective; check each before widening a pattern:\n  ${hits.join("\n  ")}`,
    ).toEqual([]);
  }, 300_000);

  it("accept the Holder Rule notice as the regulation prints it", async () => {
    // The clean document for this family: a retail instalment contract
    // carrying the notice verbatim. Every finding it draws is a bug.
    const deps = await loadAccuracyDeps({});
    const r = await analyzeText(CREDIT_CONTRACT(HOLDER_NOTICE), "contract.txt", { deps });
    const drawn = r.run.findings.filter((f) =>
      (TEXT_RULES as readonly string[]).includes(f.rule_id),
    );
    expect(
      drawn.map((f) => `${f.rule_id}: ${f.title}`),
      "the notice is verbatim; nothing should be reported about it",
    ).toEqual([]);
  });

  it("still fire on an altered notice, so zero hits above is not a dead rule", async () => {
    // 🚨 The reach half. Dropping the final sentence is the real-world defect:
    // the recovery cap is the half a seller has an incentive to leave out, and
    // a presence pattern keyed on "ANY HOLDER OF THIS CONSUMER CREDIT
    // CONTRACT" passes it.
    const deps = await loadAccuracyDeps({});
    const truncated = HOLDER_NOTICE.replace(
      " RECOVERY HEREUNDER BY THE DEBTOR SHALL NOT EXCEED AMOUNTS PAID BY THE DEBTOR HEREUNDER.",
      "",
    );
    expect(truncated).not.toBe(HOLDER_NOTICE);
    const r = await analyzeText(CREDIT_CONTRACT(truncated), "contract.txt", { deps });
    const f = r.run.findings.find((x) => x.rule_id === "TEXT-001");
    expect(f, JSON.stringify(r.run.findings.map((x) => x.rule_id))).toBeDefined();
    expect(f!.description).toContain("RECOVERY HEREUNDER");
  });
});
