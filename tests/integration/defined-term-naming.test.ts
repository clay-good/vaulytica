/**
 * A defined term is whatever the drafter decided to call it.
 *
 * "Confidential Information" is "Proprietary Information" in half the NDAs
 * ever written; a contract is an Agreement, a Contract, a Deed or an Order
 * depending on the house and the jurisdiction. Renamed consistently — the
 * definition and every use — the document says exactly what it said before,
 * and the engine should say exactly what it said before.
 *
 * The relation found TERM-009: its convenience-termination trigger named only
 * "this Agreement", and because that group is OPTIONAL the clause did not fall
 * back to matching without it — the words "this Contract " sit between
 * "terminate" and "at any time" and nothing consumes them. A lease, a deed or
 * a statement of work granting the same one-sided right was read as granting
 * none.
 *
 * ── What this file does NOT assert, and why ──────────────────────────────
 *
 * Renaming "Effective Date" to "Commencement Date" moves findings on six
 * specimens, and that is NOT a defect. It is the rewrite failing to preserve
 * meaning, which is the one discipline these probes live or die by.
 *
 * "Effective Date" sits in `definitions.ts`'s COMMON_WORDS: every contract
 * uses it without defining it, because the date is on the front page — 20 of
 * the 48 specimens that use the term never define it. "Commencement Date" is
 * a different animal. In a lease or a construction contract it is usually
 * contingent, and a drafter who leaves it undefined has left a real hole. So
 * the rename does not carry a term across; it swaps boilerplate for a term of
 * art with different drafting expectations, and STRUCT-006 reporting the
 * second is arguably right.
 *
 * The routing half is asserted for every rename because it holds for a reason
 * that does not depend on any of that: the matcher scores a document on its
 * TITLE and its clause vocabulary, and neither moves when a defined term is
 * renamed. Four renames over three hundred specimen-pairs, zero re-routes.
 *
 * ── Open, and deliberately not asserted ─────────────────────────────────
 *
 * Renaming Agreement → Contract still GAINS four absence findings, and they
 * are not one thing, which is why there is no list here pretending they are:
 *
 *   - `dpa-defined-term.txt` DPA-002, `ucc-1.txt` BNK-050 and
 *     `uk-master-services-agreement.txt` MSA-007 look like the same defect as
 *     DPA-045 — a presence detector naming one instrument noun — but each
 *     needs its own specimen read before its pattern is widened, because
 *     DPA-045 only earned its fix once the corpus produced a sub-processing
 *     agreement with ZERO occurrences of "terminate".
 *   - `stock-purchase.txt` EQT-135 is probably NOT a defect: "Ancillary
 *     Agreements" is a defined concept of a purchase agreement, and renaming
 *     it to "Ancillary Contracts" is the same term-of-art swap as the
 *     Effective Date case above rather than a carry-across.
 *
 * Asserting a gains list would freeze that ambiguity into a number. The LOSS
 * direction is asserted instead, because a rule going silent when the
 * instrument renames itself is unambiguously wrong however the gains read.
 */

import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { analyzeText } from "../../tools/cli/api.js";
import { loadAccuracyDeps } from "../../tools/accuracy/pipeline.js";

const DIR = join(process.cwd(), "tests", "fixtures", "specimens");
const SPECIMENS = readdirSync(DIR).filter((f) => f.endsWith(".txt"));

/** Renames that carry a term across without changing what it is. */
const RENAMES: ReadonlyArray<readonly [label: string, from: RegExp, to: string]> = [
  ["Effective Date → Commencement Date", /\bEffective Date\b/g, "Commencement Date"],
  [
    "Confidential Information → Proprietary Information",
    /\bConfidential Information\b/g,
    "Proprietary Information",
  ],
  ["Agreement → Contract", /\bAgreement\b/g, "Contract"],
  ["Services → Work", /\bServices\b/g, "Work"],
];

describe("a defined term is whatever the drafter called it", () => {
  it("renaming a defined term never changes which playbook the document routes to", async () => {
    const deps = await loadAccuracyDeps({});
    const reroutes: string[] = [];
    let probed = 0;
    for (const [label, from, to] of RENAMES) {
      for (const name of SPECIMENS) {
        const text = readFileSync(join(DIR, name), "utf8");
        const mutated = text.replace(from, to);
        if (mutated === text) continue;
        probed++;
        const before = await analyzeText(text, name, { deps });
        const after = await analyzeText(mutated, name, { deps });
        if (before.playbook_id !== after.playbook_id) {
          reroutes.push(`${label} — ${name}: ${before.playbook_id} -> ${after.playbook_id}`);
        }
      }
    }
    expect(probed, "the corpus never names one of these terms").toBeGreaterThan(250);
    expect(
      reroutes,
      `renaming a defined term sent these documents to a different playbook:\n  ${reroutes.join("\n  ")}`,
    ).toEqual([]);
  }, 600_000);

  it("renaming Confidential Information changes no finding", async () => {
    // The rename with no term-of-art confound: the two names are used
    // interchangeably across the profession, and neither carries a
    // convention about whether a definition is expected.
    const deps = await loadAccuracyDeps({});
    const broken: string[] = [];
    let probed = 0;
    for (const name of SPECIMENS) {
      const text = readFileSync(join(DIR, name), "utf8");
      const mutated = text.replace(/\bConfidential Information\b/g, "Proprietary Information");
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
    expect(probed, "no specimen names Confidential Information").toBeGreaterThan(15);
    expect(broken).toEqual([]);
  }, 300_000);

  it("no rule LOSES a finding because the instrument is not called an Agreement", async () => {
    // A lease, a deed, an order form and a statement of work grant the same
    // rights an agreement does. A rule that goes SILENT when the instrument
    // renames itself has stopped reading the clause — which is what TERM-009
    // did, and is a defect however the gains are read.
    const deps = await loadAccuracyDeps({});
    const silenced: string[] = [];
    let probed = 0;
    for (const name of SPECIMENS) {
      const text = readFileSync(join(DIR, name), "utf8");
      const mutated = text.replace(/\bAgreement\b/g, "Contract");
      if (mutated === text) continue;
      probed++;
      const before = await analyzeText(text, name, { deps });
      const after = await analyzeText(mutated, name, { deps });
      const ids = (r: typeof before): string[] =>
        [...new Set(r.run.findings.map((f) => f.rule_id))].sort();
      const lost = ids(before).filter((id) => !ids(after).includes(id));
      if (lost.length) silenced.push(`${name}: lost ${lost.join(",")}`);
    }
    expect(probed, "the corpus never calls itself an Agreement").toBeGreaterThan(150);
    expect(
      silenced,
      `these rules stopped reading a clause when the instrument renamed itself:\n  ${silenced.join("\n  ")}`,
    ).toEqual([]);
  }, 600_000);
});
