/**
 * What the fallback names on a document no type matched (spec-v50 §11).
 *
 * A fallback document ran 66 rules, and a probe holding seven clauses worth
 * naming drew one finding. Two of the rules existed and were skipped, one
 * could not read a party by its name, and three clauses had no rule that
 * could run here at all. One row of the spec's table per assertion.
 */
import { beforeAll, describe, expect, it } from "vitest";
import { analyzeText, loadAccuracyDeps, type AnalyzeResult } from "../../tools/cli/api.js";
import { DOCUMENT_TYPES_URL } from "../../src/engine/runner.js";

const PROBE = `PARTICIPATION TERMS

These terms are between Harbor Arts Collective and Dana Whitfield.

1. Changes. Harbor Arts Collective may amend this Memorandum at any time without notice.

2. Jury Waiver. Each party waives its right to a trial by jury in any dispute.

3. Liquidated Damages. If Dana Whitfield withdraws, Dana Whitfield will pay $2,000 as liquidated damages and not as a penalty.

4. Confession of Judgment. Dana Whitfield authorizes any attorney to appear and confess judgment against Dana Whitfield for any unpaid amount.

5. Deductions. Dana Whitfield authorizes Harbor Arts Collective to deduct any amount owed from Dana Whitfield's wages.

6. Acceleration. If a payment is more than ten days late, the entire unpaid balance becomes immediately due and payable.

7. Class Actions. Dana Whitfield waives any right to bring or join a class action.
`;

const QUIET = `PARTICIPATION TERMS

These terms are between Harbor Arts Collective and Dana Whitfield.

1. Studio. Dana Whitfield may use studio 4 on weekdays.

2. No Confession. These terms do not include any confession of judgment, no amount is deducted from wages, and no balance is accelerated.
`;

let probe: AnalyzeResult;
let quiet: AnalyzeResult;
let matched: AnalyzeResult;
beforeAll(async () => {
  const deps = await loadAccuracyDeps();
  probe = await analyzeText(PROBE, "terms.txt", { deps });
  quiet = await analyzeText(QUIET, "quiet.txt", { deps });
  matched = await analyzeText(
    "MUTUAL NONDISCLOSURE AGREEMENT\n\nThis Mutual Nondisclosure Agreement is between Acme, Inc. and Beta LLC. Each party will keep the other's Confidential Information confidential for two years.",
    "nda.txt",
    { deps },
  );
}, 120_000);

const of = (r: AnalyzeResult, id: string) => r.run.findings.filter((f) => f.rule_id === id);

describe("the fallback names the clause", () => {
  it("is the fallback", () => {
    expect(probe.playbook_id).toBe("generic-fallback");
    expect(quiet.playbook_id).toBe("generic-fallback");
  });

  it.each([
    ["DARK-005", "critical"],
    ["CHOICE-008", "info"],
    ["FIN-006", "info"],
    ["DARK-001", "warning"],
    ["GEN-001", "info"],
    ["GEN-002", "info"],
    ["GEN-003", "info"],
  ])("%s fires once, at %s", (id, severity) => {
    const found = of(probe, id);
    expect(found, id).toHaveLength(1);
    expect(found[0]!.severity).toBe(severity);
  });

  it("names a fact and a place, and never calls the document an agreement", () => {
    for (const id of ["GEN-001", "GEN-002", "GEN-003"]) {
      const f = of(probe, id)[0]!;
      expect(f.title).toMatch(/^This document /);
      expect(f.excerpt.text.length).toBeGreaterThan(20);
      expect(`${f.title} ${f.explanation} ${f.recommendation ?? ""}`).not.toMatch(
        /\b(?:this|the)\s+(?:agreement|contract)\b/i,
      );
    }
  });

  it("says nothing where the document disclaims the clause", () => {
    for (const id of ["GEN-001", "GEN-002", "GEN-003"]) expect(of(quiet, id), id).toEqual([]);
  });

  it("does not run the fallback notes on a document that matched a type", () => {
    expect(matched.playbook_id).not.toBe("generic-fallback");
    for (const id of ["GEN-001", "GEN-002", "GEN-003"]) {
      const row = matched.run.execution_log.find((e) => e.rule_id === id);
      expect(row?.ran, id).toBe(false);
      expect(of(matched, id)).toEqual([]);
    }
  });
});

describe("the fallback notice is true of the run", () => {
  it("states how many checks ran, and that is how many ran", () => {
    const message = probe.run.classification_notice!.message;
    const ran = probe.run.execution_log.filter((e) => e.ran).length;
    expect(message).toContain(`ran only its ${ran} general checks`);
    // The list it replaced named four packs while nine ran.
    expect(message).not.toMatch(/structural, basic-financial/);
    expect(message).toContain(DOCUMENT_TYPES_URL);
    const categories = new Set(probe.run.findings.map((f) => f.rule_id.split("-")[0]));
    expect(categories.has("CHOICE")).toBe(true);
  });
});
