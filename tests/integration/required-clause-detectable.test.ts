/**
 * A custom playbook may not accuse a document of missing a clause the
 * classifier cannot detect.
 *
 * Discharges `answer-undetectable-required-clauses` tasks 3-6.
 *
 * 🚨 The bug this pins produced a **critical finding asserting a clause was
 * missing from a document that plainly contained it.** `required_clauses[]
 * .category` is a free string (`z.string().min(1)`); the shipped DKB carries
 * 103 TF-IDF vocab categories but the product passes an empty vocab, so only
 * the ~21 PATTERN categories can ever appear in `extracted.classified`. A
 * playbook requiring `change-of-control` on an executive agreement with a
 * Change of Control section got:
 *
 *     [critical] Required clause missing: change-of-control
 *     [warning]  Required clause missing: base-salary
 *
 * and `unevaluable: 0` — the engine did not even report doubt. That is worse
 * than a wrong answer: it is a confident wrong answer at the top severity,
 * about the user's own standard, on a document that complies.
 *
 * The same invariant is already enforced for the 286 SHIPPED playbooks by
 * `required-clauses-live.test.ts`, where a dead category only costs match
 * weight. This file holds the surface where it manufactures an accusation.
 *
 * The document below is deliberately COMPLIANT with all three required
 * categories — the FP-hunt clean-document method: every "missing" finding it
 * draws is a bug by construction.
 */
import { describe, expect, it } from "vitest";

import { ingestPaste } from "../../src/ingest/paste.js";
import { extractAll, detectableCategories } from "../../src/extract/index.js";
import { resolveJurisdictionId } from "../../src/dkb/jurisdiction-ids.js";
import { runCustomPlaybook } from "../../src/playbooks/custom-interpreter.js";
import { validateCustomPlaybook } from "../../src/playbooks/custom-playbook.js";
import { loadDkbDirSync, resolveDkbDir } from "../../tools/dkb/resolve.js";

const dkb = loadDkbDirSync(resolveDkbDir());

/** Exactly what `src/ui/pipeline.ts` passes — an empty vocab, DKB patterns. */
const PRODUCT_CLASSIFIER = {
  vocab: { vocab: {} },
  patterns: dkb.classifier.patterns,
};

/** A document that CONTAINS base salary, change of control, and governing law. */
const COMPLIANT = `EXECUTIVE EMPLOYMENT AGREEMENT

1. Base Salary.
The Company shall pay the Executive an annual base salary of $240,000, payable in
accordance with the Company's standard payroll practices, subject to annual review
by the Board.

2. Change of Control.
Upon a Change of Control, all unvested equity awards held by the Executive shall
immediately vest in full. For purposes of this Agreement, a "Change of Control"
means any merger, consolidation, or sale of all or substantially all of the assets
of the Company.

3. Governing Law.
This Agreement is governed by and construed in accordance with the laws of the State
of Delaware.
`;

async function runAgainst(
  categories: Array<{ category: string; severity: "critical" | "warning" }>,
) {
  const ingest = await ingestPaste(COMPLIANT);
  const extracted = extractAll(ingest.tree, {
    jurisdictionLookup: resolveJurisdictionId,
    classifier: PRODUCT_CLASSIFIER,
  });
  const parsed = validateCustomPlaybook({
    schema_version: "1.0",
    id: "exec-comp",
    name: "Exec comp review",
    description: "Executive compensation review positions.",
    catalog_version: "1.0.0",
    required_clauses: categories,
  });
  if (!parsed.ok) throw new Error(`playbook invalid: ${JSON.stringify(parsed.errors)}`);
  return runCustomPlaybook(parsed.playbook, {
    tree: ingest.tree,
    extracted,
    detectable: detectableCategories(PRODUCT_CLASSIFIER),
  });
}

describe("detectableCategories", () => {
  it("reports the pattern categories the DKB ships", () => {
    const live = detectableCategories(PRODUCT_CLASSIFIER);
    // Anti-vacuity: an empty set would make every assertion below pass.
    expect(live.size, "the shipped classifier patterns emit no categories").toBeGreaterThan(10);
    expect(live.has("governing-law")).toBe(true);
  });

  it("does NOT include the vocab categories the product leaves unwired", () => {
    const live = detectableCategories(PRODUCT_CLASSIFIER);
    // These are real DKB vocab categories. If the product ever wires the vocab
    // this test fails loudly — which is the point: the detectable set must be
    // read from the data, and a change to what ships must be noticed here.
    expect(live.has("change-of-control")).toBe(false);
    expect(live.has("base-salary")).toBe(false);
  });

  it("widens when a vocab IS supplied", () => {
    const live = detectableCategories({
      vocab: { vocab: { "change-of-control": { merger: 1 } } },
      patterns: dkb.classifier.patterns,
    });
    expect(live.has("change-of-control")).toBe(true);
    expect(live.has("governing-law")).toBe(true);
  });
});

describe("a required clause the classifier cannot detect", () => {
  it("is unevaluable, not a finding, on a document that contains it", async () => {
    const run = await runAgainst([
      { category: "change-of-control", severity: "critical" },
      { category: "base-salary", severity: "warning" },
    ]);

    expect(
      run.findings.map((f) => f.title),
      "a document containing both clauses was accused of missing them",
    ).toEqual([]);
    expect(run.unevaluable.map((u) => u.rule_id).sort()).toEqual([
      "required-clause:base-salary",
      "required-clause:change-of-control",
    ]);
    // The reason has to tell the user what they CAN require, or they cannot act
    // on it.
    for (const u of run.unevaluable) {
      expect(u.reason).toContain("cannot be checked");
      expect(u.reason).toContain("governing-law");
    }
  });

  it("still reports a genuinely missing clause in a detectable category", async () => {
    // `arbitration` IS a pattern category, and this document has no
    // arbitration clause — so the accusation is true and must survive.
    const run = await runAgainst([{ category: "arbitration", severity: "critical" }]);
    expect(run.findings.map((f) => f.title)).toEqual(["Required clause missing: arbitration"]);
    expect(run.unevaluable).toEqual([]);
  });

  it("stays silent when a detectable category IS present", async () => {
    const run = await runAgainst([{ category: "governing-law", severity: "warning" }]);
    expect(run.findings).toEqual([]);
    expect(run.unevaluable).toEqual([]);
  });

  it("keeps the unevaluable list in the result hash", async () => {
    const withUndetectable = await runAgainst([
      { category: "change-of-control", severity: "critical" },
    ]);
    const withNothing = await runAgainst([]);
    // Both have zero findings, so `unevaluable` is the ONLY difference between
    // them — which makes this the discriminator the previous version of this
    // test was not. (Comparing two different undetectable categories passed
    // even with the fix disabled, because their *findings* differed.)
    expect(withUndetectable.findings).toEqual([]);
    expect(withNothing.findings).toEqual([]);
    expect(withNothing.unevaluable).toEqual([]);
    expect(withUndetectable.unevaluable).toHaveLength(1);
    expect(withUndetectable.result_hash).not.toBe(withNothing.result_hash);
  });
});
