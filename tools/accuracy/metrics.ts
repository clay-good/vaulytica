/**
 * Accuracy metrics (spec-v5 §8, Step 71).
 *
 * Given, for each graded (document × playbook), the set of rule ids the engine
 * actually fired plus the gold annotation of which rules should / should not
 * fire, compute the standard confusion counts and derive precision, recall,
 * and F1 — per rule, per group (family / sub-domain / severity), and overall
 * (macro and micro). Pure and deterministic: same inputs → byte-identical
 * counts; the scoreboard hash depends on it.
 *
 * Scoring model (spec-v5 §8, closed-world over graded docs):
 *   - TP — rule fired and gold says `should_fire`.
 *   - FP — rule fired and gold says `should_not_fire`, OR gold is silent about
 *     a rule that fired on a doc where the playbook applies (silence = the
 *     clause is fine; a fired rule there is a false alarm).
 *   - FN — rule did not fire and gold says `should_fire`.
 *   - TN — rule did not fire and gold says `should_not_fire`.
 * A rule that neither fired nor was mentioned by gold contributes nothing
 * (it is out of scope for that document) — that is the only non-counted cell.
 */

export type GradedDocument = {
  corpus_doc_id: string;
  playbook_id: string;
  /** Rule ids the engine fired on this (doc × playbook). */
  fired_rule_ids: ReadonlySet<string>;
  /** Gold verdicts keyed by rule id. */
  gold: ReadonlyMap<string, "should_fire" | "should_not_fire">;
  /** Whether this doc's annotation cleared the κ confidence bar (spec-v5 §8). */
  high_confidence: boolean;
  /** Whether this is a bootstrap placeholder doc (excluded from headline). */
  bootstrap: boolean;
};

export type Counts = { tp: number; fp: number; fn: number; tn: number };

export type RuleMetric = Counts & {
  rule_id: string;
  precision: number | null; // null when denominator is 0 (undefined, not 0)
  recall: number | null;
  f1: number | null;
  /** Distinct graded documents that exercised this rule. */
  graded_docs: number;
  /** True when every grading doc for this rule was κ-low-confidence. */
  low_confidence: boolean;
};

export type Averages = {
  /** Pooled counts → one precision/recall/F1 over all rules. */
  micro: { precision: number | null; recall: number | null; f1: number | null };
  /** Mean of per-rule precision/recall/F1 (rules with a defined value). */
  macro: { precision: number | null; recall: number | null; f1: number | null };
};

export type Scoreboard = {
  totals: Counts;
  averages: Averages;
  per_rule: RuleMetric[];
  /** Distinct (doc × playbook) pairs scored (excludes bootstrap docs). */
  graded_pairs: number;
  /** (doc × playbook) pairs skipped because they are bootstrap placeholders. */
  bootstrap_pairs: number;
  /** Rules that fired/were-expected but had zero κ-confident grading docs. */
  unmeasured_rule_ids: string[];
};

export function precision(c: Counts): number | null {
  const d = c.tp + c.fp;
  return d === 0 ? null : c.tp / d;
}
export function recall(c: Counts): number | null {
  const d = c.tp + c.fn;
  return d === 0 ? null : c.tp / d;
}
export function f1(c: Counts): number | null {
  const p = precision(c);
  const r = recall(c);
  if (p === null || r === null || p + r === 0) return null;
  return (2 * p * r) / (p + r);
}

function emptyCounts(): Counts {
  return { tp: 0, fp: 0, fn: 0, tn: 0 };
}

/**
 * Score the engine against gold. Bootstrap docs (spec-v5 §4) are excluded
 * entirely from the counts so no placeholder ever inflates or deflates a
 * headline number; only their pair count is reported.
 */
export function computeScoreboard(docs: ReadonlyArray<GradedDocument>): Scoreboard {
  const totals = emptyCounts();
  const perRule = new Map<string, Counts>();
  const perRuleDocs = new Map<string, number>();
  const perRuleConfidentDocs = new Map<string, number>();

  let gradedPairs = 0;
  let bootstrapPairs = 0;

  for (const doc of docs) {
    if (doc.bootstrap) {
      bootstrapPairs++;
      continue;
    }
    gradedPairs++;

    // Every rule mentioned by gold OR fired on this doc is in scope.
    const inScope = new Set<string>(doc.fired_rule_ids);
    for (const ruleId of doc.gold.keys()) inScope.add(ruleId);

    for (const ruleId of inScope) {
      const fired = doc.fired_rule_ids.has(ruleId);
      const verdict = doc.gold.get(ruleId); // undefined ⇒ gold silent
      // Gold silent on a fired rule ⇒ treat as should_not_fire (false alarm).
      // Gold silent on a non-fired rule ⇒ out of scope, skip.
      if (verdict === undefined && !fired) continue;

      const c = perRule.get(ruleId) ?? emptyCounts();
      perRuleDocs.set(ruleId, (perRuleDocs.get(ruleId) ?? 0) + 1);
      if (doc.high_confidence) {
        perRuleConfidentDocs.set(ruleId, (perRuleConfidentDocs.get(ruleId) ?? 0) + 1);
      }

      const shouldFire = verdict === "should_fire";
      if (fired && shouldFire) c.tp++;
      else if (fired && !shouldFire) c.fp++;
      else if (!fired && shouldFire) c.fn++;
      else c.tn++;

      perRule.set(ruleId, c);
    }
  }

  // Aggregate totals + per-rule metrics, sorted by rule id for determinism.
  const ruleIds = [...perRule.keys()].sort();
  const per_rule: RuleMetric[] = [];
  const macroP: number[] = [];
  const macroR: number[] = [];
  const macroF: number[] = [];
  const unmeasured: string[] = [];

  for (const ruleId of ruleIds) {
    const c = perRule.get(ruleId)!;
    totals.tp += c.tp;
    totals.fp += c.fp;
    totals.fn += c.fn;
    totals.tn += c.tn;

    const confidentDocs = perRuleConfidentDocs.get(ruleId) ?? 0;
    const lowConfidence = confidentDocs === 0;
    if (lowConfidence) unmeasured.push(ruleId);

    const p = precision(c);
    const r = recall(c);
    const fScore = f1(c);
    if (p !== null) macroP.push(p);
    if (r !== null) macroR.push(r);
    if (fScore !== null) macroF.push(fScore);

    per_rule.push({
      rule_id: ruleId,
      ...c,
      precision: p,
      recall: r,
      f1: fScore,
      graded_docs: perRuleDocs.get(ruleId) ?? 0,
      low_confidence: lowConfidence,
    });
  }

  const mean = (xs: number[]): number | null =>
    xs.length === 0 ? null : xs.reduce((a, b) => a + b, 0) / xs.length;

  return {
    totals,
    averages: {
      micro: { precision: precision(totals), recall: recall(totals), f1: f1(totals) },
      macro: { precision: mean(macroP), recall: mean(macroR), f1: mean(macroF) },
    },
    per_rule,
    graded_pairs: gradedPairs,
    bootstrap_pairs: bootstrapPairs,
    unmeasured_rule_ids: unmeasured,
  };
}

/** The N lowest-precision rules with a defined precision and ≥1 firing. */
export function worstByPrecision(board: Scoreboard, n: number): RuleMetric[] {
  return board.per_rule
    .filter((r) => r.precision !== null && r.tp + r.fp > 0)
    .sort((a, b) => a.precision! - b.precision! || (a.rule_id < b.rule_id ? -1 : 1))
    .slice(0, n);
}

/** The N lowest-recall rules with a defined recall and ≥1 expected firing. */
export function worstByRecall(board: Scoreboard, n: number): RuleMetric[] {
  return board.per_rule
    .filter((r) => r.recall !== null && r.tp + r.fn > 0)
    .sort((a, b) => a.recall! - b.recall! || (a.rule_id < b.rule_id ? -1 : 1))
    .slice(0, n);
}
