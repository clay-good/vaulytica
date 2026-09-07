import type { ExecutionLogEntry } from "../engine/finding.js";
import type { ConsistencyExecutionLogEntry } from "../engine/consistency/types.js";

/**
 * How one line of the audit trail reads.
 *
 * The engine records four distinguishable outcomes for a rule and the audit
 * trail used to render three of them. `!ran ? "skipped" : fired ? "fired" :
 * "silent"` collapses a rule that THREW into "silent" — and "silent" is what
 * the report means by "screened, and clean". `ExecutionLogEntry.errored` was
 * added precisely to break that conflation, and its own doc comment says so:
 * "a crashing rule reports 'screened, and clean' with nothing to contradict
 * it." The field was produced by both runners and read by no surface at all,
 * so the conflation it was written to end survived it.
 *
 * A rule that throws is treated as silent by the engine — the rule contract is
 * pure and one bad rule must not take down the run. That is the right
 * behaviour and it is not what is being changed here. What is being changed is
 * that the report now SAYS so, because "this check crashed" and "this check
 * passed" are not the same sentence to a lawyer relying on the review.
 *
 * The expression this replaces was written out twice, identically, in
 * `docx.ts` and `bundle.ts` — so the single-document report and the bundle
 * could have disagreed about what an audit line means. One owner now.
 */
export function describeExecutionLogEntry(e: ExecutionLogEntry): string {
  if (!e.ran) return "skipped";
  if (e.errored) return "errored";
  return e.fired ? "fired" : "silent";
}

/**
 * The roll-up. A per-line label is only found by a reader who reads every
 * line of a list that runs to hundreds of entries, so the count is stated
 * where the section begins.
 *
 * Returns `undefined` when nothing errored, which is the overwhelmingly common
 * path — so a run in which no rule threw renders byte-identically to the way
 * it did before this existed, and no golden moves.
 */
export function erroredRuleNotice(
  entries: ReadonlyArray<ExecutionLogEntry | ConsistencyExecutionLogEntry>,
): string | undefined {
  const errored = entries.filter((e) => e.errored);
  if (errored.length === 0) return undefined;
  return `${errored.length} rule${errored.length === 1 ? "" : "s"} could not be evaluated because ${errored.length === 1 ? "it" : "they"} ended in an error: ${errored
    .map((e) => e.rule_id)
    .join(
      ", ",
    )}. A rule that errors produces no finding, so this document was NOT checked against ${errored.length === 1 ? "it" : "them"}. Treat the corresponding area as unreviewed.`;
}

/**
 * The cross-document pass's own line, which had the same defect a third time:
 * `ran ? "ran, N findings" : "skipped"` has no branch for a consistency rule
 * that threw, and `ConsistencyExecutionLogEntry.errored` was likewise produced
 * and read by nobody.
 */
export function describeConsistencyLogEntry(
  e: ConsistencyExecutionLogEntry,
  findings: string,
): string {
  if (!e.ran) return "skipped (requires not satisfied)";
  if (e.errored) return "errored";
  return `ran, ${findings}`;
}
