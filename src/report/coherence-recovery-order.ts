/**
 * Cross-document negotiation-posture **exposure recovery order** (recovery-precedence) — per unordered
 * *pair* of fronts, when the two both *recover* (climb back at-or-above the acceptable floor), does one
 * consistently recover **first** (and so the other **last**)? For each pair, how many round-transitions
 * saw front A recover in an *earlier* step than front B (`a_recovers_first`), how many saw B recover
 * before A (`b_recovers_first`), how many saw the two recover in the *same* step (`co_recoveries` — a
 * timing tie), out of all `comparisons` (`a_recovers_first + b_recovers_first + co_recoveries`); the
 * pair's `first_recoverer` (the front that recovered first more often, `null` on an exact split), its
 * `last_recoverer` (the partner left exposed longest, `null` on a split), the `affinity` (the
 * first-recoverer's share of all comparisons), the deal's **clearest recovery order** (`max_affinity` /
 * `most_ordered_pair` / `first_recovering_front` / `last_recovering_front`), and whether any pair has a
 * front that recovered first for a strict **majority** of the comparisons — and so a consistent laggard
 * (`lags`) (spec-v37).
 *
 * This is the **recovery mirror** of v36's concession order ({@link computeCoherenceConcession}), the
 * way v33 ({@link computeCoherenceRecoveryAffinity}) mirrors v32 and v30 mirrors v28. v36 orders
 * *falls* only, so it answers "which front *concedes* (falls below floor) first?" — the leading edge of
 * a coming concession. v37 orders *recoveries* only, so it answers the opposite-direction question:
 * "which front does the counterparty *restore* first?" — and, the warning side of the same relation,
 * "which front does it leave exposed **last**?" Recovering *first* is good news (a front repaired
 * quickly); the gate-worthy signal is the laggard, the front consistently restored after its partner.
 * Two deals with byte-identical v36 (fall-order) concession order can have opposite recovery order:
 *
 * - The **first recoverer / laggard.** Cap climbs back above floor in rounds 2 and 4; Term in rounds 3
 *   and 5 — every comparison, Cap recovered first. Cap leads the recovery; **Term recovers last**, the
 *   front left exposed below the floor longest.
 * - The **interleaved pair.** Cap and Term recover in mixed order — sometimes Cap first, sometimes Term
 *   — with no consistent first-recoverer, and so no laggard.
 *
 * The recovery event is exactly v33's ({@link computeCoherenceRecoveryAffinity}): a below → at-or-above
 * transition between two *stated* rounds; an unstated round is skipped (it neither recovers nor resets
 * the standing, §3) — so v37 reuses the same per-front recovery-step sets v33 overlaps and v29 buckets
 * per step, and adds **no** posture math beyond a per-pair *ordered* comparison of those step indices.
 * By construction, each pair's `co_recoveries` (the same-step recovery ties) equals v33's
 * `co_recoveries` for that pair, and summed over all pairs `total_co_recoveries` equals
 * `Σ_t C(recovering_t, 2)` (v29's per-step recovery count choose-two'd) — the same total v33 reports.
 * The posture filter (spec-v10 §3), restated:
 *  - **Deterministic** — same N coherences in the same order → identical `recovery_order_hash`, on any
 *    machine. Fronts are pinned by `localeCompare(_, "en")` (the same order the
 *    trajectory/exposure/affinity/concession functions use); unordered pairs are enumerated in that
 *    pinned order (`dimension_a < dimension_b`); the clearest-order pick is decided by *integer
 *    cross-multiplication* (`leads × comparisons` of the two pairs), never a float compare.
 *  - **Honest about unstated data** — a front no document states in a round does not *recover* into or
 *    out of that round: silence is neither a fall nor a recovery (the §3 contract that keeps
 *    `below → unstated → below` zero recoveries in v29/v33). A pair the two never both *recovered* in a
 *    *different* step (no ordered comparison — one never recovered, or they always recovered together)
 *    has no recovery-order edge and is omitted from `pairs[]`, never ranked.
 *  - **Advisory** — the report names which front the counterparty restored *first* across the team's own
 *    floor, which it left exposed longest, and how reliably. It asserts no legal conclusion.
 *  - **Additive** — the report carries its own `recovery_order_hash`, namespaced apart from every
 *    `coherence_hash`, `movement_hash`, `trajectory_hash`, `shift_trajectory_hash`, `arc_hash`,
 *    `exposure_hash`, `persistence_hash`, `breadth_hash`, `recurrence_hash`, `volatility_hash`,
 *    `synchrony_hash`, `settling_hash`, `onset_hash`, `latency_hash`, `concurrency_hash`,
 *    `relapse_hash`, `tenure_hash`, `affinity_hash`, `recovery_affinity_hash`, `opposition_hash`,
 *    `precedence_hash`, and `concession_hash`, so computing it moves no golden.
 */

import type { NegotiationTier } from "../playbooks/custom-interpreter.js";
import { sha256Hex } from "../ingest/hash.js";
import { stableStringify } from "../engine/runner.js";
import type { PostureCoherence } from "./posture-coherence.js";

/** The team's acceptable floor — the one rung whose name means "below what we will accept." */
const BELOW_FLOOR: NegotiationTier = "below-acceptable";

/**
 * One pair's recovery-order coupling class:
 *  - `leading` — one front *recovered* (climbed back at-or-above the floor) *before* the other for a
 *    *strict majority* of the comparisons (`max(a_recovers_first, b_recovers_first) × 2 > comparisons`)
 *    — a consistent first-recoverer, and so a consistent *laggard* (the partner restored last), the
 *    gate-worthy class; the laggard is the front the counterparty leaves exposed below the floor
 *    longest;
 *  - `interleaved` — the two recovered in mixed order with no strict-majority first-recoverer
 *    (including an exact split, and a pair whose comparisons are dominated by same-step ties).
 *
 * Only pairs with ≥ 1 *ordered* comparison (`a_recovers_first + b_recovers_first ≥ 1`) are classified;
 * a pair the two never both recovered in a different step (one never recovered, or they always recovered
 * together) has no recovery-order edge and is omitted from the report.
 */
export type RecoveryOrderClass = "leading" | "interleaved";

/** One unordered pair of fronts' whole-sequence recovery-order relation. */
export type CoherenceRecoveryOrderPair = {
  /** The earlier front of the pair (`localeCompare` order). */
  dimension_a: string;
  /** The later front of the pair (`dimension_a < dimension_b`). */
  dimension_b: string;
  /** How many comparisons saw `dimension_a` recover (climb back above the floor) in an *earlier* step than `dimension_b`. */
  a_recovers_first: number;
  /** How many comparisons saw `dimension_b` recover in an *earlier* step than `dimension_a`. */
  b_recovers_first: number;
  /** How many comparisons saw the two recover in the *same* step — a timing tie (equals v33's `co_recoveries`). */
  co_recoveries: number;
  /** All comparisons of one A-recovery against one B-recovery (`a_recovers_first + b_recovers_first + co_recoveries`). */
  comparisons: number;
  /** The front that recovered first more often (`null` on an exact `a_recovers_first === b_recovers_first` split). */
  first_recoverer: string | null;
  /** The front that recovered first *less* often — the laggard left exposed longest (`null` on a split). */
  last_recoverer: string | null;
  /** The first-recoverer's share of all comparisons (`max(a_recovers_first, b_recovers_first) / comparisons`). */
  affinity: number;
  /** The coupling class. */
  class: RecoveryOrderClass;
};

export type CoherenceRecoveryOrder = {
  /** How many rounds (coherences) the report spans. */
  rounds: number;
  /** The recovery-order pairs (`a_recovers_first + b_recovers_first ≥ 1`), pinned by `(dimension_a, dimension_b)`. */
  pairs: CoherenceRecoveryOrderPair[];
  /** Per-pair tally by coupling class. */
  class_counts: Record<RecoveryOrderClass, number>;
  /** Every pair's *ordered* comparisons summed (`Σ (a_recovers_first + b_recovers_first)` over all pairs). */
  total_ordered_comparisons: number;
  /** Every pair's same-step recovery ties summed — equals `Σ_t C(recovering_t, 2)` (v29), the same total v33 reports as `total_co_recoveries`. */
  total_co_recoveries: number;
  /** The clearest recovery order across the deal — the largest `affinity` among pairs with a first-recoverer (`null` when none). */
  max_affinity: number | null;
  /** The pair owning {@link max_affinity} (earliest on a tie; `null` when no pair has a first-recoverer). */
  most_ordered_pair: [string, string] | null;
  /** The first-recovering front of {@link most_ordered_pair} (`null` when none). */
  first_recovering_front: string | null;
  /** The laggard (last-recovering front) of {@link most_ordered_pair} (`null` when none). */
  last_recovering_front: string | null;
  /** Was any pair a strict-majority recovery-order coupling — and so a consistent laggard? The gate-worthy verdict. */
  lags: boolean;
  /** SHA-256 over the canonical per-pair set — additive, apart from every other hash. */
  recovery_order_hash: string;
};

function emptyClassCounts(): Record<RecoveryOrderClass, number> {
  return { leading: 0, interleaved: 0 };
}

/**
 * Walk N cross-document posture coherences — the same bundle at round 1, round 2, …, round N —
 * and report, *per unordered pair of fronts*, when the two both *recover* (climb back at-or-above the
 * acceptable floor), whether one consistently recovers *first* (and so the other *last*): how many
 * comparisons saw A recover before B (`a_recovers_first`), B before A (`b_recovers_first`), the two
 * together (`co_recoveries`), out of all `comparisons`; the pair's `first_recoverer`, its
 * `last_recoverer`, the resulting `affinity`, the deal's clearest such recovery order (`max_affinity` /
 * `most_ordered_pair` / `first_recovering_front` / `last_recovering_front`), and whether any pair has a
 * front that recovered first for a strict majority of the comparisons (`lags`) — not a *direction-blind*
 * ordering (v35's precedence, which also orders falls) nor a *same-step* coupling (v33's co-recovery).
 *
 * Pure and deterministic: fronts are matched by dimension and pinned by `localeCompare`, unordered
 * pairs are enumerated in that order, the round order is the caller's, the clearest-order pick uses
 * integer cross-multiplication (never a float comparison), and `recovery_order_hash` is over the
 * canonical per-pair set, so the same N coherences in the same order always yield identical bytes.
 *
 * A *recovery* of a front (at the transition into the round that reveals a new standing) is exactly
 * v33's: a below → at-or-above flip between two *stated* rounds; an unstated round is skipped (it
 * neither recovers nor resets the standing, §3), so a recovery across a silent gap is attributed to the
 * transition into the round that *reveals* the new standing. A *comparison* of a pair pairs one
 * A-recovery step against one B-recovery step; A *recovers first* when its step is the earlier one.
 * Summed over all pairs, the same-step ties (`co_recoveries`) equal `Σ_t C(recovering_t, 2)` (v29's
 * per-step recovery count choose-two'd), the same total v33 reports as `total_co_recoveries`.
 *
 * Every coherence must have been computed against the **same** team positions (the caller applies one
 * active playbook to every document in every round); comparing floors across different ladders is
 * nonsense, the same way v13/v16 refuse a cross-ladder diff. The CLI core
 * ({@link computeCoherenceRecoveryOrderArtifacts}) enforces this via the v15/v16 ladder guard before
 * calling this.
 *
 * Requires at least two rounds — a recovery is a *between-round* event; a single round has no transition
 * to register one over.
 */
export async function computeCoherenceRecoveryOrder(
  rounds: readonly PostureCoherence[],
): Promise<CoherenceRecoveryOrder> {
  if (rounds.length < 2) {
    throw new Error(`a recovery order needs at least two rounds (got ${rounds.length})`);
  }

  const byDim = rounds.map((c) => new Map(c.dimensions.map((d) => [d.dimension, d])));
  const labels = Array.from(
    new Set(rounds.flatMap((c) => c.dimensions.map((d) => d.dimension))),
  ).sort((a, b) => a.localeCompare(b, "en"));

  // Per front, the *sorted* list of transition indices (0…N−2) at which it *recovered* (climbed back
  // at-or-above the floor) — the same v33 recovery event, silence-skipping (§3): a below → at-or-above
  // flip vs. the previous *stated* round, held at the transition into the round that reveals the new
  // standing. A front recovers at most once per transition, so each list is strictly increasing.
  const recoveryStepsByDim = new Map<string, number[]>();
  for (const dimension of labels) {
    const floors = byDim.map((m) => m.get(dimension)?.weakest_tier ?? null);
    const recoverySteps: number[] = [];
    let prevBelow: boolean | null = null; // the last *stated* round's below-floor state
    for (let i = 0; i < floors.length; i++) {
      const t = floors[i];
      if (t === null) continue; // silence: neither recovers nor resets the standing (§3)
      const isBelow = t === BELOW_FLOOR;
      // A recovery (below → at-or-above) vs. the previous stated round is held at index i−1.
      if (prevBelow === true && !isBelow) recoverySteps.push(i - 1);
      prevBelow = isBelow;
    }
    recoveryStepsByDim.set(dimension, recoverySteps);
  }

  const class_counts = emptyClassCounts();
  let total_ordered_comparisons = 0;
  let total_co_recoveries = 0;

  // The clearest recovery-order affinity, tracked as an exact integer ratio (leads/comparisons) to
  // avoid any float comparison: the running best is `(bestLeads, bestComparisons)`.
  let bestLeads = 0;
  let bestComparisons = 0;
  let most_ordered_pair: [string, string] | null = null;
  let first_recovering_front: string | null = null;
  let last_recovering_front: string | null = null;
  let lags = false;

  const pairs: CoherenceRecoveryOrderPair[] = [];
  for (let i = 0; i < labels.length; i++) {
    const dimension_a = labels[i]!;
    const ra = recoveryStepsByDim.get(dimension_a)!;
    for (let j = i + 1; j < labels.length; j++) {
      const dimension_b = labels[j]!;
      const rb = recoveryStepsByDim.get(dimension_b)!;

      // Ordered comparisons of one A-recovery step against one B-recovery step.
      let a_recovers_first = 0;
      let b_recovers_first = 0;
      let co_recoveries = 0;
      for (const sa of ra) {
        for (const sb of rb) {
          if (sa < sb) a_recovers_first += 1;
          else if (sb < sa) b_recovers_first += 1;
          else co_recoveries += 1;
        }
      }

      // Accumulate the deal-level totals over *every* pair (an omitted no-ordered-comparison pair
      // still contributes its same-step recovery ties to total_co_recoveries), so the join invariant
      // to v29/v33 holds across the whole matrix.
      total_ordered_comparisons += a_recovers_first + b_recovers_first;
      total_co_recoveries += co_recoveries;

      if (a_recovers_first + b_recovers_first === 0) continue; // no recovery-order edge

      const comparisons = a_recovers_first + b_recovers_first + co_recoveries;
      const leaderLeads = Math.max(a_recovers_first, b_recovers_first);
      const first_recoverer =
        a_recovers_first > b_recovers_first
          ? dimension_a
          : b_recovers_first > a_recovers_first
            ? dimension_b
            : null;
      // The laggard is the other front of the pair — the one restored last, left exposed longest.
      const last_recoverer =
        first_recoverer === null
          ? null
          : first_recoverer === dimension_a
            ? dimension_b
            : dimension_a;
      const affinity = leaderLeads / comparisons;
      // Strict majority of *all* comparisons (cross-multiplied to stay integer-exact): the
      // first-recoverer recovered first more often than the ties and reverse-order comparisons
      // combined. This is only reachable when a_recovers_first ≠ b_recovers_first, so
      // `class === "leading"` implies a non-null first_recoverer (and a non-null laggard).
      const klass: RecoveryOrderClass = leaderLeads * 2 > comparisons ? "leading" : "interleaved";
      if (klass === "leading") lags = true;
      class_counts[klass] += 1;

      // The clearest recovery order across the deal, among pairs that *have* a first-recoverer (a
      // direction to name). The first pair (in label order) whose affinity strictly exceeds the
      // running best wins. `leaderLeads/comparisons > bestLeads/bestComparisons` ⟺
      // `leaderLeads × bestComparisons > bestLeads × comparisons` (all non-negative integers), so the
      // ranking is exact — no float comparison, no platform drift.
      if (
        first_recoverer !== null &&
        (most_ordered_pair === null || leaderLeads * bestComparisons > bestLeads * comparisons)
      ) {
        bestLeads = leaderLeads;
        bestComparisons = comparisons;
        most_ordered_pair = [dimension_a, dimension_b];
        first_recovering_front = first_recoverer;
        last_recovering_front = last_recoverer;
      }

      pairs.push({
        dimension_a,
        dimension_b,
        a_recovers_first,
        b_recovers_first,
        co_recoveries,
        comparisons,
        first_recoverer,
        last_recoverer,
        affinity,
        class: klass,
      });
    }
  }

  const max_affinity = most_ordered_pair === null ? null : bestLeads / bestComparisons;

  const recovery_order_hash = await sha256Hex(
    stableStringify({
      rounds: rounds.length,
      pairs: pairs.map((p) => ({
        dimension_a: p.dimension_a,
        dimension_b: p.dimension_b,
        a_recovers_first: p.a_recovers_first,
        b_recovers_first: p.b_recovers_first,
        co_recoveries: p.co_recoveries,
        first_recoverer: p.first_recoverer,
        class: p.class,
      })),
    }),
  );

  return {
    rounds: rounds.length,
    pairs,
    class_counts,
    total_ordered_comparisons,
    total_co_recoveries,
    max_affinity,
    most_ordered_pair,
    first_recovering_front,
    last_recovering_front,
    lags,
    recovery_order_hash,
  };
}

/**
 * Did any pair of fronts have one that *recovered* (climbed back at-or-above the acceptable floor)
 * *before* the other for a strict **majority** of the comparisons — and so a partner that *recovered
 * last* for that same majority: is there a stable recovery-order pairing whose laggard is the front
 * the counterparty leaves exposed longest? The CI gate predicate — the family's second
 * *direction-resolved* precedence verdict, the recovery mirror of v36's concession verdict (v36 gates
 * on the fall order; v35 on a direction-blind ordering of any crossing; v33 on the *same-step* recovery
 * coupling; v25/v29 on per-step counts). It needs no tuning — a strict majority of the comparisons
 * (ties and reverse-order working against it) *is* "this front is consistently restored last." A pair
 * that recovered first once but recovered together twice, or split its recoveries evenly, is
 * `interleaved` and clears it; a consumer wanting a different bar reads `affinity` and `max_affinity`
 * from the JSON. **Distinct from v36**: v36 orders *falls*, so it isolates which front *concedes*
 * first; this orders *recoveries*, so it isolates which front is *restored last*. **Distinct from v33**:
 * v33 reads which two fronts recover *together* in one step; this reads, *across* steps, which front
 * recovers *first* — an ordering relation a same-step read cannot pose.
 */
export function exposureLags(recoveryOrder: CoherenceRecoveryOrder): boolean {
  return recoveryOrder.lags;
}

/**
 * Serialize a {@link CoherenceRecoveryOrder} to a stable, pretty-printed JSON string. The key order is
 * fixed and the pair order is already pinned by {@link computeCoherenceRecoveryOrder}, so the same
 * report always yields identical bytes — the `recovery_order_hash` it carries is the canonical
 * fingerprint, reproducible from `pairs` (over the integer recovery counts, ties, first-recoverer, and
 * class; the derived `last_recoverer`, the derived float `affinity`, and the derived integer
 * `comparisons` aside).
 */
export function buildCoherenceRecoveryOrderJson(recoveryOrder: CoherenceRecoveryOrder): string {
  return JSON.stringify(
    {
      schema: "vaulytica.posture-recovery-order.v1",
      recovery_order_hash: recoveryOrder.recovery_order_hash,
      rounds: recoveryOrder.rounds,
      class_counts: recoveryOrder.class_counts,
      total_ordered_comparisons: recoveryOrder.total_ordered_comparisons,
      total_co_recoveries: recoveryOrder.total_co_recoveries,
      max_affinity: recoveryOrder.max_affinity,
      most_ordered_pair: recoveryOrder.most_ordered_pair,
      first_recovering_front: recoveryOrder.first_recovering_front,
      last_recovering_front: recoveryOrder.last_recovering_front,
      lags: recoveryOrder.lags,
      pairs: recoveryOrder.pairs.map((p) => ({
        dimension_a: p.dimension_a,
        dimension_b: p.dimension_b,
        a_recovers_first: p.a_recovers_first,
        b_recovers_first: p.b_recovers_first,
        co_recoveries: p.co_recoveries,
        comparisons: p.comparisons,
        first_recoverer: p.first_recoverer,
        last_recoverer: p.last_recoverer,
        affinity: p.affinity,
        class: p.class,
      })),
    },
    null,
    2,
  );
}

/** Render a recovery-order affinity (0–1) as a whole-percent string, e.g. `0.75` → `"75%"`. */
function pct(affinity: number): string {
  return `${Math.round(affinity * 100)}%`;
}

/**
 * Render a {@link CoherenceRecoveryOrder} as human-readable terminal lines: the clearest recovery order
 * (the first-recoverer, the laggard it leaves exposed, and the share of the comparisons it recovered
 * first, or none-ordered when no front ever consistently recovered first), the class tally, then one
 * line per recovery-order pair (its class, its first-recoverer/laggard and lead share, and the
 * ordered-vs-tied split), `leading` pairs first. A pair the two never both recovered in a different step
 * is never listed (§3 honesty — no recovery-order edge). Lives beside its JSON sibling so the CLI
 * renders the report from one definition.
 */
export function renderCoherenceRecoveryOrderSummary(recoveryOrder: CoherenceRecoveryOrder): string {
  const cc = recoveryOrder.class_counts;
  const n = recoveryOrder.rounds;
  const lines = [
    `\nCoherence exposure recovery order across ${n} rounds (which front the counterparty recovers last within a pair):`,
    recoveryOrder.most_ordered_pair === null
      ? `  clearest recovery order: none — no front ever recovered above the floor first for a strict majority of the comparisons.`
      : `  clearest recovery order: ${recoveryOrder.first_recovering_front} recovers before ${recoveryOrder.last_recovering_front} — ${recoveryOrder.last_recovering_front} recovers last (left exposed longest), ${recoveryOrder.first_recovering_front} first ${pct(recoveryOrder.max_affinity!)} of the comparisons.`,
    `  pairs: ${cc.leading} leading (one front consistently recovers last), ${cc.interleaved} interleaved.`,
  ];
  // Leading pairs first (the stable recovery order), then interleaved; each group keeps the
  // (dimension_a, dimension_b) order the pairs already carry.
  for (const p of [
    ...recoveryOrder.pairs.filter((p) => p.class === "leading"),
    ...recoveryOrder.pairs.filter((p) => p.class === "interleaved"),
  ]) {
    const mark = p.class === "leading" ? "⚠" : "·";
    const order =
      p.first_recoverer === null
        ? `${p.a_recovers_first}/${p.b_recovers_first} split`
        : `${p.last_recoverer} last (${p.first_recoverer} first ${p.first_recoverer === p.dimension_a ? p.a_recovers_first : p.b_recovers_first} of ${p.comparisons})`;
    lines.push(
      `  ${mark} ${p.dimension_a} + ${p.dimension_b}: ${p.class} — ${order} (${pct(p.affinity)}); ${p.co_recoveries} same-step tie${p.co_recoveries === 1 ? "" : "s"}.`,
    );
  }
  lines.push(`  recovery_order_hash: ${recoveryOrder.recovery_order_hash}`);
  return lines.join("\n") + "\n";
}
