/**
 * Cross-document negotiation-posture **exposure recovery durability** — per front, the
 * *mean* number of rounds its binding floor held *above* the acceptable floor between a
 * recovery and the fall that undoes it: the central-tendency *magnitude* of the same
 * recovery-to-relapse intervals v30 pairs, where v30 reads only the *extreme* (spec-v41).
 *
 * v30 ({@link computeCoherenceRelapse}) pairs each *recovery* (below → at-or-above) with
 * the *next fall* (at-or-above → below) that undoes it and reads two reductions: the
 * deal's **quickest** single relapse (`min_interval`, an extreme) and whether any recovery
 * was undone at the very next round (`immediate`, the gate). Both throw away the one read a
 * deal lead asks reviewing a close that bounced: not the single fastest relapse, but the
 * **typical** one — *when this front recovers, how many clean rounds does the fix usually
 * hold before it falls again?* A count (v24), an index (v26/v27), a rate (v39), or an
 * extreme (v30's `min_interval`) all collapse the interval *durations* to a single number
 * that the typical interval does not see:
 *
 * - The **one fast relapse.** Cap holds 5 rounds, 5 rounds, then once bounces back the very
 *   next round — `min_interval` 1 (the deal's quickest), but a **mean** of 11/3 ≈ 3.7 clean
 *   rounds. One fix did not hold; the front's fixes usually last.
 * - The **chronically fragile front.** Term holds 1 round, 1 round, 1 round — the same
 *   `min_interval`-class extreme would call Cap worse (its quickest is also 1), yet Term's
 *   **mean** is 1: *every* fix collapses at once. It is the front whose recoveries
 *   *typically* do not survive a single clean round, which the single fastest relapse
 *   structurally cannot name.
 *
 * That is the *durability-magnitude* dimension of the same recovery-to-relapse intervals
 * — the above-floor mirror of v40's below-floor mean duration. Where v40 reads the **mean**
 * rounds a front sat *below* floor across its recovered exposures, v41 reads the **mean**
 * rounds it held *above* floor across its relapsed recoveries — and gates on a front whose
 * *typical* fix holds **fewer than two rounds** (`total_rounds < 2 × closed_intervals`, an
 * integer-exact bar): the front whose recoveries, on average, do *not* survive even one
 * clean round before relapsing.
 *
 * It is a reduction of the **same** intervals v30 pairs — `computeCoherenceRelapse` is
 * imported and reused unchanged (the join pattern v38 used for v36+v37, v40 used for v28),
 * so `total_relapsed_intervals` equals v30's `relapse_count` and `total_held_intervals` its
 * `held_count` by construction. It adds **no** posture math beyond averaging the relapsed
 * interval lengths v30 already computes over the `below-acceptable` rung v10 defines. The
 * posture filter (spec-v10 §3), restated:
 *  - **Deterministic** — same N coherences in the same order → identical `durability_hash`,
 *    on any machine. Fronts are pinned by `localeCompare(_, "en")` (the order v30 already
 *    pins); the round order is the caller's. The most-fragile (lowest-mean) pick is decided
 *    by *integer cross-multiplication* (`total_rounds × closed_intervals` of the two
 *    fronts), never a float comparison, so the ranking is exact and platform-independent.
 *  - **Honest about unstated data** — a front no document states does not recover or fall
 *    (the §3 contract v30 already enforces): silence contributes no interval, so a front
 *    that never recovered in-sequence carries no mean (`steady`), and an unstated front
 *    carries none (`unstated`). A *held* recovery (one never undone by a later fall) is an
 *    *unbounded* clean interval with no finite length to average, so it is counted
 *    (`open_intervals`) but excluded from the mean — the mirror of v40's open episode,
 *    semantically inverted (held is the *durable* case, not the broken one).
 *  - **Advisory** — the report names how long the team's own floor *typically* stays clear
 *    between a recovery and the fall that undoes it. It asserts no legal conclusion.
 *  - **Additive** — the durability carries its own `durability_hash`, namespaced apart from
 *    every `coherence_hash`, `movement_hash`, `trajectory_hash`, `shift_trajectory_hash`,
 *    `arc_hash`, `exposure_hash`, `persistence_hash`, `breadth_hash`, `recurrence_hash`,
 *    `volatility_hash`, `synchrony_hash`, `settling_hash`, `onset_hash`, `latency_hash`,
 *    `concurrency_hash`, `relapse_hash`, `tenure_hash`, `affinity_hash`,
 *    `recovery_affinity_hash`, `opposition_hash`, `precedence_hash`, `concession_hash`,
 *    `recovery_order_hash`, `weak_front_hash`, `cadence_hash`, and `duration_hash`, so
 *    computing it moves no golden.
 */

import { sha256Hex } from "../ingest/hash.js";
import { stableStringify } from "../engine/runner.js";
import type { NegotiationTier } from "../playbooks/custom-interpreter.js";
import type { PostureCoherence } from "./posture-coherence.js";
import { computeCoherenceRelapse } from "./coherence-relapse.js";

/**
 * A front's recovery-durability class:
 *  - `fragile` — it has ≥ 1 *relapsed* recovery and its **mean** clean interval is *below*
 *    two rounds (`total_rounds < 2 × closed_intervals`, including a mean of exactly one —
 *    every fix relapsed the very next round): when it recovers, its fix *typically* does
 *    not survive even one clean round — the gate-worthy class;
 *  - `durable` — it has ≥ 1 relapsed recovery and its mean clean interval is at least two
 *    rounds (`total_rounds ≥ 2 × closed_intervals`): its fixes typically hold for a while
 *    before relapsing;
 *  - `held` — it recovered above floor in-sequence and *every* recovery held (only an
 *    unrelapsed recovery, an unbounded clean interval with no finite length to average —
 *    the best case, the mirror of v40's `open` but semantically inverted);
 *  - `steady` — stated, but never *recovered* above floor in-sequence (no relapse interval
 *    to measure — including a front that never fell, and one that fell and never came back);
 *  - `unstated` — no document ever stated the front (§3: silence is not exposure).
 */
export type DurabilityClass = "fragile" | "durable" | "held" | "steady" | "unstated";

/** One negotiation front's whole-sequence recovery durability. */
export type CoherenceDurabilityFront = {
  dimension: string;
  /** The binding floor at each round, in sequence order (`null` = unstated that round). */
  floors: (NegotiationTier | null)[];
  /** The lengths (in clean rounds above floor) of every *relapsed* recovery, sorted ascending. */
  clean_intervals: number[];
  /** How many recoveries relapsed with a finite clean interval (= the length of {@link clean_intervals}). */
  closed_intervals: number;
  /** How many recoveries held (never undone — an unbounded interval excluded from the mean). */
  open_intervals: number;
  /** The sum of {@link clean_intervals} — the total clean rounds across relapsed recoveries (an integer). */
  total_rounds: number;
  /** The mean clean interval `total_rounds / closed_intervals` (`null` when no recovery relapsed). */
  mean_durability: number | null;
  /** The shortest single relapsed interval (`null` when none relapsed) — v30's per-front extreme, carried for contrast. */
  min_interval: number | null;
  /** The durability class. */
  class: DurabilityClass;
};

export type CoherenceDurability = {
  /** How many rounds (coherences) the durability spans. */
  rounds: number;
  fronts: CoherenceDurabilityFront[];
  /** Per-front tally by durability class. */
  class_counts: Record<DurabilityClass, number>;
  /** How many recovery-to-fall intervals closed with a relapse — equals v30's `relapse_count`. */
  total_relapsed_intervals: number;
  /** How many recoveries held — equals v30's `held_count`. */
  total_held_intervals: number;
  /** The sum of every relapsed interval's clean length across all fronts (the grand numerator). */
  total_rounds: number;
  /** The lowest *mean* clean interval across the deal — the most fragile recovery (`null` when none relapsed). */
  min_mean: number | null;
  /** The front owning {@link min_mean} (earliest on a tie; `null` when none relapsed). */
  most_fragile_dimension: string | null;
  /** Did any front's relapsed recoveries average fewer than two clean rounds? The gate-worthy verdict. */
  fragile: boolean;
  /** SHA-256 over the canonical per-front durability set — additive, apart from every other hash. */
  durability_hash: string;
};

function emptyClassCounts(): Record<DurabilityClass, number> {
  return { fragile: 0, durable: 0, held: 0, steady: 0, unstated: 0 };
}

/**
 * Walk N cross-document posture coherences — the same bundle at round 1, round 2, …,
 * round N — and report, per negotiation front, the **mean** number of rounds its binding
 * floor held above the acceptable floor between a recovery and the fall that undoes it
 * (`mean_durability`), the deal's most fragile recovery (`most_fragile_dimension`), and
 * whether any front's relapsed recoveries *typically* hold fewer than two clean rounds
 * (`fragile`) — the central tendency of the same recovery-to-relapse intervals v30 pairs,
 * not the single quickest one (v30's `min_interval`) nor the immediate-relapse gate (v30's
 * `immediate`).
 *
 * Pure and deterministic: it delegates the recovery-to-relapse pairing to
 * {@link computeCoherenceRelapse} (reused unchanged — the join pattern v38/v40 use), so
 * fronts are matched by dimension and pinned by `localeCompare`, the round order is the
 * caller's, the most-fragile pick uses integer cross-multiplication (never a float
 * comparison), and `durability_hash` is over the canonical per-front interval set, so the
 * same N coherences in the same order always yield identical bytes.
 *
 * Requires at least two rounds — a relapse interval is a *between-round* span; a single
 * round has no transition to pair a recovery and a fall over (v30 enforces this).
 */
export async function computeCoherenceDurability(
  rounds: readonly PostureCoherence[],
): Promise<CoherenceDurability> {
  const relapse = await computeCoherenceRelapse(rounds);

  const class_counts = emptyClassCounts();
  let total_relapsed_intervals = 0;
  let total_held_intervals = 0;
  let total_rounds = 0;
  // The lowest mean, tracked as an exact integer ratio (total_rounds / closed_intervals)
  // to avoid any float comparison: the running best is `(bestTotal, bestCount)`.
  let bestTotal = 0;
  let bestCount = 0;
  let most_fragile_dimension: string | null = null;
  let fragile = false;

  const fronts: CoherenceDurabilityFront[] = relapse.fronts.map((f) => {
    // Split v30's intervals into the relapsed (a finite clean length to average) and the
    // held (an unbounded interval excluded from the mean — the durable best case, §3).
    const clean_intervals = f.intervals
      .filter((iv) => iv.fall_round !== null)
      .map((iv) => iv.clean_rounds as number)
      .sort((a, b) => a - b);
    const closed_intervals = clean_intervals.length;
    const open_intervals = f.intervals.length - closed_intervals;
    const frontTotal = clean_intervals.reduce((s, l) => s + l, 0);

    total_relapsed_intervals += closed_intervals;
    total_held_intervals += open_intervals;
    total_rounds += frontTotal;

    const mean_durability = closed_intervals === 0 ? null : frontTotal / closed_intervals;

    // The mean spans fewer than two rounds — `mean < 2` ⟺ `total < 2 × count`, integer-exact:
    // when this front recovers, its fix typically does not survive even one clean round.
    const isFragile = closed_intervals > 0 && frontTotal < 2 * closed_intervals;

    const klass: DurabilityClass =
      f.relapse === "unstated"
        ? "unstated"
        : closed_intervals === 0
          ? f.relapse === "held"
            ? "held"
            : "steady"
          : isFragile
            ? "fragile"
            : "durable";
    if (klass === "fragile") fragile = true;
    class_counts[klass] += 1;

    // The lowest mean across the deal: the first front (in localeCompare order) whose mean
    // is strictly below the running best wins. `total/count < bestTotal/bestCount` ⟺
    // `total × bestCount < bestTotal × count` (all non-negative integers), so the ranking is
    // exact — no float comparison, no platform drift.
    if (
      closed_intervals > 0 &&
      (most_fragile_dimension === null || frontTotal * bestCount < bestTotal * closed_intervals)
    ) {
      bestTotal = frontTotal;
      bestCount = closed_intervals;
      most_fragile_dimension = f.dimension;
    }

    return {
      dimension: f.dimension,
      floors: f.floors,
      clean_intervals,
      closed_intervals,
      open_intervals,
      total_rounds: frontTotal,
      mean_durability,
      min_interval: f.min_interval,
      class: klass,
    };
  });

  const min_mean = most_fragile_dimension === null ? null : bestTotal / bestCount;

  const durability_hash = await sha256Hex(
    stableStringify({
      rounds: relapse.rounds,
      fronts: fronts.map((f) => ({
        dimension: f.dimension,
        floors: f.floors,
        clean_intervals: f.clean_intervals,
        open_intervals: f.open_intervals,
        class: f.class,
      })),
    }),
  );

  return {
    rounds: relapse.rounds,
    fronts,
    class_counts,
    total_relapsed_intervals,
    total_held_intervals,
    total_rounds,
    min_mean,
    most_fragile_dimension,
    fragile,
    durability_hash,
  };
}

/**
 * Did any front's *relapsed* recoveries average fewer than two clean rounds above the
 * acceptable floor — a front whose fix, when it recovers, *typically* does not survive even
 * one clean round before relapsing? The CI gate predicate — the *durability-magnitude*
 * counterpart to v40's lingering gate, and the above-floor mirror of it. It needs no
 * tuning: the bar is `mean < 2 rounds`, where two rounds is the first integer above the
 * metric's structural minimum of one clean round (a recovery and the immediately following
 * fall), so it separates the front that *typically* relapses fast from the one whose fixes
 * *typically* hold. **Strictly stronger evidence than v30's `exposureImmediateRelapse`**:
 * a fragile mean (`< 2`) forces at least one clean interval of one round (an all-integers
 * mean below two cannot avoid a 1), so every `fragile` front also trips v30's `immediate`
 * gate — but the converse fails. A front with intervals `[1, 5]` (mean 3) trips v30's
 * immediate gate on its single fast relapse yet is `durable` here; a front with `[1, 1, 1]`
 * (mean 1) trips both. v41 fires only on the *chronically* fragile front, suppressing the
 * single-fast-relapse alarm v30 raises — the central tendency the extreme cannot tell apart.
 */
export function recoveryFragile(durability: CoherenceDurability): boolean {
  return durability.fragile;
}

/**
 * Serialize a {@link CoherenceDurability} to a stable, pretty-printed JSON string. The key
 * order is fixed and the front order is already pinned by {@link computeCoherenceDurability},
 * so the same durability always yields identical bytes — the `durability_hash` it carries is
 * the canonical fingerprint, reproducible from `fronts` (over the integer interval lengths,
 * the derived `mean_durability` aside).
 */
export function buildCoherenceDurabilityJson(durability: CoherenceDurability): string {
  return JSON.stringify(
    {
      schema: "vaulytica.posture-durability.v1",
      durability_hash: durability.durability_hash,
      rounds: durability.rounds,
      class_counts: durability.class_counts,
      total_relapsed_intervals: durability.total_relapsed_intervals,
      total_held_intervals: durability.total_held_intervals,
      total_rounds: durability.total_rounds,
      min_mean: durability.min_mean,
      most_fragile_dimension: durability.most_fragile_dimension,
      fragile: durability.fragile,
      fronts: durability.fronts.map((f) => ({
        dimension: f.dimension,
        floors: f.floors,
        clean_intervals: f.clean_intervals,
        closed_intervals: f.closed_intervals,
        open_intervals: f.open_intervals,
        total_rounds: f.total_rounds,
        mean_durability: f.mean_durability,
        min_interval: f.min_interval,
        class: f.class,
      })),
    },
    null,
    2,
  );
}

/** Render a mean round count as a one-decimal string, e.g. `2` → `"2"`, `2.5` → `"2.5"`. */
function meanStr(mean: number): string {
  return Number.isInteger(mean) ? String(mean) : mean.toFixed(1);
}

/**
 * Render a {@link CoherenceDurability} as human-readable terminal lines: the most fragile
 * recovery (the front and its mean clean rounds above floor, or none when nothing relapsed),
 * the class tally, then one line per front that relapsed any recovery (its class, its mean
 * and quickest clean intervals, and its floor path), `fragile` fronts first. A `held`,
 * `steady`, or `unstated` front is counted but never listed (§3 honesty — a held recovery
 * carries no finite interval). Lives beside its JSON sibling so the CLI renders the
 * durability from one definition.
 */
export function renderCoherenceDurabilitySummary(durability: CoherenceDurability): string {
  const cc = durability.class_counts;
  const n = durability.rounds;
  const lines = [
    `\nCoherence recovery durability across ${n} rounds (mean clean rounds above floor per relapsed recovery):`,
    durability.min_mean === null
      ? `  most fragile recovery: none — no recovery was undone by a later fall in-sequence.`
      : `  most fragile recovery: ${durability.most_fragile_dimension} — relapsed fixes held above floor for ${meanStr(durability.min_mean)} round${durability.min_mean === 1 ? "" : "s"} on average.`,
    `  fronts: ${cc.fragile} fragile (typically < 2 rounds), ${cc.durable} durable; ${cc.held} held (never relapsed), ${cc.steady} steady, ${cc.unstated} never stated.`,
  ];
  const relapsed = durability.fronts.filter((f) => f.closed_intervals > 0);
  // Fragile fronts first (the weaker recoveries), then any durable front; each group keeps
  // the localeCompare order the fronts already carry.
  for (const f of [
    ...relapsed.filter((f) => f.class === "fragile"),
    ...relapsed.filter((f) => f.class === "durable"),
  ]) {
    const path = f.floors.map((t) => t ?? "—").join(" → ");
    const mark = f.class === "fragile" ? "⚠" : "·";
    const heldNote = f.open_intervals > 0 ? `, ${f.open_intervals} still holding` : "";
    lines.push(
      `  ${mark} ${f.dimension}: ${f.class} — mean ${meanStr(f.mean_durability!)} of ${f.closed_intervals} relapsed recover${f.closed_intervals === 1 ? "y" : "ies"} (quickest ${f.min_interval})${heldNote} (${path}).`,
    );
  }
  lines.push(`  durability_hash: ${durability.durability_hash}`);
  return lines.join("\n") + "\n";
}
