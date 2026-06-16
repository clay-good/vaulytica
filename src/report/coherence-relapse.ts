/**
 * Cross-document negotiation-posture **exposure relapse interval** — per front, the
 * number of rounds its binding floor held *above* the acceptable floor between a
 * *recovery* crossing and the *fall* crossing that undoes it, and whether a recovery
 * was ever relapsed at the very next round (spec-v30).
 *
 * v28 ({@link computeCoherenceLatency}) pairs each *fall* (at-or-above → below) with
 * the *recovery* (below → at-or-above) that closes it, and reads the rounds the front
 * sat **below** floor between them (`latency`, headlined by the slowest recovery
 * `max_latency`, gated on a fall that *never* recovered). v30 is its **mirror**: it
 * pairs each *recovery* with the *next fall* that undoes it, and reads the rounds the
 * front held **above** floor between them (`clean_rounds`) — the "clean interval" a
 * relapse ends.
 *
 * A count and a below-duration both throw away the one axis a deal lead asks reviewing
 * a close that bounced: **once a front recovered above the floor, how long did the fix
 * hold before it fell again — and did it ever relapse at the very next round?** Two
 * fronts v24 reports identically (both fell, recovered, fell again → three crossings
 * each) can be opposites here:
 *
 * - The **durable fix.** Cap recovers in round 2 and does not fall again until round 6 —
 *   the recovery held for *four* rounds before relapsing.
 * - The **fix that did not hold.** Cap recovers in round 2 and falls again in round 3 —
 *   the recovery held for a *single* round; it bounced straight back below floor.
 *
 * That is a missing **axis**: the *relapse-interval* dimension of the same crossing
 * data — the mirror of v28's recovery latency. Where v28 measures the rounds *below*
 * between a fall and its recovery, v30 measures the rounds *above* between a recovery
 * and its next fall — each interval's `clean_rounds`, the deal's quickest relapse
 * (`min_interval`), and whether any recovery was undone at the very next round
 * (`immediate`).
 *
 * It is a reduction of the **same** floor crossings v24/v25/v28 read —
 * `total_crossings` equals v24's grand total and v25/v26/v27/v28/v29's totals by
 * construction. It adds **no** posture math beyond pairing recoveries and the falls that
 * undo them across the `below-acceptable` rung v10 defines, over the binding floors v12
 * derived and v22/v24/v25/v28 already read. The posture filter (spec-v10 §3), restated:
 *  - **Deterministic** — same N coherences in the same order → identical
 *    `relapse_hash`, on any machine. Fronts are pinned by `localeCompare(_, "en")`
 *    (the same order the trajectory/exposure/volatility/synchrony/settling/onset/
 *    latency functions pin fronts); the round order is the caller's.
 *  - **Honest about unstated data** — a front no document states in a round does not
 *    cross *into* or *out of* that round: silence is neither a fall nor a recovery
 *    (the §3 contract that keeps `above → unstated → above` zero crossings in v24). A
 *    crossing across a silent gap is attributed to the transition *into the round that
 *    reveals the new standing*, so a clean interval that spans a silent round is
 *    measured to the round that reveals the relapse — never to the silent step.
 *  - **Advisory** — the report names how many rounds the team's own floor stayed clear
 *    between a recovery and the fall that undoes it. It asserts no legal conclusion.
 *  - **Additive** — the relapse carries its own `relapse_hash`, namespaced apart
 *    from every `coherence_hash`, `movement_hash`, `trajectory_hash`,
 *    `shift_trajectory_hash`, `arc_hash`, `exposure_hash`, `persistence_hash`,
 *    `breadth_hash`, `recurrence_hash`, `volatility_hash`, `synchrony_hash`,
 *    `settling_hash`, `onset_hash`, `latency_hash`, and `concurrency_hash`, so
 *    computing it moves no golden.
 */

import type { NegotiationTier } from "../playbooks/custom-interpreter.js";
import { sha256Hex } from "../ingest/hash.js";
import { stableStringify } from "../engine/runner.js";
import type { PostureCoherence } from "./posture-coherence.js";

/** The team's acceptable floor — the one rung whose name means "below what we will accept." */
const BELOW_FLOOR: NegotiationTier = "below-acceptable";

/**
 * A front's relapse-interval class:
 *  - `relapsed` — a recovery was undone by a later *fall* in-sequence (≥ 1 closed clean
 *    interval — the fix did not hold);
 *  - `held` — it recovered above floor in-sequence and *every* recovery held (≥ 1 open
 *    interval, none closed — no fall ever undid a recovery);
 *  - `steady` — stated, but never *recovered* above floor in-sequence (no recovery
 *    crossing to pair forward — including a front that never fell, and one that fell and
 *    never came back);
 *  - `unstated` — no document ever stated the front (§3: silence is not exposure).
 */
export type RelapseClass = "relapsed" | "held" | "steady" | "unstated";

/** One recovery-to-relapse span on a single front. */
export type CoherenceRelapseInterval = {
  /** The 1-based round the front was first seen back *at-or-above* floor (the recovery's `to_round`). */
  recovery_round: number;
  /** The 1-based round it was next seen *below* floor again (`null` when the recovery held). */
  fall_round: number | null;
  /** The rounds it held above floor: `fall_round − recovery_round` (`null` when held). */
  clean_rounds: number | null;
};

/** One negotiation front's whole-sequence relapse structure. */
export type CoherenceRelapseFront = {
  dimension: string;
  /** The binding floor at each round, in sequence order (`null` = unstated that round). */
  floors: (NegotiationTier | null)[];
  /** How many times the front's standing crossed the floor boundary (equals v24's per-front `crossings`). */
  crossings: number;
  /** The recovery-to-relapse spans, in sequence order. */
  intervals: CoherenceRelapseInterval[];
  /** The front's shortest *closed* interval — its quickest relapse (`null` when none relapsed). */
  min_interval: number | null;
  /** The relapse-interval class. */
  relapse: RelapseClass;
};

export type CoherenceRelapse = {
  /** How many rounds (coherences) the relapse spans. */
  rounds: number;
  fronts: CoherenceRelapseFront[];
  /** Per-front tally by relapse class. */
  class_counts: Record<RelapseClass, number>;
  /** Every front's crossing, summed — equals v24's grand total and v25/v26/v27/v28/v29's totals. */
  total_crossings: number;
  /** How many recovery-to-fall intervals closed with a relapse (across all fronts). */
  relapse_count: number;
  /** How many recoveries held — an interval left open at the close (across all fronts). */
  held_count: number;
  /** The quickest relapse across the deal — the shortest *closed* interval (`null` when none relapsed). */
  min_interval: number | null;
  /** The front owning {@link min_interval} (earliest on a tie; `null` when none relapsed). */
  quickest_dimension: string | null;
  /** Did any recovery relapse at the *very next* round (`clean_rounds === 1`)? The gate-worthy verdict. */
  immediate: boolean;
  /** SHA-256 over the canonical per-front interval set — additive, apart from every other hash. */
  relapse_hash: string;
};

function emptyClassCounts(): Record<RelapseClass, number> {
  return { relapsed: 0, held: 0, steady: 0, unstated: 0 };
}

/**
 * Scan one front's binding-floor path and pair its recoveries with the falls that
 * undo them — the mirror of v28's {@link computeCoherenceLatency} fall-to-recovery
 * pairing. A crossing is a transition between two *stated* rounds on opposite sides of
 * the floor — one `below-acceptable`, the other at-or-above it — in either direction.
 * An unstated round (`null`) is skipped: it neither counts as a crossing nor resets the
 * standing (silence is not a fall or a recovery, §3), so a crossing across a silent gap
 * is attributed to the round that *reveals* the new standing.
 *
 * A *recovery* (below → at-or-above) opens a clean interval at the round it reveals; the
 * next *fall* (at-or-above → below) closes it at the round it reveals — a relapse. A fall
 * with no open recovery (the front's first fall, before any recovery) closes nothing. A
 * recovery left unrelapsed at the end is an *open* interval (`fall_round` `null`) — the
 * recovery held. Returns the total crossing count (both directions — equal to v24's
 * per-front `crossings`), the intervals, and whether any round was stated.
 */
function scanIntervals(floors: (NegotiationTier | null)[]): {
  crossings: number;
  intervals: CoherenceRelapseInterval[];
  stated: boolean;
} {
  let crossings = 0;
  let stated = false;
  let prevBelow: boolean | null = null; // the last *stated* round's below-floor state
  let openRecoveryRound: number | null = null; // the to_round of an in-progress recovery
  const intervals: CoherenceRelapseInterval[] = [];

  for (let i = 0; i < floors.length; i++) {
    const t = floors[i];
    if (t === null) continue; // silence: neither crosses nor resets the standing (§3)
    stated = true;
    const isBelow = t === BELOW_FLOOR;
    if (prevBelow !== null && prevBelow !== isBelow) {
      crossings += 1;
      const round = i + 1; // the round (1-based) that reveals the new standing
      if (!isBelow) {
        // A recovery: open a clean interval at the revealing round.
        openRecoveryRound = round;
      } else if (openRecoveryRound !== null) {
        // A fall that undoes an open recovery — a relapse.
        intervals.push({
          recovery_round: openRecoveryRound,
          fall_round: round,
          clean_rounds: round - openRecoveryRound,
        });
        openRecoveryRound = null;
      }
      // A fall with no open recovery is the front's first fall — it closes no interval.
    }
    prevBelow = isBelow;
  }

  // A recovery never undone by a fall is an open interval (the recovery held).
  if (openRecoveryRound !== null) {
    intervals.push({ recovery_round: openRecoveryRound, fall_round: null, clean_rounds: null });
  }

  return { crossings, intervals, stated };
}

/**
 * Walk N cross-document posture coherences — the same bundle at round 1, round
 * 2, …, round N — and report, per negotiation front, how many rounds its binding
 * floor held *above* the acceptable floor between a recovery and the fall that undoes
 * it (`clean_rounds`), the deal's quickest such relapse (`min_interval`), and whether
 * any recovery was undone at the very next round (`immediate`), not merely how many
 * times it crossed (v24's count) or how long it sat below (v28's latency).
 *
 * Pure and deterministic: fronts are matched by dimension and pinned by
 * `localeCompare`, the round order is the caller's, and `relapse_hash` is over the
 * canonical per-front interval set, so the same N coherences in the same order always
 * yield identical bytes.
 *
 * Every coherence must have been computed against the **same** team positions (the
 * caller applies one active playbook to every document in every round); comparing
 * floors across different ladders is nonsense, the same way v13/v16 refuse a
 * cross-ladder diff. The CLI core ({@link computeCoherenceRelapseArtifacts}) enforces
 * this via the v15/v16 ladder guard before calling this.
 *
 * Requires at least two rounds — a relapse interval is a *between-round* span; a single
 * round has no transition to pair a recovery and a fall over.
 */
export async function computeCoherenceRelapse(
  rounds: readonly PostureCoherence[],
): Promise<CoherenceRelapse> {
  if (rounds.length < 2) {
    throw new Error(`a relapse needs at least two rounds (got ${rounds.length})`);
  }

  const byDim = rounds.map((c) => new Map(c.dimensions.map((d) => [d.dimension, d])));
  const labels = Array.from(
    new Set(rounds.flatMap((c) => c.dimensions.map((d) => d.dimension))),
  ).sort((a, b) => a.localeCompare(b, "en"));

  const class_counts = emptyClassCounts();
  let total_crossings = 0;
  let relapse_count = 0;
  let held_count = 0;
  let min_interval: number | null = null;
  let quickest_dimension: string | null = null;
  let immediate = false;

  const fronts: CoherenceRelapseFront[] = labels.map((dimension) => {
    const floors = byDim.map((m) => m.get(dimension)?.weakest_tier ?? null);
    const { crossings, intervals, stated } = scanIntervals(floors);
    total_crossings += crossings;

    let frontMin: number | null = null;
    let hasClosed = false;
    let hasOpen = false;
    for (const iv of intervals) {
      if (iv.fall_round === null) {
        hasOpen = true;
        held_count += 1;
      } else {
        hasClosed = true;
        relapse_count += 1;
        const clean = iv.clean_rounds!;
        if (frontMin === null || clean < frontMin) frontMin = clean;
        if (clean === 1) immediate = true;
      }
    }

    // The quickest relapse across the deal: the first front (in localeCompare order)
    // whose closed interval reaches the min wins a tie (`<` keeps the earliest).
    if (frontMin !== null && (min_interval === null || frontMin < min_interval)) {
      min_interval = frontMin;
      quickest_dimension = dimension;
    }

    const relapse: RelapseClass = !stated
      ? "unstated"
      : hasClosed
        ? "relapsed"
        : hasOpen
          ? "held"
          : "steady";
    class_counts[relapse] += 1;

    return { dimension, floors, crossings, intervals, min_interval: frontMin, relapse };
  });

  const relapse_hash = await sha256Hex(
    stableStringify({
      rounds: rounds.length,
      fronts: fronts.map((f) => ({
        dimension: f.dimension,
        floors: f.floors,
        crossings: f.crossings,
        intervals: f.intervals.map((iv) => ({
          recovery_round: iv.recovery_round,
          fall_round: iv.fall_round,
          clean_rounds: iv.clean_rounds,
        })),
        min_interval: f.min_interval,
        relapse: f.relapse,
      })),
    }),
  );

  return {
    rounds: rounds.length,
    fronts,
    class_counts,
    total_crossings,
    relapse_count,
    held_count,
    min_interval,
    quickest_dimension,
    immediate,
    relapse_hash,
  };
}

/**
 * Did any recovery relapse at the **very next round** — a front recovered above the
 * acceptable floor and fell back below it on the next stated step (`clean_rounds === 1`)?
 * The CI gate predicate — the *relapse-interval* counterpart to v28's recovery-latency
 * gate. Unlike `exposureUnrecovered` (a fall that never closed with a recovery — an
 * unbounded *below*-duration), this fires on a recovery whose *above*-duration was the
 * shortest possible: the fix did not hold for even one clean round. It needs no
 * tuning — a recovery undone the very next round *is* a fix that did not hold. A
 * recovery that held for two or more rounds before relapsing clears it (the relapse is
 * `relapsed` but not `immediate`); a consumer wanting a wider bar reads `min_interval`
 * and the per-interval `clean_rounds` instead. **Distinct from v24's crossing count**:
 * a front can cross many times without any *adjacent* recover-then-fall pair; this fires
 * only on the recover-then-fall-next-round pattern.
 */
export function exposureImmediateRelapse(relapse: CoherenceRelapse): boolean {
  return relapse.immediate;
}

/**
 * Serialize a {@link CoherenceRelapse} to a stable, pretty-printed JSON string. The
 * key order is fixed and the front order is already pinned by
 * {@link computeCoherenceRelapse}, so the same relapse always yields identical bytes —
 * the `relapse_hash` it carries is the canonical fingerprint, reproducible from
 * `fronts`.
 */
export function buildCoherenceRelapseJson(relapse: CoherenceRelapse): string {
  return JSON.stringify(
    {
      schema: "vaulytica.posture-relapse.v1",
      relapse_hash: relapse.relapse_hash,
      rounds: relapse.rounds,
      class_counts: relapse.class_counts,
      total_crossings: relapse.total_crossings,
      relapse_count: relapse.relapse_count,
      held_count: relapse.held_count,
      min_interval: relapse.min_interval,
      quickest_dimension: relapse.quickest_dimension,
      immediate: relapse.immediate,
      fronts: relapse.fronts.map((f) => ({
        dimension: f.dimension,
        floors: f.floors,
        crossings: f.crossings,
        intervals: f.intervals.map((iv) => ({
          recovery_round: iv.recovery_round,
          fall_round: iv.fall_round,
          clean_rounds: iv.clean_rounds,
        })),
        min_interval: f.min_interval,
        relapse: f.relapse,
      })),
    },
    null,
    2,
  );
}

/**
 * Render a {@link CoherenceRelapse} as human-readable terminal lines: the quickest
 * relapse (the front and the rounds it held above floor, or held-throughout when no
 * recovery was ever undone), the relapse/held counts, then one line per front that
 * holds an interval (its class and its recovery-to-relapse spans). A `steady` or
 * `unstated` front is counted but never listed (§3 honesty). Lives beside its JSON
 * sibling so the CLI renders the relapse from one definition.
 */
export function renderCoherenceRelapseSummary(relapse: CoherenceRelapse): string {
  const cc = relapse.class_counts;
  const n = relapse.rounds;
  const lines = [
    `\nCoherence exposure relapse interval across ${n} rounds (rounds above floor per recovery-to-relapse span):`,
    relapse.min_interval === null
      ? `  quickest relapse: none — no recovery was undone by a later fall in-sequence.`
      : `  quickest relapse: ${relapse.quickest_dimension} — held above floor for ${relapse.min_interval} round${relapse.min_interval === 1 ? "" : "s"} before falling again.`,
    `  intervals: ${relapse.relapse_count} relapsed, ${relapse.held_count} held (a recovery never undone); ${cc.steady} steady, ${cc.unstated} never stated.`,
  ];
  for (const f of relapse.fronts) {
    if (f.relapse !== "relapsed" && f.relapse !== "held") continue;
    const path = f.floors.map((t) => t ?? "—").join(" → ");
    const spans = f.intervals
      .map((iv) =>
        iv.fall_round === null
          ? `recovered round ${iv.recovery_round}, held`
          : `recovered round ${iv.recovery_round} → fell again round ${iv.fall_round} (${iv.clean_rounds} round${iv.clean_rounds === 1 ? "" : "s"} above)`,
      )
      .join("; ");
    const mark =
      f.relapse === "relapsed" && f.intervals.some((iv) => iv.clean_rounds === 1) ? "⚠" : "·";
    lines.push(`  ${mark} ${f.dimension}: ${f.relapse} — ${spans} (${path}).`);
  }
  lines.push(`  relapse_hash: ${relapse.relapse_hash}`);
  return lines.join("\n") + "\n";
}
