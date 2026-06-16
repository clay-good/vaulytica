/**
 * Cross-document negotiation-posture **exposure concurrency** — the per-round
 * *transition* count of how many fronts' binding floors crossed the acceptable
 * floor in the *same step*, split by **direction**: fronts that *fell* (at-or-above
 * → below) vs. fronts that *recovered* (below → at-or-above) in that one step
 * (spec-v29).
 *
 * v25 ({@link computeCoherenceSynchrony}) reads the posture archive down the round
 * axis on the *movement*: pick a round-transition, count how many fronts *crossed*
 * the floor that step (`crossing_fronts`) — but it is **direction-blind**. A step
 * where three fronts *fell* below floor together and a step where two fell while one
 * recovered both register as the *same* synchrony to v25 (a count of crossings,
 * falls and recoveries indistinguishable). So from the v25 archive a deal lead can
 * answer "was there a round the package *lurched* — three fronts moved at once?" but
 * not "was there a round the package *collapsed* — three fronts fell **the same
 * direction**, below floor, together?" That is a missing **axis**: the
 * direction-resolved transpose of v25's per-step crossing count.
 *
 * This module is that split:
 *
 *  - v25 answers *for each round-transition, count the fronts that crossed the floor
 *    that step* — direction-blind (a fall and a recovery both count as one crossing).
 *  - v29 (here) answers *for each round-transition, count the fronts that **fell**
 *    and the fronts that **recovered** that step, separately* — the deal's
 *    coordinated collapse (`falling ≥ 2`, a *concerted fall*) distinguished from a
 *    coordinated rebound (`recovering ≥ 2`, a *concerted recovery*) and from churn
 *    (fronts moving *both* ways in one step, `mixed`), the deal's **peak fall step**
 *    (the single step the most fronts fell at once), and whether any step was a
 *    concerted fall. A redline round that knocked several fronts below floor *at
 *    once* trips the gate even when no single front is volatile across the whole deal
 *    and even when v25 would call the step merely "synchronized" (it cannot tell a
 *    concerted fall from a fall-and-recover churn).
 *
 * It is a re-bucketing of the **same** floor crossings v24 counts and v25 buckets per
 * step: the sum of every transition's `falling + recovering` equals the sum of every
 * front's v24 `crossings` (`total_crossings`), and `total_falls + total_recoveries`
 * equals it too. v24 slices the crossings by *front*; v25 slices them by *step*; v29
 * slices each step's crossings by *direction*. It adds **no** posture math beyond that
 * direction split of transitions across the `below-acceptable` rung v10 defines, over
 * the binding floors v12 derived and v22/v24/v25 already read. The posture filter
 * (spec-v10 §3), restated:
 *  - **Deterministic** — same N coherences in the same order → identical
 *    `concurrency_hash`, on any machine. The round order is the caller's; the
 *    per-transition fell/recovered dimension lists are pinned by
 *    `localeCompare(_, "en")` (the same order the trajectory/exposure/volatility/
 *    synchrony functions pin fronts).
 *  - **Honest about unstated data** — a front no document states in a round does not
 *    cross *into* or *out of* that round: silence is neither a fall nor a recovery
 *    (the §3 contract that keeps `below → unstated → below` zero crossings in v24).
 *    A crossing across a silent gap is attributed to the transition *into the round
 *    that reveals the new standing*, so `below → unstated → acceptable` is one
 *    recovery on the step ending at the third round — never an invented crossing on
 *    the silent step.
 *  - **Advisory** — the report names how many fronts moved each way across the team's
 *    own floor in each step. It asserts no legal conclusion.
 *  - **Additive** — the concurrency carries its own `concurrency_hash`, namespaced
 *    apart from every `coherence_hash`, `movement_hash`, `trajectory_hash`,
 *    `shift_trajectory_hash`, `arc_hash`, `exposure_hash`, `persistence_hash`,
 *    `breadth_hash`, `recurrence_hash`, `volatility_hash`, `synchrony_hash`,
 *    `settling_hash`, `onset_hash`, and `latency_hash`, so computing it moves no golden.
 */

import type { NegotiationTier } from "../playbooks/custom-interpreter.js";
import { sha256Hex } from "../ingest/hash.js";
import { stableStringify } from "../engine/runner.js";
import type { PostureCoherence } from "./posture-coherence.js";

/** The team's acceptable floor — the one rung whose name means "below what we will accept." */
const BELOW_FLOOR: NegotiationTier = "below-acceptable";

/**
 * One round-transition's *direction-resolved* concurrency class (priority order):
 *  - `concerted-fall` — **two or more** fronts *fell* below floor in this one step
 *    (a coordinated collapse — the gate-worthy class; dominates even if a recovery
 *    also happened that step);
 *  - `concerted-recovery` — two or more fronts *recovered* and fewer than two fell (a
 *    coordinated rebound);
 *  - `mixed` — fronts moved *both* ways in one step but neither direction reached two
 *    (exactly one fell *and* at least one recovered — churn across the floor);
 *  - `isolated` — exactly one front crossed, in one direction;
 *  - `quiet` — no front crossed the floor this step.
 */
export type ConcurrencyClass =
  | "concerted-fall"
  | "concerted-recovery"
  | "mixed"
  | "isolated"
  | "quiet";

/** One round-transition's deal-wide movement, resolved by direction. */
export type CoherenceConcurrencyTransition = {
  /** The 1-based round this step starts at, in sequence order. */
  from_round: number;
  /** The 1-based round this step ends at (`from_round + 1`). */
  to_round: number;
  /** How many fronts *fell* below floor in this step (at-or-above → below). */
  falling: number;
  /** How many fronts *recovered* in this step (below → at-or-above). */
  recovering: number;
  /** The fronts that fell this step, pinned by `localeCompare` (deterministic). */
  falling_dimensions: string[];
  /** The fronts that recovered this step, pinned by `localeCompare` (deterministic). */
  recovering_dimensions: string[];
  /** The direction-resolved concurrency class for this step. */
  concurrency: ConcurrencyClass;
};

export type CoherenceConcurrency = {
  /** How many rounds (coherences) the concurrency spans. */
  rounds: number;
  /** The per-transition deal-wide movement, in sequence order (length = rounds − 1). */
  per_transition: CoherenceConcurrencyTransition[];
  /** Every front's crossing, summed over the steps — equals v24's grand crossing total. */
  total_crossings: number;
  /** Every *fall* crossing summed over the steps (`total_falls + total_recoveries = total_crossings`). */
  total_falls: number;
  /** Every *recovery* crossing summed over the steps. */
  total_recoveries: number;
  /** The 1-based `from_round` of the step the most fronts *fell* at once (earliest on a tie; `null` when none ever fell). */
  peak_fall_transition: number | null;
  /** The fell-front count at {@link peak_fall_transition} (0 when no front ever fell). */
  peak_fall_count: number;
  /** How many steps were a *concerted fall* (≥2 fronts falling at once — the gate-worthy count). */
  concerted_fall_count: number;
  /** How many steps were a *concerted recovery* (≥2 recovering, <2 falling). */
  concerted_recovery_count: number;
  /** How many steps were *mixed* (fronts moving both ways, neither direction reaching two). */
  mixed_count: number;
  /** Did any single step see two or more fronts fall below floor together? The gate-worthy verdict. */
  concerted: boolean;
  /** SHA-256 over the canonical per-transition set — additive, apart from every other hash. */
  concurrency_hash: string;
};

/**
 * Walk N cross-document posture coherences — the same bundle at round 1, round
 * 2, …, round N — and report, *per round-transition*, how many fronts' binding
 * floors *fell* below the acceptable floor and how many *recovered* in that step,
 * resolved by direction (the deal's coordinated movement that step), plus the peak
 * fall step (the single step the most fronts fell at once) and how many steps were a
 * concerted fall.
 *
 * Pure and deterministic: the round order is the caller's, the per-transition
 * fell/recovered dimension lists are pinned by `localeCompare`, and
 * `concurrency_hash` is over the canonical per-transition set, so the same N
 * coherences in the same order always yield identical bytes.
 *
 * A crossing is a transition between two *stated* rounds on opposite sides of the
 * floor (one `below-acceptable`, the other at-or-above it); a *fall* is at-or-above →
 * below, a *recovery* is below → at-or-above. An unstated round is skipped: it neither
 * crosses nor resets the standing (§3), so a crossing across a silent gap is
 * attributed to the transition into the round that *reveals* the new standing — never
 * to the silent step. Summed over all transitions, the crossing count equals v24's
 * per-front crossing total (`total_crossings`) and `total_falls + total_recoveries`:
 * v29 is the same crossings re-bucketed by step *and direction* instead of by front.
 *
 * Every coherence must have been computed against the **same** team positions (the
 * caller applies one active playbook to every document in every round); comparing
 * floors across different ladders is nonsense, the same way v13/v16 refuse a
 * cross-ladder diff. The CLI core ({@link computeCoherenceConcurrencyArtifacts})
 * enforces this via the v15/v16 ladder guard before calling this.
 *
 * Requires at least two rounds — concurrency is a *between-round* movement; a single
 * round has no transition to count crossings over.
 */
export async function computeCoherenceConcurrency(
  rounds: readonly PostureCoherence[],
): Promise<CoherenceConcurrency> {
  if (rounds.length < 2) {
    throw new Error(`a concurrency needs at least two rounds (got ${rounds.length})`);
  }

  const byDim = rounds.map((c) => new Map(c.dimensions.map((d) => [d.dimension, d])));
  const labels = Array.from(
    new Set(rounds.flatMap((c) => c.dimensions.map((d) => d.dimension))),
  ).sort((a, b) => a.localeCompare(b, "en"));

  // One bucket per round-transition (round k → round k+1, k = 1…N−1), split by
  // direction. Each front's crossing is attributed to the step into the round that
  // *reveals* the new standing, so the per-transition totals re-bucket v24's per-front
  // crossings by step and direction.
  const fellByTransition: string[][] = Array.from({ length: rounds.length - 1 }, () => []);
  const recoveredByTransition: string[][] = Array.from({ length: rounds.length - 1 }, () => []);

  for (const dimension of labels) {
    const floors = byDim.map((m) => m.get(dimension)?.weakest_tier ?? null);
    let prevBelow: boolean | null = null; // the last *stated* round's below-floor state
    for (let i = 0; i < floors.length; i++) {
      const t = floors[i];
      if (t === null) continue; // silence: neither crosses nor resets the standing (§3)
      const isBelow = t === BELOW_FLOOR;
      // A flip vs. the previous stated round is a crossing on the step ending at
      // round i+1 — i.e. transition (i → i+1), held at per-transition index i−1.
      if (prevBelow !== null && prevBelow !== isBelow) {
        if (isBelow) fellByTransition[i - 1]!.push(dimension);
        else recoveredByTransition[i - 1]!.push(dimension);
      }
      prevBelow = isBelow;
    }
  }

  let total_crossings = 0;
  let total_falls = 0;
  let total_recoveries = 0;
  let peak_fall_transition: number | null = null;
  let peak_fall_count = 0;
  let concerted_fall_count = 0;
  let concerted_recovery_count = 0;
  let mixed_count = 0;

  const per_transition: CoherenceConcurrencyTransition[] = fellByTransition.map((fell, idx) => {
    const recovered = recoveredByTransition[idx]!;
    // The labels were iterated in localeCompare order, so the lists are already
    // pinned; the explicit sort keeps them deterministic regardless.
    fell.sort((a, b) => a.localeCompare(b, "en"));
    recovered.sort((a, b) => a.localeCompare(b, "en"));
    const falling = fell.length;
    const recovering = recovered.length;
    total_falls += falling;
    total_recoveries += recovering;
    total_crossings += falling + recovering;

    // The peak fall step is the one the most fronts fell at once; the first such step
    // wins a tie (earliest-peak, mirroring v25's earliest-peak tiebreak).
    if (falling > peak_fall_count) {
      peak_fall_count = falling;
      peak_fall_transition = idx + 1;
    }

    // Priority: a concerted fall dominates (the gate-worthy class), then a concerted
    // recovery, then churn (both directions, neither reaching two), then isolated.
    let concurrency: ConcurrencyClass;
    if (falling >= 2) {
      concurrency = "concerted-fall";
      concerted_fall_count += 1;
    } else if (recovering >= 2) {
      concurrency = "concerted-recovery";
      concerted_recovery_count += 1;
    } else if (falling >= 1 && recovering >= 1) {
      concurrency = "mixed";
      mixed_count += 1;
    } else if (falling + recovering === 1) {
      concurrency = "isolated";
    } else {
      concurrency = "quiet";
    }

    return {
      from_round: idx + 1,
      to_round: idx + 2,
      falling,
      recovering,
      falling_dimensions: fell,
      recovering_dimensions: recovered,
      concurrency,
    };
  });

  const concurrency_hash = await sha256Hex(
    stableStringify({
      rounds: rounds.length,
      per_transition: per_transition.map((t) => ({
        from_round: t.from_round,
        to_round: t.to_round,
        falling: t.falling,
        recovering: t.recovering,
        falling_dimensions: t.falling_dimensions,
        recovering_dimensions: t.recovering_dimensions,
        concurrency: t.concurrency,
      })),
    }),
  );

  return {
    rounds: rounds.length,
    per_transition,
    total_crossings,
    total_falls,
    total_recoveries,
    peak_fall_transition,
    peak_fall_count,
    concerted_fall_count,
    concerted_recovery_count,
    mixed_count,
    concerted: concerted_fall_count > 0,
    concurrency_hash,
  };
}

/**
 * Did any single step see **two or more** fronts *fall* below the team's acceptable
 * floor at once — was there a round the package *collapsed*? The CI gate predicate —
 * the *direction-resolved* counterpart to v25's synchrony gate. Unlike
 * `exposureSynchronized` (which fires on any step where ≥2 fronts crossed the floor,
 * falls and recoveries indistinguishable — a fall-and-recover churn trips it just as a
 * coordinated collapse does), this fires only on a step where ≥2 fronts moved the
 * **same** way, *down*, below floor: a concerted fall. It needs no tuning — two fronts
 * falling at once *is* a coordinated regression. A consumer wanting a higher
 * simultaneity reads `peak_fall_count`; one wanting the coordinated *rebound* reads
 * `concerted_recovery_count`.
 */
export function exposureConcerted(concurrency: CoherenceConcurrency): boolean {
  return concurrency.concerted_fall_count > 0;
}

/**
 * Serialize a {@link CoherenceConcurrency} to a stable, pretty-printed JSON string.
 * The key order is fixed and the per-transition series is already in sequence order
 * with `localeCompare`-pinned dimension lists, so the same concurrency always yields
 * identical bytes — the `concurrency_hash` it carries is the canonical fingerprint,
 * reproducible from `per_transition`.
 */
export function buildCoherenceConcurrencyJson(concurrency: CoherenceConcurrency): string {
  return JSON.stringify(
    {
      schema: "vaulytica.posture-concurrency.v1",
      concurrency_hash: concurrency.concurrency_hash,
      rounds: concurrency.rounds,
      total_crossings: concurrency.total_crossings,
      total_falls: concurrency.total_falls,
      total_recoveries: concurrency.total_recoveries,
      peak_fall_transition: concurrency.peak_fall_transition,
      peak_fall_count: concurrency.peak_fall_count,
      concerted_fall_count: concurrency.concerted_fall_count,
      concerted_recovery_count: concurrency.concerted_recovery_count,
      mixed_count: concurrency.mixed_count,
      concerted: concurrency.concerted,
      per_transition: concurrency.per_transition.map((t) => ({
        from_round: t.from_round,
        to_round: t.to_round,
        falling: t.falling,
        recovering: t.recovering,
        falling_dimensions: t.falling_dimensions,
        recovering_dimensions: t.recovering_dimensions,
        concurrency: t.concurrency,
      })),
    },
    null,
    2,
  );
}

/**
 * Render a {@link CoherenceConcurrency} as human-readable terminal lines: the peak
 * fall step (the round the most fronts fell below floor at once), how many steps were
 * a concerted fall, then one line per step showing how many fronts fell and recovered
 * and which. Lives beside its JSON sibling so the CLI renders the concurrency from one
 * definition.
 */
export function renderCoherenceConcurrencySummary(concurrency: CoherenceConcurrency): string {
  const n = concurrency.rounds;
  const lines = [
    `\nCoherence exposure concurrency across ${n} rounds (fronts falling vs. recovering per step):`,
    concurrency.peak_fall_transition === null
      ? `  peak fall step: none — no front ever fell below the floor.`
      : `  peak fall step: round ${concurrency.peak_fall_transition}→${concurrency.peak_fall_transition + 1} (${concurrency.peak_fall_count} front${concurrency.peak_fall_count === 1 ? "" : "s"} fell below the floor at once).`,
    `  concerted falls (≥2 fronts falling at once): ${concurrency.concerted_fall_count} of ${concurrency.per_transition.length}.`,
  ];
  for (const t of concurrency.per_transition) {
    const fellDims = t.falling === 0 ? "—" : t.falling_dimensions.join(", ");
    const recDims = t.recovering === 0 ? "—" : t.recovering_dimensions.join(", ");
    const mark = t.concurrency === "concerted-fall" ? "⚠" : "·";
    lines.push(
      `  ${mark} round ${t.from_round}→${t.to_round}: ${t.falling} fell (${fellDims}), ${t.recovering} recovered (${recDims}) [${t.concurrency}].`,
    );
  }
  lines.push(`  concurrency_hash: ${concurrency.concurrency_hash}`);
  return lines.join("\n") + "\n";
}
