/**
 * Cross-document negotiation-posture **exposure synchrony** — the per-round
 * *transition* count of how many fronts' binding floors *crossed* the acceptable
 * floor in the *same step* (spec-v25).
 *
 * v24 ({@link computeCoherenceVolatility}) reads the posture archive **down the
 * front axis**: pick a negotiation front, count how many times its standing
 * crossed the floor *across all rounds* (`crossings`). v22
 * ({@link computeCoherenceBreadth}) reads it **down the round axis**, but only on
 * the *level*: pick a round, count how many fronts sat *below* the floor that round
 * (a static standing). Neither reads the archive down the round axis on the
 * *movement*: pick a round-*transition*, count how many fronts *crossed* the floor
 * in that one step. So from the archive a deal lead can answer "how many fronts
 * were below floor in round 3?" (v22, a snapshot) and "how many times did the Cap
 * front cross the floor over the whole deal?" (v24, a per-front sum) but not "was
 * there a single round where the *package lurched* — three fronts moved across the
 * floor at once?" That is a missing **axis**: the per-transition transpose of v24's
 * per-front crossing count.
 *
 * This module is that transpose:
 *
 *  - v24 answers *for each front, count its crossings across the rounds* — a
 *    per-front reduction (fix a front, sum over rounds).
 *  - v22 answers *for each round, count the fronts below floor* — a per-round
 *    reduction on the *level* (fix a round, count standings).
 *  - v25 (here) answers *for each round-transition, count the fronts that crossed
 *    the floor in that step* — a per-round reduction on the *movement* (fix a step,
 *    count crossings): the `crossing_fronts` per transition, the deal's **peak
 *    transition** (the single step with the most simultaneous crossings — the round
 *    the package lurched), and whether any step was **synchronized** (two or more
 *    fronts crossing the floor together). A coordinated shift — one redline round
 *    that knocked several fronts below floor at once, or won several back — trips
 *    the gate even when no single front is volatile across the whole deal.
 *
 * It is a re-bucketing of the **same** floor crossings v24 counts: the sum of every
 * transition's `crossing_fronts` equals the sum of every front's v24 `crossings`
 * (`total_crossings`). v24 slices the crossings by *front*; v25 slices them by
 * *step*. It adds **no** posture math beyond that re-bucketing of transitions across
 * the `below-acceptable` rung v10 defines, over the binding floors v12 derived and
 * v22/v24 already read. The posture filter (spec-v10 §3), restated:
 *  - **Deterministic** — same N coherences in the same order → identical
 *    `synchrony_hash`, on any machine. The round order is the caller's; the
 *    per-transition crossed-dimension lists are pinned by `localeCompare(_, "en")`
 *    (the same order the trajectory/exposure/volatility functions pin fronts).
 *  - **Honest about unstated data** — a front no document states in a round does not
 *    cross *into* or *out of* that round: silence is neither a fall nor a recovery
 *    (the §3 contract that keeps `below → unstated → below` zero crossings in v24).
 *    A crossing across a silent gap is attributed to the transition *into the round
 *    that reveals the new standing*, so `below → unstated → acceptable` is one
 *    crossing on the step ending at the third round — never an invented crossing on
 *    the silent step.
 *  - **Advisory** — the report names how many fronts moved across the team's own
 *    floor in each step. It asserts no legal conclusion.
 *  - **Additive** — the synchrony carries its own `synchrony_hash`, namespaced apart
 *    from every `coherence_hash`, `movement_hash`, `trajectory_hash`,
 *    `shift_trajectory_hash`, `arc_hash`, `exposure_hash`, `persistence_hash`,
 *    `breadth_hash`, `recurrence_hash`, and `volatility_hash`, so computing it moves
 *    no golden.
 */

import type { NegotiationTier } from "../playbooks/custom-interpreter.js";
import { sha256Hex } from "../ingest/hash.js";
import { stableStringify } from "../engine/runner.js";
import type { PostureCoherence } from "./posture-coherence.js";

/** The team's acceptable floor — the one rung whose name means "below what we will accept." */
const BELOW_FLOOR: NegotiationTier = "below-acceptable";

/**
 * One round-transition's synchrony class:
 *  - `synchronized` — **two or more** fronts crossed the floor in this one step
 *    (a coordinated shift — the package lurched);
 *  - `isolated` — exactly one front crossed the floor this step;
 *  - `quiet` — no front crossed the floor this step.
 */
export type SynchronyClass = "synchronized" | "isolated" | "quiet";

/** One round-transition's deal-wide movement: how many fronts crossed the floor in this step. */
export type CoherenceSynchronyTransition = {
  /** The 1-based round this step starts at, in sequence order. */
  from_round: number;
  /** The 1-based round this step ends at (`from_round + 1`). */
  to_round: number;
  /** How many fronts crossed the floor boundary in this step (falls and recoveries alike). */
  crossing_fronts: number;
  /** The fronts that crossed this step, pinned by `localeCompare` (so the list is deterministic). */
  crossed_dimensions: string[];
  /** The synchrony class for this step. */
  synchrony: SynchronyClass;
};

export type CoherenceSynchrony = {
  /** How many rounds (coherences) the synchrony spans. */
  rounds: number;
  /** The per-transition deal-wide movement, in sequence order (length = rounds − 1). */
  per_transition: CoherenceSynchronyTransition[];
  /** Every front's crossing, summed over the steps — equals v24's grand crossing total. */
  total_crossings: number;
  /** The 1-based `from_round` of the step with the most simultaneous crossings (earliest on a tie; `null` when none ever crossed). */
  peak_transition: number | null;
  /** The crossing-front count at {@link peak_transition} (0 when no front ever crossed the floor). */
  peak_count: number;
  /** How many steps were synchronized (two or more fronts crossing at once — the gate-worthy count). */
  synchronized_count: number;
  /** SHA-256 over the canonical per-transition set — additive, apart from every other hash. */
  synchrony_hash: string;
};

/**
 * Walk N cross-document posture coherences — the same bundle at round 1, round
 * 2, …, round N — and report, *per round-transition*, how many fronts' binding
 * floors crossed the acceptable floor in that step (the deal's aggregate movement
 * that step), plus the peak transition (the single step the most fronts crossed at
 * once) and how many steps were synchronized.
 *
 * Pure and deterministic: the round order is the caller's, the per-transition
 * crossed-dimension lists are pinned by `localeCompare`, and `synchrony_hash` is
 * over the canonical per-transition set, so the same N coherences in the same order
 * always yield identical bytes.
 *
 * A crossing is a transition between two *stated* rounds on opposite sides of the
 * floor (one `below-acceptable`, the other at-or-above it), in either direction. An
 * unstated round is skipped: it neither crosses nor resets the standing (§3), so a
 * crossing across a silent gap is attributed to the transition into the round that
 * *reveals* the new standing — never to the silent step. Summed over all
 * transitions, the crossing count equals v24's per-front crossing total
 * (`total_crossings`): v25 is the same crossings re-bucketed by step instead of by
 * front.
 *
 * Every coherence must have been computed against the **same** team positions (the
 * caller applies one active playbook to every document in every round); comparing
 * floors across different ladders is nonsense, the same way v13/v16 refuse a
 * cross-ladder diff. The CLI core ({@link computeCoherenceSynchronyArtifacts})
 * enforces this via the v15/v16 ladder guard before calling this.
 *
 * Requires at least two rounds — synchrony is a *between-round* movement; a single
 * round has no transition to count crossings over.
 */
export async function computeCoherenceSynchrony(
  rounds: readonly PostureCoherence[],
): Promise<CoherenceSynchrony> {
  if (rounds.length < 2) {
    throw new Error(`a synchrony needs at least two rounds (got ${rounds.length})`);
  }

  const byDim = rounds.map((c) => new Map(c.dimensions.map((d) => [d.dimension, d])));
  const labels = Array.from(
    new Set(rounds.flatMap((c) => c.dimensions.map((d) => d.dimension))),
  ).sort((a, b) => a.localeCompare(b, "en"));

  // One bucket per round-transition (round k → round k+1, k = 1…N−1). Each front's
  // crossing is attributed to the step into the round that *reveals* the new
  // standing, so the per-transition total re-buckets v24's per-front crossings.
  const crossedByTransition: string[][] = Array.from(
    { length: rounds.length - 1 },
    () => [],
  );

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
        crossedByTransition[i - 1]!.push(dimension);
      }
      prevBelow = isBelow;
    }
  }

  let total_crossings = 0;
  let peak_transition: number | null = null;
  let peak_count = 0;
  let synchronized_count = 0;

  const per_transition: CoherenceSynchronyTransition[] = crossedByTransition.map(
    (dims, idx) => {
      // The labels were iterated in localeCompare order, so `dims` is already
      // pinned; the explicit sort keeps the list deterministic regardless.
      dims.sort((a, b) => a.localeCompare(b, "en"));
      const crossing_fronts = dims.length;
      total_crossings += crossing_fronts;
      if (crossing_fronts >= 2) synchronized_count += 1;
      // The peak step is the one the most fronts crossed at once; the first such
      // step wins a tie (earliest-peak, mirroring v22's earliest-worst-round tiebreak).
      if (crossing_fronts > peak_count) {
        peak_count = crossing_fronts;
        peak_transition = idx + 1;
      }
      const synchrony: SynchronyClass =
        crossing_fronts >= 2 ? "synchronized" : crossing_fronts === 1 ? "isolated" : "quiet";
      return {
        from_round: idx + 1,
        to_round: idx + 2,
        crossing_fronts,
        crossed_dimensions: dims,
        synchrony,
      };
    },
  );

  const synchrony_hash = await sha256Hex(
    stableStringify({
      rounds: rounds.length,
      per_transition: per_transition.map((t) => ({
        from_round: t.from_round,
        to_round: t.to_round,
        crossing_fronts: t.crossing_fronts,
        crossed_dimensions: t.crossed_dimensions,
        synchrony: t.synchrony,
      })),
    }),
  );

  return {
    rounds: rounds.length,
    per_transition,
    total_crossings,
    peak_transition,
    peak_count,
    synchronized_count,
    synchrony_hash,
  };
}

/**
 * Did any single step cross the team's acceptable floor with *two or more* fronts at
 * once — was there a round the package *lurched*? The CI gate predicate — the
 * *co-movement* counterpart to v24's per-front instability gate and v22's
 * deal-breadth gate. Unlike `exposureVolatile` (which fires on any single front
 * crossing the floor ≥ 2 times *across the whole deal*) and `exposureWidened` (which
 * fires on a deal whose below-floor *count* grew first→latest), this fires on a
 * *synchronized* step: two or more fronts crossed the floor *together*, in the same
 * transition. It needs no tuning — two fronts crossing at once *is* a coordinated
 * shift. A consumer wanting a higher simultaneity reads `peak_count` instead.
 */
export function exposureSynchronized(synchrony: CoherenceSynchrony): boolean {
  return synchrony.synchronized_count > 0;
}

/**
 * Serialize a {@link CoherenceSynchrony} to a stable, pretty-printed JSON string.
 * The key order is fixed and the per-transition series is already in sequence order
 * with `localeCompare`-pinned dimension lists, so the same synchrony always yields
 * identical bytes — the `synchrony_hash` it carries is the canonical fingerprint,
 * reproducible from `per_transition`.
 */
export function buildCoherenceSynchronyJson(synchrony: CoherenceSynchrony): string {
  return JSON.stringify(
    {
      schema: "vaulytica.posture-synchrony.v1",
      synchrony_hash: synchrony.synchrony_hash,
      rounds: synchrony.rounds,
      total_crossings: synchrony.total_crossings,
      peak_transition: synchrony.peak_transition,
      peak_count: synchrony.peak_count,
      synchronized_count: synchrony.synchronized_count,
      per_transition: synchrony.per_transition.map((t) => ({
        from_round: t.from_round,
        to_round: t.to_round,
        crossing_fronts: t.crossing_fronts,
        crossed_dimensions: t.crossed_dimensions,
        synchrony: t.synchrony,
      })),
    },
    null,
    2,
  );
}

/**
 * Render a {@link CoherenceSynchrony} as human-readable terminal lines: the peak
 * step (the round the most fronts crossed the floor at once), how many steps were
 * synchronized, then one line per step showing how many fronts crossed and which.
 * Lives beside its JSON sibling so the CLI renders the synchrony from one definition.
 */
export function renderCoherenceSynchronySummary(synchrony: CoherenceSynchrony): string {
  const n = synchrony.rounds;
  const lines = [
    `\nCoherence exposure synchrony across ${n} rounds (fronts crossing the floor per step):`,
    synchrony.peak_transition === null
      ? `  peak step: none — no front ever crossed the floor.`
      : `  peak step: round ${synchrony.peak_transition}→${synchrony.peak_transition + 1} (${synchrony.peak_count} front${synchrony.peak_count === 1 ? "" : "s"} crossed the floor at once).`,
    `  synchronized steps (≥2 fronts crossing at once): ${synchrony.synchronized_count} of ${synchrony.per_transition.length}.`,
  ];
  for (const t of synchrony.per_transition) {
    const dims = t.crossing_fronts === 0 ? "—" : t.crossed_dimensions.join(", ");
    const mark = t.synchrony === "synchronized" ? "⚠" : "·";
    lines.push(
      `  ${mark} round ${t.from_round}→${t.to_round}: ${t.crossing_fronts} front${t.crossing_fronts === 1 ? "" : "s"} crossed (${dims}).`,
    );
  }
  lines.push(`  synchrony_hash: ${synchrony.synchrony_hash}`);
  return lines.join("\n") + "\n";
}
