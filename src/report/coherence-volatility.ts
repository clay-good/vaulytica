/**
 * Cross-document negotiation-posture **exposure volatility** — the per-front count
 * of times a front's binding floor *crossed* the acceptable floor boundary across
 * the whole deal, recoveries included (spec-v24).
 *
 * v23 ({@link computeCoherenceRecurrence}) reads the posture archive on the
 * **episode-count** axis: per front, how many *separate* times it fell below the
 * acceptable floor (`below_runs`). But `below_runs` counts only the **entries** into
 * below-floor — it is blind to the **recoveries** between them. A front whose
 * binding floor reads `acceptable → below → acceptable` (it fell once and cleanly
 * recovered, never relapsing) reports `below_runs = 1`, `recurrence = single`, and
 * does **not** trip v23's churn gate — identical, to v23, to a front that reads
 * `below → below → below` (also one episode), which never moved at all. Yet the
 * first front *crossed the floor twice* (down, then up) and the second *never
 * crossed it*. v23 cannot see the difference, because it counts below-floor runs and
 * discards the recoveries that bound them; v21 calls the first `resolved` and the
 * second `open` (the current standing, not the movement); v20 calls both `exposed`;
 * v17 nets the first `unchanged`.
 *
 * This module is the orthogonal **crossing-count** axis the episode count throws
 * away:
 *
 *  - v17 answers *which way did the floor move* — up, down, or whipsaw.
 *  - v20 answers *how low did the floor ever get* — the worst rung reached.
 *  - v21 answers *how long was it below floor, and is it still below floor now*.
 *  - v23 answers *how many separate times did it fall below floor* — the count of
 *    below-floor episodes (entries only, recoveries discarded).
 *  - v24 (here) answers *how many times did its standing flip across the floor* —
 *    the count of floor-boundary **crossings** in both directions (falls **and**
 *    recoveries): zero is `stable` (it stayed on one side the whole deal), one is
 *    `monotone` (it crossed once, never back), two or more is `volatile` (its
 *    standing reversed across the floor at least once — gate trips).
 *
 * It adds **no** posture math beyond a scan for transitions across the
 * `below-acceptable` rung v10 defines, over the binding floors v12 derived and
 * v21/v23 already read. The posture filter (spec-v10 §3), restated:
 *  - **Deterministic** — same N coherences in the same order → identical
 *    `volatility_hash`, on any machine. Fronts are pinned by `localeCompare(_,
 *    "en")` (the same order the trajectory/exposure/persistence/recurrence functions
 *    use); the round order is the caller's.
 *  - **Honest about unstated data** — a front no document states in *any* round is
 *    `unstated`, never `volatile`/`monotone`/`stable`. Within a front's path, an
 *    unstated round is skipped: it neither counts as a crossing nor resets the
 *    standing (silence is not a fall or a recovery — the §3 contract that keeps
 *    `unstated` never-flagged in v20 and `below → unstated → below` one episode in
 *    v23). A crossing is counted only between two *stated* rounds on opposite sides
 *    of the floor.
 *  - **Advisory** — the report names how many times each front's standing crossed
 *    the team's own floor. It asserts no legal conclusion.
 *  - **Additive** — the volatility carries its own `volatility_hash`, namespaced
 *    apart from every `coherence_hash`, `movement_hash`, `trajectory_hash`,
 *    `shift_trajectory_hash`, `arc_hash`, `exposure_hash`, `persistence_hash`,
 *    `breadth_hash`, and `recurrence_hash`, so computing it moves no golden.
 */

import type { NegotiationTier } from "../playbooks/custom-interpreter.js";
import { sha256Hex } from "../ingest/hash.js";
import { stableStringify } from "../engine/runner.js";
import type { PostureCoherence } from "./posture-coherence.js";

/** The team's acceptable floor — the one rung whose name means "below what we will accept." */
const BELOW_FLOOR: NegotiationTier = "below-acceptable";

/**
 * A front's floor-crossing class:
 *  - `volatile` — its standing crossed the floor in **two or more** transitions (it
 *    both fell across and rose across — its standing reversed at least once);
 *  - `monotone` — it crossed the floor in exactly one transition (a single fall, or
 *    a single recovery, never reversed);
 *  - `stable` — stated, but never crossed the floor (it stayed on one side the whole
 *    deal: always below, or always at-or-above);
 *  - `unstated` — no document ever stated the front (§3: silence is not exposure).
 */
export type VolatilityClass = "volatile" | "monotone" | "stable" | "unstated";

/** One negotiation front's whole-sequence floor-crossing structure. */
export type CoherenceVolatilityFront = {
  dimension: string;
  /** The binding floor at each round, in sequence order (`null` = unstated that round). */
  floors: (NegotiationTier | null)[];
  /** How many rounds stated a `below-acceptable` binding floor (for context). */
  rounds_below: number;
  /** How many times the front's standing crossed the floor boundary, both directions (the verdict). */
  crossings: number;
  /** The floor-crossing class. */
  volatility: VolatilityClass;
};

export type CoherenceVolatility = {
  /** How many rounds (coherences) the volatility spans. */
  rounds: number;
  fronts: CoherenceVolatilityFront[];
  /** Per-front tally by volatility class. */
  class_counts: Record<VolatilityClass, number>;
  /** How many fronts crossed the floor two or more times (the gate-worthy count). */
  volatile_count: number;
  /** The front with the most floor crossings (earliest on a tie; `null` when none ever crossed). */
  most_volatile_dimension: string | null;
  /** The crossing count at {@link most_volatile_dimension} (0 when no front ever crossed the floor). */
  max_crossings: number;
  /** SHA-256 over the canonical volatility set — additive, apart from every other hash. */
  volatility_hash: string;
};

function emptyClassCounts(): Record<VolatilityClass, number> {
  return { volatile: 0, monotone: 0, stable: 0, unstated: 0 };
}

/**
 * Scan one front's binding-floor path and count its floor crossings. A crossing is a
 * transition between two *stated* rounds on opposite sides of the floor — one
 * `below-acceptable`, the other at-or-above it — in either direction. An unstated
 * round (`null`) is skipped: it neither counts as a crossing nor resets the standing
 * (silence is not a fall or a recovery, §3), so `below → null → below` is zero
 * crossings and `below → null → acceptable` is one. Returns the crossing count and
 * whether any round was ever stated.
 */
function scanCrossings(floors: (NegotiationTier | null)[]): {
  crossings: number;
  stated: boolean;
} {
  let crossings = 0;
  let stated = false;
  let prevBelow: boolean | null = null; // the last *stated* round's below-floor state

  for (const t of floors) {
    if (t === null) continue; // silence: neither crosses nor resets the standing (§3)
    stated = true;
    const isBelow = t === BELOW_FLOOR;
    if (prevBelow !== null && prevBelow !== isBelow) crossings += 1;
    prevBelow = isBelow;
  }

  return { crossings, stated };
}

/**
 * Walk N cross-document posture coherences — the same bundle at round 1, round
 * 2, …, round N — and report, per negotiation front, how many times its binding
 * floor *crossed* the acceptable floor boundary (falls and recoveries alike), not
 * merely how many times it fell below it (v23's episode count) or how many rounds it
 * was down (v21's sum).
 *
 * Pure and deterministic: fronts are matched by dimension and pinned by
 * `localeCompare`, the round order is the caller's, and `volatility_hash` is over
 * the canonical per-front set, so the same N coherences in the same order always
 * yield identical bytes.
 *
 * Every coherence must have been computed against the **same** team positions (the
 * caller applies one active playbook to every document in every round); comparing
 * floors across different ladders is nonsense, the same way v13/v16 refuse a
 * cross-ladder diff. The CLI core ({@link computeCoherenceVolatilityArtifacts})
 * enforces this via the v15/v16 ladder guard before calling this.
 *
 * Requires at least two rounds — volatility is the *whole-deal* crossing structure;
 * a single round's floor is exactly what `analyze --posture` already reports.
 */
export async function computeCoherenceVolatility(
  rounds: readonly PostureCoherence[],
): Promise<CoherenceVolatility> {
  if (rounds.length < 2) {
    throw new Error(`a volatility needs at least two rounds (got ${rounds.length})`);
  }

  const byDim = rounds.map((c) => new Map(c.dimensions.map((d) => [d.dimension, d])));
  const labels = Array.from(
    new Set(rounds.flatMap((c) => c.dimensions.map((d) => d.dimension))),
  ).sort((a, b) => a.localeCompare(b, "en"));

  const class_counts = emptyClassCounts();
  let volatile_count = 0;
  let most_volatile_dimension: string | null = null;
  let max_crossings = 0;

  const fronts: CoherenceVolatilityFront[] = labels.map((dimension) => {
    const floors = byDim.map((m) => m.get(dimension)?.weakest_tier ?? null);
    const { crossings, stated } = scanCrossings(floors);
    const rounds_below = floors.filter((t) => t === BELOW_FLOOR).length;

    const volatility: VolatilityClass = !stated
      ? "unstated"
      : crossings >= 2
        ? "volatile"
        : crossings === 1
          ? "monotone"
          : "stable";

    if (volatility === "volatile") volatile_count += 1;
    class_counts[volatility] += 1;
    // The most volatile front is the one with the most crossings; the first such
    // front wins a tie (labels are already localeCompare-sorted, so > keeps the earliest).
    if (crossings > max_crossings) {
      max_crossings = crossings;
      most_volatile_dimension = dimension;
    }

    return { dimension, floors, rounds_below, crossings, volatility };
  });

  const volatility_hash = await sha256Hex(
    stableStringify({
      rounds: rounds.length,
      fronts: fronts.map((f) => ({
        dimension: f.dimension,
        floors: f.floors,
        rounds_below: f.rounds_below,
        crossings: f.crossings,
        volatility: f.volatility,
      })),
    }),
  );

  return {
    rounds: rounds.length,
    fronts,
    class_counts,
    volatile_count,
    most_volatile_dimension,
    max_crossings,
    volatility_hash,
  };
}

/**
 * Did any front's standing cross the team's acceptable floor *two or more* times —
 * did it both fall across and rise across, reversing at least once? The CI gate
 * predicate — the *instability* counterpart to v23's churn gate and v21's
 * current-standing gate. Unlike `exposureBreached` (any front ever below floor),
 * `exposureOpen` (any front still below floor now), and `exposureRecurred` (any
 * front below floor in ≥ 2 episodes), this fires on a front whose standing reversed
 * across the floor — counting recoveries, so a front that fell once and *cleanly
 * recovered* (two crossings, a single episode to v23) trips it, while a front that
 * fell once and *stayed down* (zero crossings) does not. It needs no tuning — two
 * crossings is the threshold that *means* the standing reversed. A consumer wanting
 * a higher crossing count reads `max_crossings` instead.
 */
export function exposureVolatile(volatility: CoherenceVolatility): boolean {
  return volatility.volatile_count > 0;
}

/**
 * Serialize a {@link CoherenceVolatility} to a stable, pretty-printed JSON string.
 * The key order is fixed and the front order is already pinned by
 * {@link computeCoherenceVolatility}, so the same volatility always yields identical
 * bytes — the `volatility_hash` it carries is the canonical fingerprint,
 * reproducible from `fronts`.
 */
export function buildCoherenceVolatilityJson(volatility: CoherenceVolatility): string {
  return JSON.stringify(
    {
      schema: "vaulytica.posture-volatility.v1",
      volatility_hash: volatility.volatility_hash,
      rounds: volatility.rounds,
      class_counts: volatility.class_counts,
      volatile_count: volatility.volatile_count,
      most_volatile_dimension: volatility.most_volatile_dimension,
      max_crossings: volatility.max_crossings,
      fronts: volatility.fronts.map((f) => ({
        dimension: f.dimension,
        floors: f.floors,
        rounds_below: f.rounds_below,
        crossings: f.crossings,
        volatility: f.volatility,
      })),
    },
    null,
    2,
  );
}

/**
 * Render a {@link CoherenceVolatility} as human-readable terminal lines: the class
 * tally and the volatile-front count, then one line per **volatile** front (showing
 * its crossing count and the floor path), then one line per **monotone** front (one
 * crossing — it moved across the floor once, never back). A `stable` or `unstated`
 * front is counted but never listed (§3 honesty). Lives beside its JSON sibling so
 * the CLI renders the volatility from one definition.
 */
export function renderCoherenceVolatilitySummary(volatility: CoherenceVolatility): string {
  const cc = volatility.class_counts;
  const n = volatility.rounds;
  const lines = [
    `\nCoherence exposure volatility across ${n} rounds (floor crossings per front):`,
    `  ${cc.volatile} volatile (standing reversed across floor), ${cc.monotone} monotone (one crossing), ${cc.stable} stable (never crossed), ${cc.unstated} never stated.`,
    `  volatile fronts (standing crossed the floor ≥2 times): ${volatility.volatile_count}.`,
  ];
  for (const f of volatility.fronts) {
    if (f.volatility !== "volatile") continue;
    const path = f.floors.map((t) => t ?? "—").join(" → ");
    lines.push(
      `  ⚠ ${f.dimension}: volatile — its standing crossed the floor ${f.crossings} times (${path}).`,
    );
  }
  for (const f of volatility.fronts) {
    if (f.volatility !== "monotone") continue;
    const path = f.floors.map((t) => t ?? "—").join(" → ");
    lines.push(`  · ${f.dimension}: monotone — crossed the floor once (${path}).`);
  }
  lines.push(`  volatility_hash: ${volatility.volatility_hash}`);
  return lines.join("\n") + "\n";
}
