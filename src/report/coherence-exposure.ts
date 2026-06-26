/**
 * Cross-document negotiation-posture **exposure** — the whole-deal binding-floor
 * *low-water mark* (spec-v20).
 *
 * Every posture command from v10 to v19 reports **movement** — how a rung, a
 * binding floor, or a coherence kind *changed* between rounds. v17 walks N
 * coherences on the floor axis ({@link compareCoherenceTrajectory}); v18 walks
 * the same N on the agreement axis ({@link compareCoherenceShiftTrajectory}); v19
 * joins both ({@link compareCoherenceArc}). But all three classify *change*, and a
 * change-only view has one blind spot: a front that sat at `below-acceptable` in
 * **every** round never *moved*, so v17 calls it `flat`, v18 calls it `stable`,
 * and every trend/arc summary omits it and every movement gate waves it through —
 * the floor only "regresses" when it changes to a *worse* rung, and a floor that
 * was always below the team's acceptable minimum never changed. Yet it is the
 * single most exposed front in the deal.
 *
 * This module is the orthogonal **level** axis the movement family never read:
 *
 *  - v17 answers *which way did the floor move* — up, down, or whipsaw.
 *  - v20 (here) answers *how low did the floor ever get* — the worst binding floor
 *    each front reached at any round across the whole deal (its low-water mark),
 *    which round it first reached it, and whether that worst rung is **below the
 *    team's acceptable floor**. A front pinned below floor for all N rounds is
 *    `flat`/`stable` to the movement family but **exposed** here.
 *
 * It adds **no** posture math beyond a minimum over the same `TIER_RANK` v11/v13
 * use: it reads each round's binding floor (the same `weakest_tier` v12 derived,
 * carried verbatim in the artifact) and takes the worst rung per front. The
 * posture filter (spec-v10 §3), restated:
 *  - **Deterministic** — same N coherences in the same order → identical
 *    `exposure_hash`, on any machine. Fronts are pinned by `localeCompare(_,
 *    "en")` (the same order the trajectory functions use); the round order is the
 *    caller's.
 *  - **Honest about unstated data** — a front no document states in *any* round
 *    has a `null` worst floor and is reported as `unstated`, never as exposed:
 *    "not stated" is not a point on the ideal→floor axis, so silence is never a
 *    false exposure (the §3 contract that makes `newly-stated`/`now-unstated`
 *    unranked in v11/v13). Only a *stated* floor of `below-acceptable` is
 *    exposure.
 *  - **Advisory** — the report names the worst rung each front reached on the
 *    team's own ladder across the deal. It asserts no legal conclusion.
 *  - **Additive** — the exposure carries its own `exposure_hash`, namespaced apart
 *    from every `coherence_hash`, `movement_hash`, `trajectory_hash`,
 *    `shift_trajectory_hash`, and `arc_hash`, so computing it moves no golden.
 */

import type { NegotiationTier } from "../playbooks/custom-interpreter.js";
import { sha256Hex } from "../ingest/hash.js";
import { stableStringify } from "../engine/runner.js";
import { TIER_RANK } from "./posture-movement.js";
import type { PostureCoherence } from "./posture-coherence.js";

/**
 * The worst binding-floor level a front reached across the whole sequence — a
 * stated rung, or `unstated` when no document ever stated the front. (A binding
 * floor is always a *stated*, ranked rung — v12 excludes `unevaluable` from the
 * floor — so the worst floor is one of `ideal` / `acceptable` / `below-acceptable`
 * or, when never stated, `unstated`.)
 */
export type ExposureLevel = "ideal" | "acceptable" | "below-acceptable" | "unstated";

/** One negotiation front's whole-sequence binding-floor low-water mark. */
export type CoherenceExposureFront = {
  dimension: string;
  /** The binding floor at each round, in sequence order (`null` = unstated that round). */
  floors: (NegotiationTier | null)[];
  /** The lowest-ranked binding floor across all rounds (`null` = never stated in any round). */
  worst_floor: NegotiationTier | null;
  /** The 1-based round index where the floor first reached {@link worst_floor} (`null` when never stated). */
  worst_round: number | null;
  /** How many rounds stated this front (a non-`null` binding floor). */
  rounds_stated: number;
  /** True iff {@link worst_floor} is below the team's acceptable floor (`below-acceptable`). */
  exposed: boolean;
};

export type CoherenceExposure = {
  /** How many rounds (coherences) the exposure spans. */
  rounds: number;
  fronts: CoherenceExposureFront[];
  /** Per-front tally by the worst level reached across the deal. */
  worst_counts: Record<ExposureLevel, number>;
  /** How many fronts ever fell below the acceptable floor (the gate-worthy count). */
  exposed_count: number;
  /** SHA-256 over the canonical exposure set — additive, apart from every other hash. */
  exposure_hash: string;
};

function emptyWorstCounts(): Record<ExposureLevel, number> {
  return { ideal: 0, acceptable: 0, "below-acceptable": 0, unstated: 0 };
}

/**
 * Walk N cross-document posture coherences — the same bundle at round 1, round
 * 2, …, round N — and report, per negotiation front, the *worst* binding floor it
 * reached across the whole sequence (its low-water mark).
 *
 * Pure and deterministic: fronts are matched by dimension and pinned by
 * `localeCompare`, the round order is the caller's, and `exposure_hash` is over
 * the canonical per-front set, so the same N coherences in the same order always
 * yield identical bytes.
 *
 * Every coherence must have been computed against the **same** team positions
 * (the caller applies one active playbook to every document in every round);
 * comparing floors across different ladders is nonsense, the same way v13/v16
 * refuse a cross-ladder diff. The CLI core
 * ({@link compareCoherenceExposureArtifacts}) enforces this via the v15/v16
 * ladder guard before calling this.
 *
 * Requires at least two rounds — exposure is the *whole-deal* low-water mark; a
 * single round's floors are exactly what `analyze --posture` already reports.
 */
export async function compareCoherenceExposure(
  rounds: readonly PostureCoherence[],
): Promise<CoherenceExposure> {
  if (rounds.length < 2) {
    throw new Error(`an exposure needs at least two rounds (got ${rounds.length})`);
  }

  const byDim = rounds.map((c) => new Map(c.dimensions.map((d) => [d.dimension, d])));
  const labels = Array.from(
    new Set(rounds.flatMap((c) => c.dimensions.map((d) => d.dimension))),
  ).sort((a, b) => a.localeCompare(b, "en"));

  const worst_counts = emptyWorstCounts();
  let exposed_count = 0;

  const fronts: CoherenceExposureFront[] = labels.map((dimension) => {
    const floors = byDim.map((m) => m.get(dimension)?.weakest_tier ?? null);

    // The worst floor is the lowest-ranked *stated* rung across all rounds.
    // `TIER_RANK` is injective over the three ranked rungs, so the minimum rank
    // maps to a unique tier; the first round to hit it is the earliest exposure.
    let worst_floor: NegotiationTier | null = null;
    let worst_round: number | null = null;
    let rounds_stated = 0;
    floors.forEach((t, i) => {
      if (t === null) return;
      rounds_stated += 1;
      const rank = TIER_RANK[t] as number;
      if (worst_floor === null || rank < (TIER_RANK[worst_floor] as number)) {
        worst_floor = t;
        worst_round = i + 1;
      }
    });

    const exposed = worst_floor === "below-acceptable";
    if (exposed) exposed_count += 1;
    worst_counts[(worst_floor ?? "unstated") as ExposureLevel] += 1;

    return { dimension, floors, worst_floor, worst_round, rounds_stated, exposed };
  });

  const exposure_hash = await sha256Hex(
    stableStringify({
      rounds: rounds.length,
      fronts: fronts.map((f) => ({
        dimension: f.dimension,
        floors: f.floors,
        worst_floor: f.worst_floor,
        worst_round: f.worst_round,
        rounds_stated: f.rounds_stated,
        exposed: f.exposed,
      })),
    }),
  );

  return { rounds: rounds.length, fronts, worst_counts, exposed_count, exposure_hash };
}

/**
 * Did any front ever fall below the team's acceptable floor at any round? The CI
 * gate predicate — the *level* counterpart to v17's movement gate. Unlike
 * `trajectoryRegressed` (which fires only on a floor that *changed* to a worse
 * rung), this fires on a floor that *sat* below acceptable in any round, so a
 * front pinned at `below-acceptable` for the whole deal — invisible to every
 * movement command — trips it. A consumer wanting the worse-than-ideal level
 * reads `worst_counts` instead.
 */
export function exposureBreached(exposure: CoherenceExposure): boolean {
  return exposure.exposed_count > 0;
}

/**
 * Serialize a {@link CoherenceExposure} to a stable, pretty-printed JSON string.
 * The key order is fixed and the front order is already pinned by
 * {@link compareCoherenceExposure}, so the same exposure always yields identical
 * bytes — the `exposure_hash` it carries is the canonical fingerprint,
 * reproducible from `fronts`.
 */
export function buildCoherenceExposureJson(exposure: CoherenceExposure): string {
  return JSON.stringify(
    {
      schema: "vaulytica.posture-exposure.v1",
      exposure_hash: exposure.exposure_hash,
      rounds: exposure.rounds,
      worst_counts: exposure.worst_counts,
      exposed_count: exposure.exposed_count,
      fronts: exposure.fronts.map((f) => ({
        dimension: f.dimension,
        floors: f.floors,
        worst_floor: f.worst_floor,
        worst_round: f.worst_round,
        rounds_stated: f.rounds_stated,
        exposed: f.exposed,
      })),
    },
    null,
    2,
  );
}

/**
 * Render a {@link CoherenceExposure} as human-readable terminal lines: the
 * worst-level tally and the exposed-front count, then one line per **exposed**
 * front (worst floor `below-acceptable` — the summary surfaces only the fronts
 * that breached the team's floor; an `unstated` front is counted but never flagged,
 * per §3 honesty), showing the floor path and when the floor first fell below
 * acceptable, and the `exposure_hash`. Lives beside its JSON sibling so the CLI
 * renders the exposure from one definition.
 */
export function renderCoherenceExposureSummary(exposure: CoherenceExposure): string {
  const wc = exposure.worst_counts;
  const n = exposure.rounds;
  const lines = [
    `\nCoherence exposure across ${n} rounds (worst binding floor):`,
    `  worst floor reached: ${wc.ideal} ideal, ${wc.acceptable} acceptable, ${wc["below-acceptable"]} below floor, ${wc.unstated} never stated.`,
    `  exposed fronts (ever below floor): ${exposure.exposed_count}.`,
  ];
  for (const f of exposure.fronts) {
    if (!f.exposed) continue;
    const path = f.floors.map((t) => t ?? "—").join(" → ");
    lines.push(`  ⚠ ${f.dimension}: worst below floor, first at round ${f.worst_round} (${path}).`);
  }
  lines.push(`  exposure_hash: ${exposure.exposure_hash}`);
  return lines.join("\n") + "\n";
}
