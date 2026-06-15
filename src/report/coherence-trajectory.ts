/**
 * Cross-document negotiation-posture *trajectory* (spec-v17).
 *
 * This module is the multi-round generalization of {@link compareCoherence}
 * (spec-v13/v16), and it is to that command what v11's trajectory is to v10's
 * snapshot: the signal that only exists when you look at the whole sequence.
 *
 *  - v13 ({@link compareCoherence}) diffs a bundle's coherence at a **base**
 *    round and a **revised** round — one step.
 *  - v17 (here) walks **N** coherences — a bundle at round 1, round 2, …, round
 *    N — and reports, per negotiation front, the binding floor at every round,
 *    each consecutive step, the **net** movement (round 1 → round N), and a
 *    **trajectory**: did the floor climb steadily, slide steadily, or *whipsaw*
 *    (move in both directions — a below-floor dip in the middle that a
 *    first-vs-last diff would hide)?
 *
 * The deal lead's whole-negotiation question that no single pair of rounds
 * answers: *across this entire deal, which fronts are steadily eroding, and
 * which round-tripped through a dip the counterparty walked back?*
 *
 * It adds **no** posture math: it applies the same §3-honest floor classifier
 * v11/v13 use ({@link classifyFloorMovement}, exported from
 * `coherence-movement.ts`) to each consecutive pair, then reduces the per-step
 * classifications to a per-front trajectory. The posture filter (spec-v10 §3),
 * restated:
 *  - **Deterministic** — same N coherences in the same order → identical
 *    `trajectory_hash`, on any machine. Fronts are pinned by
 *    `localeCompare(_, "en")`; the round order is the caller's.
 *  - **Honest about unstated data** — a `newly-stated`/`now-unstated` step is
 *    never counted as improved or regressed (the shared classifier's contract),
 *    so a front that round-trips *through* unstated is `flat`, never `whipsaw`.
 *  - **Advisory** — a trajectory reports where the floor moved on the team's own
 *    ladder across the deal. It asserts no legal conclusion.
 *  - **Additive** — the trajectory carries its own `trajectory_hash`, namespaced
 *    apart from each `coherence_hash` and each `movement_hash`, so computing it
 *    moves no golden.
 */

import type { NegotiationTier } from "../playbooks/custom-interpreter.js";
import { sha256Hex } from "../ingest/hash.js";
import { stableStringify } from "../engine/runner.js";
import { classifyFloorMovement } from "./coherence-movement.js";
import type { PostureMovementKind } from "./posture-movement.js";
import type { PostureCoherence, PostureCoherenceKind } from "./posture-coherence.js";

/**
 * How a front's binding floor moved across the **whole** sequence of rounds.
 *
 *  - `steady-improvement` — at least one step improved and **no** step regressed.
 *  - `steady-regression`  — at least one step regressed and **no** step improved.
 *  - `whipsaw`            — at least one step improved **and** at least one step
 *                           regressed. The floor moved in both directions; this
 *                           is the signal a first-vs-last diff hides (e.g. a dip
 *                           below floor in the middle that recovered by the end).
 *  - `flat`               — no *ranked* movement at any step (only `unchanged`,
 *                           `newly-stated`, or `now-unstated` steps). A front
 *                           that only ever appeared or dropped, never moving
 *                           between two stated rungs, is `flat` — never a false
 *                           whipsaw (§3 honesty).
 */
export type FloorTrajectoryKind =
  | "steady-improvement"
  | "steady-regression"
  | "whipsaw"
  | "flat";

/** How one negotiation front's binding floor moved across N rounds. */
export type CoherenceFrontTrajectory = {
  dimension: string;
  /** The binding floor at each round, in sequence order (`null` = unstated that round). */
  floors: (NegotiationTier | null)[];
  /** The coherence kind at each round (`null` = the front is absent that round — defensive). */
  coherences: (PostureCoherenceKind | null)[];
  /** The consecutive floor movements (length = rounds − 1), in v11/v13 vocabulary. */
  steps: PostureMovementKind[];
  /** The net floor movement: first stated floor vs. last (round 1 → round N). */
  net_floor_movement: PostureMovementKind;
  /** The path classification across the whole sequence. */
  trajectory: FloorTrajectoryKind;
};

export type CoherenceTrajectory = {
  /** How many rounds (coherences) the trajectory spans. */
  rounds: number;
  fronts: CoherenceFrontTrajectory[];
  /** Per-front trajectory tally. */
  trajectory_counts: Record<FloorTrajectoryKind, number>;
  /** Net (round 1 → round N) movement tally, in v11/v13 vocabulary. */
  net_counts: Record<PostureMovementKind, number>;
  /** SHA-256 over the canonical trajectory set — additive, apart from each `coherence_hash`/`movement_hash`. */
  trajectory_hash: string;
};

function emptyTrajectoryCounts(): Record<FloorTrajectoryKind, number> {
  return { "steady-improvement": 0, "steady-regression": 0, whipsaw: 0, flat: 0 };
}

function emptyNetCounts(): Record<PostureMovementKind, number> {
  return {
    improved: 0,
    regressed: 0,
    unchanged: 0,
    "newly-stated": 0,
    "now-unstated": 0,
    appeared: 0,
    disappeared: 0,
  };
}

/**
 * Reduce a front's consecutive floor steps to a {@link FloorTrajectoryKind}.
 * Only `improved`/`regressed` are *ranked* movements; `newly-stated`,
 * `now-unstated`, and `unchanged` are not (the §3 contract), so they do not make
 * a front a whipsaw.
 */
function classifyTrajectory(steps: PostureMovementKind[]): FloorTrajectoryKind {
  let improved = 0;
  let regressed = 0;
  for (const s of steps) {
    if (s === "improved") improved += 1;
    else if (s === "regressed") regressed += 1;
  }
  if (improved > 0 && regressed > 0) return "whipsaw";
  if (regressed > 0) return "steady-regression";
  if (improved > 0) return "steady-improvement";
  return "flat";
}

/**
 * Walk N cross-document posture coherences — the same bundle at round 1, round
 * 2, …, round N — and report, per negotiation front, the binding-floor path
 * across the whole sequence.
 *
 * Pure and deterministic: fronts are matched by dimension and pinned by
 * `localeCompare`, the round order is the caller's, and `trajectory_hash` is
 * over the canonical per-front set, so the same N coherences in the same order
 * always yield identical bytes.
 *
 * Every coherence must have been computed against the **same** team positions
 * (the caller applies one active playbook to every document in every round);
 * comparing floors across different ladders is nonsense, the same way v13/v16
 * refuse a cross-ladder diff. The CLI core ({@link compareCoherenceTrendArtifacts})
 * enforces this via the v15/v16 ladder guard before calling this.
 *
 * Requires at least two rounds — a single coherence has no trajectory.
 */
export async function compareCoherenceTrajectory(
  rounds: readonly PostureCoherence[],
): Promise<CoherenceTrajectory> {
  if (rounds.length < 2) {
    throw new Error(`a trajectory needs at least two rounds (got ${rounds.length})`);
  }

  const byDim = rounds.map((c) => new Map(c.dimensions.map((d) => [d.dimension, d])));
  const labels = Array.from(new Set(rounds.flatMap((c) => c.dimensions.map((d) => d.dimension)))).sort(
    (a, b) => a.localeCompare(b, "en"),
  );

  const trajectory_counts = emptyTrajectoryCounts();
  const net_counts = emptyNetCounts();

  const fronts: CoherenceFrontTrajectory[] = labels.map((dimension) => {
    const floors = byDim.map((m) => m.get(dimension)?.weakest_tier ?? null);
    const coherences = byDim.map((m) => m.get(dimension)?.coherence ?? null);

    const steps: PostureMovementKind[] = [];
    for (let i = 0; i + 1 < floors.length; i++) {
      steps.push(classifyFloorMovement(floors[i]!, floors[i + 1]!));
    }
    const net_floor_movement = classifyFloorMovement(floors[0]!, floors[floors.length - 1]!);
    const trajectory = classifyTrajectory(steps);

    trajectory_counts[trajectory] += 1;
    net_counts[net_floor_movement] += 1;

    return { dimension, floors, coherences, steps, net_floor_movement, trajectory };
  });

  const trajectory_hash = await sha256Hex(
    stableStringify({
      rounds: rounds.length,
      fronts: fronts.map((f) => ({
        dimension: f.dimension,
        floors: f.floors,
        coherences: f.coherences,
        steps: f.steps,
        net_floor_movement: f.net_floor_movement,
        trajectory: f.trajectory,
      })),
    }),
  );

  return { rounds: rounds.length, fronts, trajectory_counts, net_counts, trajectory_hash };
}

/**
 * Did the bundle's binding floor regress at **any step** of the sequence? The CI
 * gate predicate — the faithful multi-round generalization of v13's
 * `coherenceRegressed` (any front whose floor regressed). True when any front is
 * `steady-regression` or `whipsaw`, so a transient below-floor dip trips the gate
 * even when the front recovered by the final round — strictly stronger than a
 * first-vs-last comparison, and deliberately so. A consumer wanting the weaker
 * net-only gate reads `net_counts.regressed` instead.
 */
export function trajectoryRegressed(trajectory: CoherenceTrajectory): boolean {
  return trajectory.trajectory_counts["steady-regression"] + trajectory.trajectory_counts.whipsaw > 0;
}

/**
 * Serialize a {@link CoherenceTrajectory} to a stable, pretty-printed JSON string.
 * The key order is fixed and the front order is already pinned by
 * {@link compareCoherenceTrajectory}, so the same trajectory always yields
 * identical bytes — the `trajectory_hash` it carries is the canonical
 * fingerprint, reproducible from `fronts`.
 */
export function buildCoherenceTrajectoryJson(trajectory: CoherenceTrajectory): string {
  return JSON.stringify(
    {
      schema: "vaulytica.posture-trajectory.v1",
      trajectory_hash: trajectory.trajectory_hash,
      rounds: trajectory.rounds,
      trajectory_counts: trajectory.trajectory_counts,
      net_counts: trajectory.net_counts,
      fronts: trajectory.fronts.map((f) => ({
        dimension: f.dimension,
        floors: f.floors,
        coherences: f.coherences,
        steps: f.steps,
        net_floor_movement: f.net_floor_movement,
        trajectory: f.trajectory,
      })),
    },
    null,
    2,
  );
}

const NET_ARROW: Partial<Record<PostureMovementKind, string>> = {
  improved: "↑ improved",
  regressed: "↓ regressed",
  "newly-stated": "+ newly stated",
  "now-unstated": "− now unstated",
};

/**
 * Render a {@link CoherenceTrajectory} as human-readable terminal lines: the
 * trajectory- and net-count summary, then one line per front that moved
 * (steady-regression, whipsaw, or steady-improvement — a `flat` front is omitted
 * since the summary surfaces only what moved), showing the floor sequence and
 * net direction, and the `trajectory_hash`. Lives beside its JSON sibling so the
 * CLI renders the trajectory from one definition.
 */
export function renderCoherenceTrajectorySummary(trajectory: CoherenceTrajectory): string {
  const tc = trajectory.trajectory_counts;
  const nc = trajectory.net_counts;
  const n = trajectory.rounds;
  const lines = [
    `\nCoherence trajectory across ${n} rounds:`,
    `  floor trajectory: ${tc["steady-improvement"]} steady improvement, ${tc["steady-regression"]} steady regression, ${tc.whipsaw} whipsaw, ${tc.flat} flat.`,
    `  net (round 1 → round ${n}): ${nc.improved} improved, ${nc.regressed} regressed, ${nc["newly-stated"]} newly stated, ${nc["now-unstated"]} now unstated, ${nc.unchanged} unchanged.`,
  ];
  for (const f of trajectory.fronts) {
    if (f.trajectory === "flat") continue;
    const path = f.floors.map((t) => t ?? "—").join(" → ");
    const net = NET_ARROW[f.net_floor_movement] ?? f.net_floor_movement;
    const mark = f.trajectory === "steady-regression" || f.trajectory === "whipsaw" ? "⚠" : "•";
    lines.push(`  ${mark} ${f.dimension}: ${f.trajectory} (${path}); net ${net}.`);
  }
  lines.push(`  trajectory_hash: ${trajectory.trajectory_hash}`);
  return lines.join("\n") + "\n";
}
