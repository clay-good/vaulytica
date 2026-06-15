/**
 * Cross-document negotiation-posture *coherence-shift* trajectory (spec-v18).
 *
 * This is the advisory companion to v17's binding-floor trajectory
 * ({@link compareCoherenceTrajectory}). v17 walks N coherences and reports, per
 * front, how the binding *floor* moved across the whole deal — steady up, steady
 * down, or whipsawed. But v13 always reported a *second* signal beside the
 * floor: did the package **fracture** (a position the documents agreed on now
 * disagrees with itself) or **reconcile** (a divergent front closed up)? v16/v17
 * carried each round's coherence kind in the artifact but classified the
 * trajectory on the floor only; this module classifies the trajectory on that
 * second axis.
 *
 *  - v13 ({@link compareCoherence}) reports the fracture/reconcile *shift* between
 *    a base round and a revised round — one step.
 *  - v18 (here) walks **N** coherences and reports, per negotiation front, the
 *    coherence kind at every round, each consecutive **shift**, the **net** shift
 *    (round 1 → round N), and a **shift trajectory**: did the package fracture
 *    steadily, reconcile steadily, or *oscillate* (split apart and re-merge —
 *    e.g. a front that fractured in round 3 and reconciled by round 5, the signal
 *    a first-vs-last diff would call `unchanged` and hide)?
 *
 * It adds **no** posture math: it applies the same fracture/reconcile classifier
 * v13 uses ({@link classifyShift}, exported from `coherence-movement.ts`) to each
 * consecutive pair, then reduces the per-step shifts to a per-front trajectory —
 * exactly as v17 does for the floor. The posture filter (spec-v10 §3), restated:
 *  - **Deterministic** — same N coherences in the same order → identical
 *    `shift_trajectory_hash`, on any machine. Fronts are pinned by
 *    `localeCompare(_, "en")`; the round order is the caller's.
 *  - **Honest about absent fronts** — a step where the front is absent on either
 *    side (it appeared or dropped that round) is `unchanged`, the same defensive
 *    contract v13 holds; a `realigned` step (the stating set changed without
 *    crossing the divergence line) is never counted as a fracture or a reconcile,
 *    so a front that only ever realigns is `stable`, never a false oscillation.
 *  - **Advisory** — a trajectory reports where the package agreed or split across
 *    the deal. It asserts no legal conclusion.
 *  - **Additive** — the trajectory carries its own `shift_trajectory_hash`,
 *    namespaced apart from each `coherence_hash`, each `movement_hash`, and v17's
 *    `trajectory_hash`, so computing it moves no golden.
 */

import { sha256Hex } from "../ingest/hash.js";
import { stableStringify } from "../engine/runner.js";
import { classifyShift, type CoherenceShift } from "./coherence-movement.js";
import type { PostureCoherence, PostureCoherenceKind } from "./posture-coherence.js";

/**
 * How a front's coherence kind moved across the **whole** sequence of rounds —
 * the fracture/reconcile analog of v17's {@link FloorTrajectoryKind}.
 *
 *  - `steady-fracture`  — at least one step fractured and **no** step reconciled.
 *  - `steady-reconcile` — at least one step reconciled and **no** step fractured.
 *  - `oscillating`      — at least one step fractured **and** at least one step
 *                         reconciled. The package split and re-merged; this is the
 *                         signal a first-vs-last diff hides (e.g. a front that
 *                         fractured in round 3 and reconciled by round 5).
 *  - `stable`           — no *directional* shift at any step (only `realigned` or
 *                         `unchanged` steps). A front whose stating set changed
 *                         without ever crossing the divergence line is `stable` —
 *                         never a false oscillation (§3 honesty).
 */
export type CoherenceShiftTrajectoryKind =
  | "steady-fracture"
  | "steady-reconcile"
  | "oscillating"
  | "stable";

/** How one negotiation front's coherence kind moved across N rounds. */
export type CoherenceShiftFrontTrajectory = {
  dimension: string;
  /** The coherence kind at each round, in sequence order (`null` = the front is absent that round). */
  coherences: (PostureCoherenceKind | null)[];
  /** The consecutive coherence-kind shifts (length = rounds − 1), in v13 vocabulary. */
  shifts: CoherenceShift[];
  /** The net shift: first round's kind vs. last (round 1 → round N). */
  net_shift: CoherenceShift;
  /** The path classification across the whole sequence. */
  shift_trajectory: CoherenceShiftTrajectoryKind;
};

export type CoherenceShiftTrajectory = {
  /** How many rounds (coherences) the trajectory spans. */
  rounds: number;
  fronts: CoherenceShiftFrontTrajectory[];
  /** Per-front shift-trajectory tally. */
  shift_trajectory_counts: Record<CoherenceShiftTrajectoryKind, number>;
  /** Net (round 1 → round N) shift tally, in v13 vocabulary. */
  net_shift_counts: Record<CoherenceShift, number>;
  /** SHA-256 over the canonical trajectory set — additive, apart from every `coherence_hash`/`movement_hash`/`trajectory_hash`. */
  shift_trajectory_hash: string;
};

function emptyShiftTrajectoryCounts(): Record<CoherenceShiftTrajectoryKind, number> {
  return { "steady-fracture": 0, "steady-reconcile": 0, oscillating: 0, stable: 0 };
}

function emptyNetShiftCounts(): Record<CoherenceShift, number> {
  return { fractured: 0, reconciled: 0, realigned: 0, unchanged: 0 };
}

/**
 * Classify the coherence-kind shift between two rounds, tolerating an absent
 * front on either side (`null` = no document stated the dimension that round).
 * An appear/disappear step carries no fracture/reconcile signal — the same
 * defensive contract v13's {@link compareCoherence} holds when a front is missing
 * on a side — so it classifies as `unchanged`. Both sides present → the shared
 * v13 classifier.
 */
function classifyShiftStep(
  base: PostureCoherenceKind | null,
  revised: PostureCoherenceKind | null,
): CoherenceShift {
  if (base === null || revised === null) return "unchanged";
  return classifyShift(base, revised);
}

/**
 * Reduce a front's consecutive coherence-kind shifts to a
 * {@link CoherenceShiftTrajectoryKind}. Only `fractured`/`reconciled` are
 * *directional* shifts; `realigned` and `unchanged` are not (§3), so they do not
 * make a front oscillate.
 */
function classifyShiftTrajectory(shifts: CoherenceShift[]): CoherenceShiftTrajectoryKind {
  let fractured = 0;
  let reconciled = 0;
  for (const s of shifts) {
    if (s === "fractured") fractured += 1;
    else if (s === "reconciled") reconciled += 1;
  }
  if (fractured > 0 && reconciled > 0) return "oscillating";
  if (fractured > 0) return "steady-fracture";
  if (reconciled > 0) return "steady-reconcile";
  return "stable";
}

/**
 * Walk N cross-document posture coherences — the same bundle at round 1, round
 * 2, …, round N — and report, per negotiation front, the fracture/reconcile path
 * across the whole sequence.
 *
 * Pure and deterministic: fronts are matched by dimension and pinned by
 * `localeCompare`, the round order is the caller's, and `shift_trajectory_hash`
 * is over the canonical per-front set, so the same N coherences in the same order
 * always yield identical bytes.
 *
 * Every coherence must have been computed against the **same** team positions
 * (the caller applies one active playbook to every document in every round); the
 * CLI core enforces this via the v15/v16 ladder guard before calling this, the
 * same way v17 does.
 *
 * Requires at least two rounds — a single coherence has no trajectory.
 */
export async function compareCoherenceShiftTrajectory(
  rounds: readonly PostureCoherence[],
): Promise<CoherenceShiftTrajectory> {
  if (rounds.length < 2) {
    throw new Error(`a trajectory needs at least two rounds (got ${rounds.length})`);
  }

  const byDim = rounds.map((c) => new Map(c.dimensions.map((d) => [d.dimension, d])));
  const labels = Array.from(new Set(rounds.flatMap((c) => c.dimensions.map((d) => d.dimension)))).sort(
    (a, b) => a.localeCompare(b, "en"),
  );

  const shift_trajectory_counts = emptyShiftTrajectoryCounts();
  const net_shift_counts = emptyNetShiftCounts();

  const fronts: CoherenceShiftFrontTrajectory[] = labels.map((dimension) => {
    const coherences = byDim.map((m) => m.get(dimension)?.coherence ?? null);

    const shifts: CoherenceShift[] = [];
    for (let i = 0; i + 1 < coherences.length; i++) {
      shifts.push(classifyShiftStep(coherences[i]!, coherences[i + 1]!));
    }
    const net_shift = classifyShiftStep(coherences[0]!, coherences[coherences.length - 1]!);
    const shift_trajectory = classifyShiftTrajectory(shifts);

    shift_trajectory_counts[shift_trajectory] += 1;
    net_shift_counts[net_shift] += 1;

    return { dimension, coherences, shifts, net_shift, shift_trajectory };
  });

  const shift_trajectory_hash = await sha256Hex(
    stableStringify({
      rounds: rounds.length,
      fronts: fronts.map((f) => ({
        dimension: f.dimension,
        coherences: f.coherences,
        shifts: f.shifts,
        net_shift: f.net_shift,
        shift_trajectory: f.shift_trajectory,
      })),
    }),
  );

  return { rounds: rounds.length, fronts, shift_trajectory_counts, net_shift_counts, shift_trajectory_hash };
}

/**
 * Did the package's coherence **fracture** at **any step** of the sequence? The
 * CI gate predicate — the multi-round generalization of "a front fractured" from
 * one step to the whole deal. True when any front is `steady-fracture` or
 * `oscillating`, so a transient split trips the gate even when the front
 * reconciled by the final round — strictly stronger than a first-vs-last
 * comparison, and deliberately so (the fracture/reconcile companion to v17's
 * any-step floor gate). A consumer wanting the weaker net-only gate reads
 * `net_shift_counts.fractured` instead.
 */
export function shiftTrajectoryFractured(trajectory: CoherenceShiftTrajectory): boolean {
  return (
    trajectory.shift_trajectory_counts["steady-fracture"] +
      trajectory.shift_trajectory_counts.oscillating >
    0
  );
}

/**
 * Serialize a {@link CoherenceShiftTrajectory} to a stable, pretty-printed JSON
 * string. The key order is fixed and the front order is already pinned by
 * {@link compareCoherenceShiftTrajectory}, so the same trajectory always yields
 * identical bytes — the `shift_trajectory_hash` it carries is the canonical
 * fingerprint, reproducible from `fronts`.
 */
export function buildCoherenceShiftTrajectoryJson(trajectory: CoherenceShiftTrajectory): string {
  return JSON.stringify(
    {
      schema: "vaulytica.posture-shift-trajectory.v1",
      shift_trajectory_hash: trajectory.shift_trajectory_hash,
      rounds: trajectory.rounds,
      shift_trajectory_counts: trajectory.shift_trajectory_counts,
      net_shift_counts: trajectory.net_shift_counts,
      fronts: trajectory.fronts.map((f) => ({
        dimension: f.dimension,
        coherences: f.coherences,
        shifts: f.shifts,
        net_shift: f.net_shift,
        shift_trajectory: f.shift_trajectory,
      })),
    },
    null,
    2,
  );
}

const NET_MARK: Partial<Record<CoherenceShift, string>> = {
  fractured: "⤬ fractured",
  reconciled: "⤝ reconciled",
  realigned: "↔ realigned",
};

/**
 * Render a {@link CoherenceShiftTrajectory} as human-readable terminal lines: the
 * shift-trajectory and net-shift summary, then one line per front that moved on
 * this axis (steady-fracture, oscillating, or steady-reconcile — a `stable` front
 * is omitted since the summary surfaces only what moved), showing the coherence
 * sequence and net direction, and the `shift_trajectory_hash`. Lives beside its
 * JSON sibling so the CLI renders the trajectory from one definition.
 */
export function renderCoherenceShiftTrajectorySummary(trajectory: CoherenceShiftTrajectory): string {
  const tc = trajectory.shift_trajectory_counts;
  const nc = trajectory.net_shift_counts;
  const n = trajectory.rounds;
  const lines = [
    `\nCoherence-shift trajectory across ${n} rounds:`,
    `  shift trajectory: ${tc["steady-fracture"]} steady fracture, ${tc["steady-reconcile"]} steady reconcile, ${tc.oscillating} oscillating, ${tc.stable} stable.`,
    `  net (round 1 → round ${n}): ${nc.fractured} fractured, ${nc.reconciled} reconciled, ${nc.realigned} realigned, ${nc.unchanged} unchanged.`,
  ];
  for (const f of trajectory.fronts) {
    if (f.shift_trajectory === "stable") continue;
    const path = f.coherences.map((c) => c ?? "—").join(" → ");
    const net = NET_MARK[f.net_shift] ?? f.net_shift;
    const mark = f.shift_trajectory === "steady-fracture" || f.shift_trajectory === "oscillating" ? "⚠" : "•";
    lines.push(`  ${mark} ${f.dimension}: ${f.shift_trajectory} (${path}); net ${net}.`);
  }
  lines.push(`  shift_trajectory_hash: ${trajectory.shift_trajectory_hash}`);
  return lines.join("\n") + "\n";
}
