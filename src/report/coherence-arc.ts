/**
 * Cross-document negotiation-posture combined **arc** (spec-v19).
 *
 * v13 ({@link compareCoherence}) reports, per negotiation front, *both* axes of a
 * two-round move: how the binding **floor** shifted (the exposure axis) and
 * whether the package **fractured** or **reconciled** (the agreement axis). v16
 * carried both for two saved artifacts (`compare-coherence`); v17 walked N
 * artifacts on the floor axis alone ({@link compareCoherenceTrajectory},
 * `coherence-trend`); v18 walked the same N on the agreement axis alone
 * ({@link compareCoherenceShiftTrajectory}, `coherence-shift-trend`). This module
 * is the last open cell of that matrix: the v13 per-front *combined* view,
 * generalized to **N** rounds and read from the archive alone.
 *
 *  - v17 answers *how exposed am I, across the deal* — did the floor erode,
 *    climb, or whipsaw through a below-floor dip?
 *  - v18 answers *does my package agree with itself, across the deal* — did a
 *    front fracture, reconcile, or oscillate through a split it walked back?
 *  - v19 (here) answers **both at once, joined per front** — and gives one
 *    deal-level gate that trips when *either* the floor regressed *or* the
 *    package fractured at some step. A bundle can hold its floor steady while
 *    quietly fracturing, or fracture and hold its floor; the arc is the single
 *    object that surfaces both without the consumer re-joining two JSON files
 *    (and getting the combined gate subtly wrong).
 *
 * It adds **no** posture math and re-derives nothing: it runs the two existing
 * pure trajectory functions on the same rounds and joins their per-front results
 * positionally on `dimension` — both pin fronts with the same `localeCompare`
 * over the same union of dimensions, so the two `fronts` arrays are identical in
 * order and length (v18 Part XVII open question #2: *"both are pinned in the same
 * front order, so the join is positional"*). The posture filter (spec-v10 §3),
 * restated:
 *  - **Deterministic** — same N coherences in the same order → identical
 *    `arc_hash`, on any machine. The arc carries the two component fingerprints
 *    verbatim (`trajectory_hash`, `shift_trajectory_hash`) and an `arc_hash`
 *    derived purely from that pair, so a combined report is reproducible from —
 *    and cross-checkable against — the two single-axis commands' output.
 *  - **Honest about absent fronts** — every absent-side defense from v17/v18
 *    flows through unchanged: a `newly-stated`/`now-unstated` step is never a
 *    floor regression, an appear/disappear or realign-only step is never a
 *    fracture, so neither axis invents movement that is not there.
 *  - **Advisory** — the arc reports where the floor moved on the team's own
 *    ladder and where the package agreed or split across the deal. It asserts no
 *    legal conclusion.
 *  - **Additive** — the arc carries its own `arc_hash`, namespaced apart from
 *    every `coherence_hash`, `movement_hash`, `trajectory_hash`, and
 *    `shift_trajectory_hash`, and it re-runs the two existing functions without
 *    altering them, so computing it moves no golden.
 */

import type { NegotiationTier } from "../playbooks/custom-interpreter.js";
import { sha256Hex } from "../ingest/hash.js";
import { stableStringify } from "../engine/runner.js";
import type { CoherenceShift } from "./coherence-movement.js";
import type { PostureMovementKind } from "./posture-movement.js";
import type { PostureCoherence, PostureCoherenceKind } from "./posture-coherence.js";
import { compareCoherenceTrajectory, type FloorTrajectoryKind } from "./coherence-trajectory.js";
import {
  compareCoherenceShiftTrajectory,
  type CoherenceShiftTrajectoryKind,
} from "./coherence-shift-trajectory.js";

/**
 * One negotiation front's whole-sequence arc on **both** axes — v17's floor
 * trajectory and v18's shift trajectory, joined. The `coherences` array (each
 * round's coherence kind) is the single field the two axes share; it appears
 * once here.
 */
export type CoherenceArcFront = {
  dimension: string;
  /** The coherence kind at each round, in sequence order (`null` = the front is absent that round). */
  coherences: (PostureCoherenceKind | null)[];
  // --- binding-floor axis (spec-v17) ---
  /** The binding floor at each round, in sequence order (`null` = unstated that round). */
  floors: (NegotiationTier | null)[];
  /** The consecutive floor movements (length = rounds − 1), in v11/v13 vocabulary. */
  steps: PostureMovementKind[];
  /** The net floor movement: first stated floor vs. last (round 1 → round N). */
  net_floor_movement: PostureMovementKind;
  /** The floor path classification across the whole sequence. */
  trajectory: FloorTrajectoryKind;
  // --- coherence-kind axis (spec-v18) ---
  /** The consecutive coherence-kind shifts (length = rounds − 1), in v13 vocabulary. */
  shifts: CoherenceShift[];
  /** The net shift: first round's kind vs. last (round 1 → round N). */
  net_shift: CoherenceShift;
  /** The fracture/reconcile path classification across the whole sequence. */
  shift_trajectory: CoherenceShiftTrajectoryKind;
};

export type CoherenceArc = {
  /** How many rounds (coherences) the arc spans. */
  rounds: number;
  fronts: CoherenceArcFront[];
  // floor-axis tallies (spec-v17)
  trajectory_counts: Record<FloorTrajectoryKind, number>;
  net_counts: Record<PostureMovementKind, number>;
  // shift-axis tallies (spec-v18)
  shift_trajectory_counts: Record<CoherenceShiftTrajectoryKind, number>;
  net_shift_counts: Record<CoherenceShift, number>;
  /** The v17 floor-trajectory fingerprint, carried verbatim. */
  trajectory_hash: string;
  /** The v18 shift-trajectory fingerprint, carried verbatim. */
  shift_trajectory_hash: string;
  /** SHA-256 over the pair of component fingerprints — additive, apart from every other hash. */
  arc_hash: string;
};

/**
 * Walk N cross-document posture coherences and report, per negotiation front, the
 * combined floor-and-shift arc across the whole sequence. Pure and deterministic.
 *
 * It composes — never re-implements — the two single-axis functions: it runs
 * {@link compareCoherenceTrajectory} (v17, floor) and
 * {@link compareCoherenceShiftTrajectory} (v18, shift) on the same rounds and
 * joins their `fronts` positionally. Both pin fronts by `localeCompare` over the
 * same union of dimensions, so the arrays align index-for-index; a defensive
 * dimension check guards the join invariant.
 *
 * Every coherence must have been computed against the **same** team positions
 * (one active playbook applied to every document in every round); the CLI core
 * enforces this with the shared v15/v16 cross-ladder guard before calling here,
 * the same way v17/v18 do.
 *
 * Requires at least two rounds — a single coherence has no arc (both component
 * functions enforce this).
 */
export async function compareCoherenceArc(
  rounds: readonly PostureCoherence[],
): Promise<CoherenceArc> {
  const floor = await compareCoherenceTrajectory(rounds);
  const shift = await compareCoherenceShiftTrajectory(rounds);

  const fronts: CoherenceArcFront[] = floor.fronts.map((ff, i) => {
    const sf = shift.fronts[i]!;
    if (sf.dimension !== ff.dimension) {
      // Unreachable: both axes pin fronts by the same localeCompare over the same
      // union of dimensions. The guard makes a broken join loud instead of silent.
      throw new Error(
        `arc join misaligned at index ${i}: floor front "${ff.dimension}" vs shift front "${sf.dimension}"`,
      );
    }
    return {
      dimension: ff.dimension,
      coherences: ff.coherences,
      floors: ff.floors,
      steps: ff.steps,
      net_floor_movement: ff.net_floor_movement,
      trajectory: ff.trajectory,
      shifts: sf.shifts,
      net_shift: sf.net_shift,
      shift_trajectory: sf.shift_trajectory,
    };
  });

  const arc_hash = await sha256Hex(
    stableStringify({
      trajectory_hash: floor.trajectory_hash,
      shift_trajectory_hash: shift.shift_trajectory_hash,
    }),
  );

  return {
    rounds: floor.rounds,
    fronts,
    trajectory_counts: floor.trajectory_counts,
    net_counts: floor.net_counts,
    shift_trajectory_counts: shift.shift_trajectory_counts,
    net_shift_counts: shift.net_shift_counts,
    trajectory_hash: floor.trajectory_hash,
    shift_trajectory_hash: shift.shift_trajectory_hash,
    arc_hash,
  };
}

/**
 * Did the deal go wrong on **either** axis at **any step**? The combined CI gate
 * predicate — true when the binding floor regressed at some step (v17's
 * `trajectoryRegressed`) **or** the package fractured at some step (v18's
 * `shiftTrajectoryFractured`). This is the single deal-level verdict neither
 * single-axis command exposes: a consumer wanting it from the two commands would
 * `||` their exit codes (two reads, no combined hash); the arc computes it from
 * one read. A consumer wanting just one axis still reads `trajectory_counts` or
 * `shift_trajectory_counts`.
 */
export function arcRegressedOrFractured(arc: CoherenceArc): boolean {
  const floorRegressed =
    arc.trajectory_counts["steady-regression"] + arc.trajectory_counts.whipsaw > 0;
  const fractured =
    arc.shift_trajectory_counts["steady-fracture"] + arc.shift_trajectory_counts.oscillating > 0;
  return floorRegressed || fractured;
}

/**
 * Serialize a {@link CoherenceArc} to a stable, pretty-printed JSON string. The
 * key order is fixed and the front order is already pinned by
 * {@link compareCoherenceArc}, so the same arc always yields identical bytes —
 * the `arc_hash` it carries is the canonical fingerprint, reproducible from the
 * `trajectory_hash`/`shift_trajectory_hash` pair (and those, in turn, from the
 * single-axis commands).
 */
export function buildCoherenceArcJson(arc: CoherenceArc): string {
  return JSON.stringify(
    {
      schema: "vaulytica.posture-arc.v1",
      arc_hash: arc.arc_hash,
      trajectory_hash: arc.trajectory_hash,
      shift_trajectory_hash: arc.shift_trajectory_hash,
      rounds: arc.rounds,
      trajectory_counts: arc.trajectory_counts,
      net_counts: arc.net_counts,
      shift_trajectory_counts: arc.shift_trajectory_counts,
      net_shift_counts: arc.net_shift_counts,
      fronts: arc.fronts.map((f) => ({
        dimension: f.dimension,
        coherences: f.coherences,
        floors: f.floors,
        steps: f.steps,
        net_floor_movement: f.net_floor_movement,
        trajectory: f.trajectory,
        shifts: f.shifts,
        net_shift: f.net_shift,
        shift_trajectory: f.shift_trajectory,
      })),
    },
    null,
    2,
  );
}

const FLOOR_NET_ARROW: Partial<Record<PostureMovementKind, string>> = {
  improved: "↑ improved",
  regressed: "↓ regressed",
  "newly-stated": "+ newly stated",
  "now-unstated": "− now unstated",
};

const SHIFT_NET_MARK: Partial<Record<CoherenceShift, string>> = {
  fractured: "⤬ fractured",
  reconciled: "⤝ reconciled",
  realigned: "↔ realigned",
};

function frontMovedAdversely(f: CoherenceArcFront): boolean {
  return (
    f.trajectory === "steady-regression" ||
    f.trajectory === "whipsaw" ||
    f.shift_trajectory === "steady-fracture" ||
    f.shift_trajectory === "oscillating"
  );
}

/**
 * Render a {@link CoherenceArc} as human-readable terminal lines: the floor- and
 * shift-trajectory summary blocks (verbatim in spirit with v17/v18), then one
 * line per front that moved on **either** axis (a front that is `flat` on the
 * floor *and* `stable` on the shift is omitted, since the summary surfaces only
 * what moved), showing both paths and both net directions, and all three hashes.
 * Lives beside its JSON sibling so the CLI renders the arc from one definition.
 */
export function renderCoherenceArcSummary(arc: CoherenceArc): string {
  const tc = arc.trajectory_counts;
  const nc = arc.net_counts;
  const sc = arc.shift_trajectory_counts;
  const ns = arc.net_shift_counts;
  const n = arc.rounds;
  const lines = [
    `\nCoherence arc across ${n} rounds (floor + shift):`,
    `  floor trajectory: ${tc["steady-improvement"]} steady improvement, ${tc["steady-regression"]} steady regression, ${tc.whipsaw} whipsaw, ${tc.flat} flat.`,
    `  net floor (round 1 → round ${n}): ${nc.improved} improved, ${nc.regressed} regressed, ${nc["newly-stated"]} newly stated, ${nc["now-unstated"]} now unstated, ${nc.unchanged} unchanged.`,
    `  shift trajectory: ${sc["steady-fracture"]} steady fracture, ${sc["steady-reconcile"]} steady reconcile, ${sc.oscillating} oscillating, ${sc.stable} stable.`,
    `  net shift (round 1 → round ${n}): ${ns.fractured} fractured, ${ns.reconciled} reconciled, ${ns.realigned} realigned, ${ns.unchanged} unchanged.`,
  ];
  for (const f of arc.fronts) {
    if (f.trajectory === "flat" && f.shift_trajectory === "stable") continue;
    const floorPath = f.floors.map((t) => t ?? "—").join(" → ");
    const cohPath = f.coherences.map((c) => c ?? "—").join(" → ");
    const netFloor = FLOOR_NET_ARROW[f.net_floor_movement] ?? f.net_floor_movement;
    const netShift = SHIFT_NET_MARK[f.net_shift] ?? f.net_shift;
    const mark = frontMovedAdversely(f) ? "⚠" : "•";
    lines.push(
      `  ${mark} ${f.dimension}: floor ${f.trajectory} (${floorPath}); coherence ${f.shift_trajectory} (${cohPath}); net floor ${netFloor}, net shift ${netShift}.`,
    );
  }
  lines.push(`  trajectory_hash: ${arc.trajectory_hash}`);
  lines.push(`  shift_trajectory_hash: ${arc.shift_trajectory_hash}`);
  lines.push(`  arc_hash: ${arc.arc_hash}`);
  return lines.join("\n") + "\n";
}
