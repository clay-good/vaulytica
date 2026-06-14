/**
 * Cross-document negotiation-posture movement (spec-v13 Thrust A).
 *
 * This module is the fourth corner of the posture matrix:
 *
 *  - v10 scores a **single** document at a **single** version (the snapshot).
 *  - v11 ({@link comparePosture}) diffs two postures of **one** document across
 *    **two** versions (the movement).
 *  - v12 ({@link bundlePostureCoherence}) diffs N postures across a **bundle** at
 *    **one** round (the coherence).
 *  - v13 (here) diffs two **coherences** — a bundle at a **base** round and at a
 *    **revised** round — and reports, per negotiation front, how the bundle's
 *    **binding floor** moved and whether the package **fractured** or
 *    **reconciled** between rounds.
 *
 * The deal lead's round-over-round question that neither axis answers alone:
 * *the counterparty sent a revised package — did the weakest document on each
 * front (the rung that actually governs my exposure) get better or worse, and
 * did any front that the package agreed on quietly split apart?*
 *
 * It is a deterministic diff of two coherences the v12 engine already produces —
 * no AI, no server, no new probabilistic step, and it matches fronts by
 * **dimension** (the negotiation front), not by document, so the two rounds may
 * carry different document filenames or even a different document count (the
 * `msa-v1.docx`/`msa-v2.docx` rename between rounds never confuses it).
 *
 * Posture, restated (spec-v10 §3, unchanged):
 *  - **Deterministic** — same two coherences → identical `movement_hash`, on any
 *    machine. Fronts are pinned by `localeCompare(_, "en")`.
 *  - **Honest about unstated data** — the binding-floor movement is computed on
 *    the *stated* floor only, reusing v11's `TIER_RANK` (where `unevaluable` is
 *    unranked); a front no document states on a side is `unstated` and is never
 *    folded into a ranked improvement or regression.
 *  - **Advisory** — a movement reports where the bundle's floor moved on the
 *    team's own ladder and whether the package agreed or split. It never asserts
 *    a term became legally adequate, enforceable, or that the weakest document
 *    legally governs.
 *  - **Additive** — the movement carries its own `movement_hash`, namespaced
 *    apart from each `result_hash`, each `posture_hash`, and each
 *    `coherence_hash`, so computing it moves no golden.
 */

import type { NegotiationTier } from "../playbooks/custom-interpreter.js";
import { sha256Hex } from "../ingest/hash.js";
import { stableStringify } from "../engine/runner.js";
import { TIER_RANK, type PostureMovementKind } from "./posture-movement.js";
import type { PostureCoherence, PostureCoherenceKind } from "./posture-coherence.js";

/**
 * How the *coherence kind* of one front changed between the two rounds — the
 * advisory companion to the well-ordered floor movement.
 *
 *  - `fractured`  — the front was **not** divergent on the base round and **is**
 *                   divergent on the revised round. A position the package held
 *                   (or had not split on) now disagrees with itself.
 *  - `reconciled` — the front **was** divergent and is **no longer** divergent.
 *                   The package closed a gap between its documents.
 *  - `realigned`  — the coherence kind changed but in neither of the above ways
 *                   (e.g. `single` → `aligned`, `unstated` → `single`): the set
 *                   of documents stating the front changed without crossing the
 *                   divergence line.
 *  - `unchanged`  — the same coherence kind on both rounds.
 */
export type CoherenceShift = "fractured" | "reconciled" | "realigned" | "unchanged";

/**
 * How one negotiation front moved across the bundle between two rounds.
 *
 * `floor_movement` is the headline: the binding floor (the weakest *stated*
 * rung, which governs exposure) classified with the exact v11 vocabulary —
 * `improved` / `regressed` / `unchanged` / `newly-stated` / `now-unstated`, plus
 * defensive `appeared` / `disappeared` for the cross-ladder case. `coherence_shift`
 * is the advisory companion: did the package fracture or reconcile on this front?
 */
export type CoherenceFrontMovement = {
  dimension: string;
  /** The front's coherence kind on the base round (`null` only if absent — defensive, cross-ladder). */
  base_coherence: PostureCoherenceKind | null;
  /** The front's coherence kind on the revised round (`null` only if absent — defensive). */
  revised_coherence: PostureCoherenceKind | null;
  /** The binding floor (weakest stated rung) on the base round; `null` when no document stated it. */
  base_floor: NegotiationTier | null;
  /** The binding floor on the revised round; `null` when no document stated it. */
  revised_floor: NegotiationTier | null;
  /** How the binding floor moved — the well-ordered, gate-worthy signal (v11 vocabulary). */
  floor_movement: PostureMovementKind;
  /** How the coherence kind shifted — advisory context for the floor movement. */
  coherence_shift: CoherenceShift;
};

export type CoherenceMovement = {
  fronts: CoherenceFrontMovement[];
  floor_counts: Record<PostureMovementKind, number>;
  shift_counts: Record<CoherenceShift, number>;
  /** SHA-256 over the canonical movement set — additive, apart from each `coherence_hash`. */
  movement_hash: string;
};

function emptyFloorCounts(): Record<PostureMovementKind, number> {
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

function emptyShiftCounts(): Record<CoherenceShift, number> {
  return { fractured: 0, reconciled: 0, realigned: 0, unchanged: 0 };
}

/**
 * Classify how the binding floor moved, given the floor tier on each side
 * (`null` = no document stated the front on that side). Identical contract to
 * v11's per-dimension classifier: a transition that touches an unstated side is
 * `newly-stated` / `now-unstated` and is **never** ranked as improved or
 * regressed (the §3 honesty contract — "not stated" is not a point on the
 * ideal→floor axis).
 */
function classifyFloorMovement(
  base: NegotiationTier | null,
  revised: NegotiationTier | null,
): PostureMovementKind {
  if (base === null && revised === null) return "unchanged";
  if (base === null) return "newly-stated"; // no stated floor before → a floor now exists
  if (revised === null) return "now-unstated"; // a floor before → none stated now
  if (base === revised) return "unchanged";

  // Both sides have a stated floor; both are ranked (a stated floor is never
  // `unevaluable`), so compare the rungs directly.
  return (TIER_RANK[revised] as number) > (TIER_RANK[base] as number) ? "improved" : "regressed";
}

/** Classify the coherence-kind shift between the two rounds (both kinds present). */
function classifyShift(
  base: PostureCoherenceKind,
  revised: PostureCoherenceKind,
): CoherenceShift {
  if (base === revised) return "unchanged";
  if (revised === "divergent") return "fractured";
  if (base === "divergent") return "reconciled";
  return "realigned";
}

/**
 * Compare two cross-document posture coherences — the same bundle at a base
 * round and a revised round — and report, per negotiation front, how the binding
 * floor moved and whether the package fractured or reconciled.
 *
 * Pure and deterministic: fronts are matched by dimension and pinned by
 * `localeCompare`, and `movement_hash` is over the canonical per-front set, so
 * the same two coherences always yield identical bytes.
 *
 * Both coherences must have been computed against the **same** team positions
 * (the caller applies one active playbook to every document in both rounds) —
 * comparing floors computed from different ladders would be nonsense, the same
 * way v11 refuses a cross-ladder movement and v12 refuses a cross-ladder
 * coherence.
 */
export async function compareCoherence(
  base: PostureCoherence,
  revised: PostureCoherence,
): Promise<CoherenceMovement> {
  const baseByDim = new Map(base.dimensions.map((d) => [d.dimension, d]));
  const revisedByDim = new Map(revised.dimensions.map((d) => [d.dimension, d]));

  const labels = Array.from(new Set([...baseByDim.keys(), ...revisedByDim.keys()])).sort((a, b) =>
    a.localeCompare(b, "en"),
  );

  const floor_counts = emptyFloorCounts();
  const shift_counts = emptyShiftCounts();

  const fronts: CoherenceFrontMovement[] = labels.map((dimension) => {
    const b = baseByDim.get(dimension) ?? null;
    const r = revisedByDim.get(dimension) ?? null;

    const base_coherence = b?.coherence ?? null;
    const revised_coherence = r?.coherence ?? null;
    const base_floor = b?.weakest_tier ?? null;
    const revised_floor = r?.weakest_tier ?? null;

    const floor_movement = classifyFloorMovement(base_floor, revised_floor);
    const coherence_shift =
      base_coherence !== null && revised_coherence !== null
        ? classifyShift(base_coherence, revised_coherence)
        : "unchanged";

    floor_counts[floor_movement] += 1;
    shift_counts[coherence_shift] += 1;

    return {
      dimension,
      base_coherence,
      revised_coherence,
      base_floor,
      revised_floor,
      floor_movement,
      coherence_shift,
    };
  });

  const movement_hash = await sha256Hex(
    stableStringify({
      fronts: fronts.map((f) => ({
        dimension: f.dimension,
        base_coherence: f.base_coherence,
        revised_coherence: f.revised_coherence,
        base_floor: f.base_floor,
        revised_floor: f.revised_floor,
        floor_movement: f.floor_movement,
        coherence_shift: f.coherence_shift,
      })),
    }),
  );

  return { fronts, floor_counts, shift_counts, movement_hash };
}

/**
 * Did the bundle's binding floor regress on any front between the two rounds?
 * The CI gate predicate (mirrors v11's `postureRegressed` and v12's
 * `hasDivergence`): true when any front's binding floor moved to a strictly
 * worse stated rung. A floor that dropped off the ladder entirely
 * (`now-unstated`) is reported but never trips it (§3 honesty — a dropped front
 * is not conflated with a rung regression; a team that wants to gate on it
 * composes from `floor_counts`).
 */
export function coherenceRegressed(movement: CoherenceMovement): boolean {
  return movement.floor_counts.regressed > 0;
}

/**
 * Serialize a {@link CoherenceMovement} to a stable, pretty-printed JSON string
 * for the two-round deliverable's structured download (spec-v13 Thrust B). The
 * key order is fixed and the front order is already pinned by `compareCoherence`,
 * so the same movement always yields identical bytes — the `movement_hash` it
 * carries is the canonical fingerprint, reproducible from the `fronts` here.
 */
export function buildCoherenceMovementJson(movement: CoherenceMovement): string {
  return JSON.stringify(
    {
      schema: "vaulytica.posture-movement.v1",
      movement_hash: movement.movement_hash,
      floor_counts: movement.floor_counts,
      shift_counts: movement.shift_counts,
      fronts: movement.fronts.map((f) => ({
        dimension: f.dimension,
        base_coherence: f.base_coherence,
        revised_coherence: f.revised_coherence,
        base_floor: f.base_floor,
        revised_floor: f.revised_floor,
        floor_movement: f.floor_movement,
        coherence_shift: f.coherence_shift,
      })),
    },
    null,
    2,
  );
}
