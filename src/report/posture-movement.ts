/**
 * Negotiation-posture movement across versions (spec-v11 Thrust A).
 *
 * A negotiation is a sequence of drafts. v10 reports which rung of the team's
 * ladder a *single* draft sits on for each dimension; this module reports how
 * that rung **moved** when the counterparty sends a revised draft — the thing a
 * negotiator most needs round-over-round: *did their counter improve, regress,
 * or leave each front untouched?*
 *
 * It is a deterministic diff of two deterministic {@link NegotiationPosture}s
 * the v10 evaluator already produces — no AI, no server, no new probabilistic
 * step. Both postures are computed by classifying the team's *same* positions
 * against each draft; this function compares the two tier classifications by
 * dimension and labels each transition.
 *
 * Posture, restated (spec-v10 §3, unchanged):
 *  - **Deterministic** — same two postures → identical `movement_hash`, on any
 *    machine. The dimension order is pinned by `localeCompare(_, "en")`.
 *  - **Honest about unstated data** — a dimension that is `unevaluable` on one
 *    side is never folded into improved/regressed (that would conflate "not
 *    stated" with "below floor", which the §3 contract forbids). It gets its
 *    own honest label: `newly-stated` (was unstated, now on the ladder) or
 *    `now-unstated` (was on the ladder, now absent from the revised draft).
 *  - **Advisory** — a movement reports where the draft moved on the team's own
 *    ladder. It never asserts a term became legally adequate or enforceable.
 *  - **Additive** — the movement carries its own `movement_hash`, namespaced
 *    apart from the comparison `result_hash`, so wiring it moves no golden.
 */

import type { NegotiationPosture, NegotiationTier } from "../playbooks/custom-interpreter.js";
import { sha256Hex } from "../ingest/hash.js";
import { stableStringify } from "../engine/runner.js";

/**
 * How a single dimension's rung moved between the base and the revised draft.
 *
 *  - `improved`      — both drafts state the term; the revised rung is strictly
 *                      better (closer to ideal) than the base.
 *  - `regressed`     — both state it; the revised rung is strictly worse.
 *  - `unchanged`     — the same tier on both drafts (including both unstated).
 *  - `newly-stated`  — unstated on the base, on the ladder in the revised draft.
 *  - `now-unstated`  — on the ladder in the base, unstated in the revised draft.
 *  - `appeared`      — the dimension is in the revised posture only (defensive;
 *                      only possible if the two runs used different positions).
 *  - `disappeared`   — the dimension is in the base posture only (defensive).
 */
export type PostureMovementKind =
  | "improved"
  | "regressed"
  | "unchanged"
  | "newly-stated"
  | "now-unstated"
  | "appeared"
  | "disappeared";

export type PostureDimensionMovement = {
  dimension: string;
  /** The rung the base draft met, or null when the dimension is absent from the base posture. */
  base_tier: NegotiationTier | null;
  /** The rung the revised draft meets, or null when absent from the revised posture. */
  revised_tier: NegotiationTier | null;
  movement: PostureMovementKind;
};

export type PostureMovement = {
  dimensions: PostureDimensionMovement[];
  counts: Record<PostureMovementKind, number>;
  /** SHA-256 over the canonical movement set — additive, apart from `result_hash`. */
  movement_hash: string;
};

/**
 * Rung order on the ladder (higher is closer to the team's ideal). `unevaluable`
 * is deliberately **unranked** (null): "not stated" is not a point on the
 * ideal→floor axis, so it is never compared as better or worse than a stated
 * rung (spec-v10 §3 corollary 2). Adding a rung here is the single place to
 * extend the order.
 */
const TIER_RANK: Record<NegotiationTier, number | null> = {
  ideal: 3,
  acceptable: 2,
  "below-acceptable": 1,
  unevaluable: null,
};

function emptyCounts(): Record<PostureMovementKind, number> {
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

/** Classify how one dimension moved, given the tier on each side (null = absent). */
function classifyMovement(
  base: NegotiationTier | null,
  revised: NegotiationTier | null,
): PostureMovementKind {
  if (base === null) return "appeared";
  if (revised === null) return "disappeared";
  if (base === revised) return "unchanged";

  const baseRank = TIER_RANK[base];
  const revRank = TIER_RANK[revised];

  // Exactly one side is unstated: honest, non-ranked transitions.
  if (baseRank === null) return "newly-stated"; // base unevaluable → revised on the ladder
  if (revRank === null) return "now-unstated"; // base on the ladder → revised unevaluable

  // Both stated and different: compare rungs.
  return revRank > baseRank ? "improved" : "regressed";
}

/**
 * Compare two negotiation postures and report, per dimension, how the rung
 * moved. Pure and deterministic: the dimension order is pinned, and the
 * `movement_hash` is over the canonical `{dimension, base_tier, revised_tier,
 * movement}` set so the same two postures always yield identical bytes.
 */
export async function comparePosture(
  base: NegotiationPosture,
  revised: NegotiationPosture,
): Promise<PostureMovement> {
  const baseTier = new Map<string, NegotiationTier>();
  for (const p of base.positions) baseTier.set(p.dimension, p.tier);
  const revisedTier = new Map<string, NegotiationTier>();
  for (const p of revised.positions) revisedTier.set(p.dimension, p.tier);

  const labels = Array.from(new Set([...baseTier.keys(), ...revisedTier.keys()]));
  labels.sort((a, b) => a.localeCompare(b, "en"));

  const counts = emptyCounts();
  const dimensions: PostureDimensionMovement[] = labels.map((dimension) => {
    const b = baseTier.get(dimension) ?? null;
    const r = revisedTier.get(dimension) ?? null;
    const movement = classifyMovement(b, r);
    counts[movement] += 1;
    return { dimension, base_tier: b, revised_tier: r, movement };
  });

  const movement_hash = await sha256Hex(
    stableStringify({
      dimensions: dimensions.map((d) => ({
        dimension: d.dimension,
        base_tier: d.base_tier,
        revised_tier: d.revised_tier,
        movement: d.movement,
      })),
    }),
  );

  return { dimensions, counts, movement_hash };
}
