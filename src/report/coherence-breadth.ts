/**
 * Cross-document negotiation-posture **exposure breadth** — the whole-deal
 * *per-round* standing across all fronts (spec-v22).
 *
 * Every posture command from v16 to v21 reads the N-round archive **down the
 * front axis**: pick a negotiation front, summarize its history *across rounds*.
 *  - v17 ({@link compareCoherenceTrajectory}) — which way did the front's floor move.
 *  - v20 ({@link compareCoherenceExposure}) — how low did the front's floor ever get.
 *  - v21 ({@link computeCoherencePersistence}) — how long was the front below floor,
 *    and is it still below floor now.
 *
 * None of them reads the archive **down the round axis**: pick a *round*,
 * summarize the whole deal's standing *across fronts*. So from the archive a deal
 * lead can answer "is the Cap front still below floor?" (v21) but not "how many
 * fronts were below floor in round 3, and was that the worst the package ever
 * looked?" — every existing command produces a per-front series; none produces a
 * per-round one. That is a missing **axis**, the transpose of v20/v21.
 *
 * This module is that transpose:
 *
 *  - v20/v21 answer *for each front, summarize the rounds* — a per-front reduction.
 *  - v22 (here) answers *for each round, summarize the fronts* — a per-round
 *    reduction: the count of fronts below the acceptable floor in each round
 *    (`exposed_fronts`), the deal's **worst round** (the round with the most fronts
 *    below floor at once), and whether the package's exposure **broadened** from the
 *    first round to the latest (`widened`). A deal whose breadth grew over the
 *    negotiation trips the gate even if no single front's *worst point* changed.
 *
 * It adds **no** posture math beyond a per-round count of the `below-acceptable`
 * rung v10 defines, over the binding floors v12 derived and v20 already reads. The
 * posture filter (spec-v10 §3), restated:
 *  - **Deterministic** — same N coherences in the same order → identical
 *    `breadth_hash`, on any machine. The round order is the caller's; the
 *    per-round exposed-dimension lists are pinned by `localeCompare(_, "en")` (the
 *    same order the trajectory/exposure functions pin fronts).
 *  - **Honest about unstated data** — a front no document states in a round is not
 *    counted as below floor that round: "not stated" is not a point on the
 *    ideal→floor axis, so silence is never a false exposure (the §3 contract that
 *    keeps `unstated` never-flagged in v20). `stated_fronts` gives the denominator.
 *  - **Advisory** — the report names how broadly the package sat below the team's
 *    own floor at each round. It asserts no legal conclusion.
 *  - **Additive** — the breadth carries its own `breadth_hash`, namespaced apart
 *    from every `coherence_hash`, `movement_hash`, `trajectory_hash`,
 *    `shift_trajectory_hash`, `arc_hash`, `exposure_hash`, and `persistence_hash`,
 *    so computing it moves no golden.
 */

import { sha256Hex } from "../ingest/hash.js";
import { stableStringify } from "../engine/runner.js";
import type { PostureCoherence } from "./posture-coherence.js";

/** The team's acceptable floor — the one rung whose name means "below what we will accept." */
const BELOW_FLOOR = "below-acceptable";

/** One round's deal-wide standing: how many fronts sat below the acceptable floor. */
export type CoherenceBreadthRound = {
  /** The 1-based round index, in sequence order. */
  round: number;
  /** How many fronts had a binding floor of `below-acceptable` this round. */
  exposed_fronts: number;
  /** How many fronts stated a binding floor this round (the denominator; the rest are unstated). */
  stated_fronts: number;
  /** The fronts below floor this round, pinned by `localeCompare` (so the list is deterministic). */
  exposed_dimensions: string[];
};

export type CoherenceBreadth = {
  /** How many rounds (coherences) the breadth spans. */
  rounds: number;
  /** The per-round deal-wide standing, in sequence order. */
  per_round: CoherenceBreadthRound[];
  /** The 1-based round with the most fronts below floor (earliest on a tie; `null` when none ever was). */
  worst_round: number | null;
  /** The exposed-front count at {@link worst_round} (0 when no front was ever below floor). */
  worst_count: number;
  /** The exposed-front count in the first round. */
  first_count: number;
  /** The exposed-front count in the latest round. */
  latest_count: number;
  /** True iff the latest round has strictly more fronts below floor than the first (the gate-worthy verdict). */
  widened: boolean;
  /** SHA-256 over the canonical per-round set — additive, apart from every other hash. */
  breadth_hash: string;
};

/**
 * Walk N cross-document posture coherences — the same bundle at round 1, round
 * 2, …, round N — and report, *per round*, how many fronts sat below the
 * acceptable floor (the deal's aggregate standing that round), plus the worst
 * round and whether the package's exposure broadened from first to latest.
 *
 * Pure and deterministic: the round order is the caller's, the per-round
 * exposed-dimension lists are pinned by `localeCompare`, and `breadth_hash` is
 * over the canonical per-round set, so the same N coherences in the same order
 * always yield identical bytes.
 *
 * Every coherence must have been computed against the **same** team positions (the
 * caller applies one active playbook to every document in every round); comparing
 * floors across different ladders is nonsense, the same way v13/v16 refuse a
 * cross-ladder diff. The CLI core ({@link computeCoherenceBreadthArtifacts})
 * enforces this via the v15/v16 ladder guard before calling this.
 *
 * Requires at least two rounds — breadth is the *whole-deal* per-round series; a
 * single round's below-floor count is exactly what `analyze --posture` already
 * reports.
 */
export async function computeCoherenceBreadth(
  rounds: readonly PostureCoherence[],
): Promise<CoherenceBreadth> {
  if (rounds.length < 2) {
    throw new Error(`a breadth needs at least two rounds (got ${rounds.length})`);
  }

  const per_round: CoherenceBreadthRound[] = rounds.map((c, i) => {
    let stated_fronts = 0;
    const exposed_dimensions: string[] = [];
    for (const d of c.dimensions) {
      if (d.weakest_tier === null) continue;
      stated_fronts += 1;
      if (d.weakest_tier === BELOW_FLOOR) exposed_dimensions.push(d.dimension);
    }
    exposed_dimensions.sort((a, b) => a.localeCompare(b, "en"));
    return {
      round: i + 1,
      exposed_fronts: exposed_dimensions.length,
      stated_fronts,
      exposed_dimensions,
    };
  });

  // The worst round is the round with the most fronts below floor; the first such
  // round wins a tie (earliest-peak, mirroring v20's earliest-exposure tiebreak).
  let worst_round: number | null = null;
  let worst_count = 0;
  for (const r of per_round) {
    if (r.exposed_fronts > worst_count) {
      worst_count = r.exposed_fronts;
      worst_round = r.round;
    }
  }

  const first_count = per_round[0]!.exposed_fronts;
  const latest_count = per_round[per_round.length - 1]!.exposed_fronts;
  const widened = latest_count > first_count;

  const breadth_hash = await sha256Hex(
    stableStringify({
      rounds: rounds.length,
      per_round: per_round.map((r) => ({
        round: r.round,
        exposed_fronts: r.exposed_fronts,
        stated_fronts: r.stated_fronts,
        exposed_dimensions: r.exposed_dimensions,
      })),
    }),
  );

  return {
    rounds: rounds.length,
    per_round,
    worst_round,
    worst_count,
    first_count,
    latest_count,
    widened,
    breadth_hash,
  };
}

/**
 * Did the package's exposure *broaden* over the negotiation — does the latest
 * round have strictly more fronts below the acceptable floor than the first? The
 * CI gate predicate — the *deal-level breadth* counterpart to v20's per-front
 * level gate. Unlike `exposureBreached` (which fires on any single front ever
 * below floor) and `exposureOpen` (which fires on any single front still below
 * floor now), this fires on the *aggregate trend*: the deal ended with more fronts
 * below floor than it started with. It needs no tuning — it compares the two
 * endpoint counts. A consumer wanting the worst round's absolute breadth reads
 * `worst_count` instead.
 */
export function exposureWidened(breadth: CoherenceBreadth): boolean {
  return breadth.widened;
}

/**
 * Serialize a {@link CoherenceBreadth} to a stable, pretty-printed JSON string.
 * The key order is fixed and the per-round series is already in sequence order
 * with `localeCompare`-pinned dimension lists, so the same breadth always yields
 * identical bytes — the `breadth_hash` it carries is the canonical fingerprint,
 * reproducible from `per_round`.
 */
export function buildCoherenceBreadthJson(breadth: CoherenceBreadth): string {
  return JSON.stringify(
    {
      schema: "vaulytica.posture-breadth.v1",
      breadth_hash: breadth.breadth_hash,
      rounds: breadth.rounds,
      worst_round: breadth.worst_round,
      worst_count: breadth.worst_count,
      first_count: breadth.first_count,
      latest_count: breadth.latest_count,
      widened: breadth.widened,
      per_round: breadth.per_round.map((r) => ({
        round: r.round,
        exposed_fronts: r.exposed_fronts,
        stated_fronts: r.stated_fronts,
        exposed_dimensions: r.exposed_dimensions,
      })),
    },
    null,
    2,
  );
}

/**
 * Render a {@link CoherenceBreadth} as human-readable terminal lines: the
 * per-round below-floor count (the deal's standing each round), the worst round,
 * and whether the package's exposure widened, narrowed, or held from first to
 * latest. Lives beside its JSON sibling so the CLI renders the breadth from one
 * definition.
 */
export function renderCoherenceBreadthSummary(breadth: CoherenceBreadth): string {
  const n = breadth.rounds;
  const trend = breadth.widened
    ? `widened (${breadth.first_count} → ${breadth.latest_count} fronts below floor)`
    : breadth.latest_count < breadth.first_count
      ? `narrowed (${breadth.first_count} → ${breadth.latest_count} fronts below floor)`
      : `held (${breadth.first_count} → ${breadth.latest_count} fronts below floor)`;
  const lines = [
    `\nCoherence exposure breadth across ${n} rounds (fronts below floor per round):`,
    `  exposure ${trend}.`,
    breadth.worst_round === null
      ? `  worst round: none — no front was ever below floor.`
      : `  worst round: round ${breadth.worst_round} (${breadth.worst_count} front${breadth.worst_count === 1 ? "" : "s"} below floor at once).`,
  ];
  for (const r of breadth.per_round) {
    const dims = r.exposed_fronts === 0 ? "—" : r.exposed_dimensions.join(", ");
    lines.push(
      `  round ${r.round}: ${r.exposed_fronts} of ${r.stated_fronts} stated front${r.stated_fronts === 1 ? "" : "s"} below floor (${dims}).`,
    );
  }
  lines.push(`  breadth_hash: ${breadth.breadth_hash}`);
  return lines.join("\n") + "\n";
}
