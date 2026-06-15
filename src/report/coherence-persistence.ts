/**
 * Cross-document negotiation-posture **exposure persistence** — the whole-deal
 * below-floor *duration* and *current standing* (spec-v21).
 *
 * v20 ({@link compareCoherenceExposure}) reads the posture archive on the
 * **level** axis: per front, the *worst* binding floor it ever reached (its
 * low-water mark). That answers "how low did it get." But a low-water mark is a
 * single extreme with no memory of time, so it cannot tell a closed wound from an
 * open one: a front that dipped to `below-acceptable` in round 2 and **recovered**
 * to `acceptable` by round 4 carries the same `worst_floor` / `exposed` as a front
 * **still** at `below-acceptable` in the latest round — and v20's
 * `--fail-on-exposure` fires on both, forever (the worst point never changes once
 * it has happened). A team that resolved a dip cannot make that gate go green.
 *
 * This module is the orthogonal **duration** axis the level family never read:
 *
 *  - v17 answers *which way did the floor move* — up, down, or whipsaw.
 *  - v20 answers *how low did the floor ever get* — the worst rung reached.
 *  - v21 (here) answers *how long was it below floor, and is it still below floor
 *    now* — the count of rounds each front sat below acceptable, the span it was
 *    down, and whether its **latest stated** floor is still below acceptable. A
 *    front that recovered is `resolved` (gate clears); a front still down is `open`
 *    (gate trips).
 *
 * It adds **no** posture math beyond a scan for the `below-acceptable` rung v10
 * defines, over the binding floors v12 derived and v20 already reads. The posture
 * filter (spec-v10 §3), restated:
 *  - **Deterministic** — same N coherences in the same order → identical
 *    `persistence_hash`, on any machine. Fronts are pinned by `localeCompare(_,
 *    "en")` (the same order the trajectory/exposure functions use); the round
 *    order is the caller's.
 *  - **Honest about unstated data** — a front no document states in *any* round is
 *    `unstated`, never `open`/`resolved`. Current standing reads the latest round
 *    that *stated* the front, not the latest round overall: silence after an
 *    exposure keeps the last *known* standing — neither an invented recovery nor a
 *    fresh exposure (the §3 contract that keeps `newly-stated`/`now-unstated`
 *    unranked in v11/v13 and `unstated` never-flagged in v20).
 *  - **Advisory** — the report names how long each front sat below the team's own
 *    floor and where it stands now. It asserts no legal conclusion.
 *  - **Additive** — the persistence carries its own `persistence_hash`, namespaced
 *    apart from every `coherence_hash`, `movement_hash`, `trajectory_hash`,
 *    `shift_trajectory_hash`, `arc_hash`, and `exposure_hash`, so computing it
 *    moves no golden.
 */

import type { NegotiationTier } from "../playbooks/custom-interpreter.js";
import { sha256Hex } from "../ingest/hash.js";
import { stableStringify } from "../engine/runner.js";
import type { PostureCoherence } from "./posture-coherence.js";

/** The team's acceptable floor — the one rung whose name means "below what we will accept." */
const BELOW_FLOOR: NegotiationTier = "below-acceptable";

/**
 * A front's below-floor history class:
 *  - `open` — its latest *stated* binding floor is `below-acceptable` (still down);
 *  - `resolved` — it was below floor at some round but its latest stated floor is
 *    at/above acceptable (recovered);
 *  - `none` — stated, but never below floor;
 *  - `unstated` — no document ever stated the front (§3: silence is not exposure).
 */
export type PersistenceClass = "open" | "resolved" | "none" | "unstated";

/** One negotiation front's whole-sequence below-floor duration and current standing. */
export type CoherencePersistenceFront = {
  dimension: string;
  /** The binding floor at each round, in sequence order (`null` = unstated that round). */
  floors: (NegotiationTier | null)[];
  /** How many rounds stated a `below-acceptable` binding floor. */
  rounds_below: number;
  /** The 1-based first round it was below floor (`null` when never below floor). */
  first_below_round: number | null;
  /** The 1-based last round it was below floor (`null` when never below floor). */
  last_below_round: number | null;
  /** The 1-based latest round that stated a floor (`null` when never stated). */
  last_stated_round: number | null;
  /** True iff the floor at {@link last_stated_round} is `below-acceptable` (current standing). */
  currently_below: boolean;
  /** The below-floor history class. */
  persistence: PersistenceClass;
};

export type CoherencePersistence = {
  /** How many rounds (coherences) the persistence spans. */
  rounds: number;
  fronts: CoherencePersistenceFront[];
  /** Per-front tally by persistence class. */
  class_counts: Record<PersistenceClass, number>;
  /** How many fronts are still below floor at their latest stated round (the gate-worthy count). */
  open_count: number;
  /** SHA-256 over the canonical persistence set — additive, apart from every other hash. */
  persistence_hash: string;
};

function emptyClassCounts(): Record<PersistenceClass, number> {
  return { open: 0, resolved: 0, none: 0, unstated: 0 };
}

/**
 * Walk N cross-document posture coherences — the same bundle at round 1, round
 * 2, …, round N — and report, per negotiation front, how long it sat below the
 * acceptable floor and whether it is still below floor at its latest stated round.
 *
 * Pure and deterministic: fronts are matched by dimension and pinned by
 * `localeCompare`, the round order is the caller's, and `persistence_hash` is over
 * the canonical per-front set, so the same N coherences in the same order always
 * yield identical bytes.
 *
 * Every coherence must have been computed against the **same** team positions (the
 * caller applies one active playbook to every document in every round); comparing
 * floors across different ladders is nonsense, the same way v13/v16 refuse a
 * cross-ladder diff. The CLI core ({@link computeCoherencePersistenceArtifacts})
 * enforces this via the v15/v16 ladder guard before calling this.
 *
 * Requires at least two rounds — persistence is the *whole-deal* duration; a
 * single round's floors are exactly what `analyze --posture` already reports.
 */
export async function computeCoherencePersistence(
  rounds: readonly PostureCoherence[],
): Promise<CoherencePersistence> {
  if (rounds.length < 2) {
    throw new Error(`a persistence needs at least two rounds (got ${rounds.length})`);
  }

  const byDim = rounds.map((c) => new Map(c.dimensions.map((d) => [d.dimension, d])));
  const labels = Array.from(
    new Set(rounds.flatMap((c) => c.dimensions.map((d) => d.dimension))),
  ).sort((a, b) => a.localeCompare(b, "en"));

  const class_counts = emptyClassCounts();
  let open_count = 0;

  const fronts: CoherencePersistenceFront[] = labels.map((dimension) => {
    const floors = byDim.map((m) => m.get(dimension)?.weakest_tier ?? null);

    let rounds_below = 0;
    let first_below_round: number | null = null;
    let last_below_round: number | null = null;
    let last_stated_round: number | null = null;
    floors.forEach((t, i) => {
      if (t === null) return;
      last_stated_round = i + 1;
      if (t === BELOW_FLOOR) {
        rounds_below += 1;
        if (first_below_round === null) first_below_round = i + 1;
        last_below_round = i + 1;
      }
    });

    // Current standing reads the *latest stated* round (§3: silence keeps the last
    // known standing — neither an invented recovery nor a fresh exposure).
    const currentFloor =
      last_stated_round === null ? null : (floors[(last_stated_round as number) - 1] ?? null);
    const currently_below = currentFloor === BELOW_FLOOR;

    const persistence: PersistenceClass =
      last_stated_round === null
        ? "unstated"
        : currently_below
          ? "open"
          : rounds_below > 0
            ? "resolved"
            : "none";

    if (persistence === "open") open_count += 1;
    class_counts[persistence] += 1;

    return {
      dimension,
      floors,
      rounds_below,
      first_below_round,
      last_below_round,
      last_stated_round,
      currently_below,
      persistence,
    };
  });

  const persistence_hash = await sha256Hex(
    stableStringify({
      rounds: rounds.length,
      fronts: fronts.map((f) => ({
        dimension: f.dimension,
        floors: f.floors,
        rounds_below: f.rounds_below,
        first_below_round: f.first_below_round,
        last_below_round: f.last_below_round,
        last_stated_round: f.last_stated_round,
        currently_below: f.currently_below,
        persistence: f.persistence,
      })),
    }),
  );

  return { rounds: rounds.length, fronts, class_counts, open_count, persistence_hash };
}

/**
 * Is any front still below the team's acceptable floor at its latest stated round?
 * The CI gate predicate — the *current-standing* counterpart to v20's *ever* gate.
 * Unlike `exposureBreached` (which fires on a floor below acceptable at *any* round
 * and stays red after a recovery), this fires only on a front below floor *now*, so
 * a resolved dip clears the gate and an open wound trips it. A consumer wanting a
 * below-floor-round *count* reads `rounds_below` instead.
 */
export function exposureOpen(persistence: CoherencePersistence): boolean {
  return persistence.open_count > 0;
}

/**
 * Serialize a {@link CoherencePersistence} to a stable, pretty-printed JSON string.
 * The key order is fixed and the front order is already pinned by
 * {@link computeCoherencePersistence}, so the same persistence always yields
 * identical bytes — the `persistence_hash` it carries is the canonical fingerprint,
 * reproducible from `fronts`.
 */
export function buildCoherencePersistenceJson(persistence: CoherencePersistence): string {
  return JSON.stringify(
    {
      schema: "vaulytica.posture-persistence.v1",
      persistence_hash: persistence.persistence_hash,
      rounds: persistence.rounds,
      class_counts: persistence.class_counts,
      open_count: persistence.open_count,
      fronts: persistence.fronts.map((f) => ({
        dimension: f.dimension,
        floors: f.floors,
        rounds_below: f.rounds_below,
        first_below_round: f.first_below_round,
        last_below_round: f.last_below_round,
        last_stated_round: f.last_stated_round,
        currently_below: f.currently_below,
        persistence: f.persistence,
      })),
    },
    null,
    2,
  );
}

/**
 * Render a {@link CoherencePersistence} as human-readable terminal lines: the
 * class tally and the open-front count, then one line per **open** front (still
 * below floor — showing the floor path, how many rounds it was down, and the
 * span), then one line per **resolved** front (recovered — showing when it was
 * down and that it is now back above floor). A `none` or `unstated` front is
 * counted but never listed (§3 honesty). Lives beside its JSON sibling so the CLI
 * renders the persistence from one definition.
 */
export function renderCoherencePersistenceSummary(persistence: CoherencePersistence): string {
  const cc = persistence.class_counts;
  const n = persistence.rounds;
  const lines = [
    `\nCoherence exposure persistence across ${n} rounds (below-floor duration & current standing):`,
    `  ${cc.open} open (still below floor), ${cc.resolved} resolved (recovered), ${cc.none} never below floor, ${cc.unstated} never stated.`,
    `  open fronts (below floor now): ${persistence.open_count}.`,
  ];
  for (const f of persistence.fronts) {
    if (f.persistence !== "open") continue;
    const path = f.floors.map((t) => t ?? "—").join(" → ");
    const span =
      f.first_below_round === f.last_below_round
        ? `round ${f.first_below_round}`
        : `rounds ${f.first_below_round}–${f.last_below_round}`;
    lines.push(
      `  ⚠ ${f.dimension}: open — below floor ${f.rounds_below} of ${n} rounds (${span}), still below floor at round ${f.last_stated_round} (${path}).`,
    );
  }
  for (const f of persistence.fronts) {
    if (f.persistence !== "resolved") continue;
    const path = f.floors.map((t) => t ?? "—").join(" → ");
    const span =
      f.first_below_round === f.last_below_round
        ? `round ${f.first_below_round}`
        : `rounds ${f.first_below_round}–${f.last_below_round}`;
    lines.push(
      `  ✓ ${f.dimension}: resolved — was below floor ${span}, now back above floor at round ${f.last_stated_round} (${path}).`,
    );
  }
  lines.push(`  persistence_hash: ${persistence.persistence_hash}`);
  return lines.join("\n") + "\n";
}
