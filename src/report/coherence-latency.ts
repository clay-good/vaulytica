/**
 * Cross-document negotiation-posture **exposure recovery latency** — per front, the
 * number of rounds its binding floor sat *below* the acceptable floor between a
 * *fall* crossing and the *recovery* crossing that closes it, and whether a fall
 * ever went unrecovered (spec-v28).
 *
 * v24 ({@link computeCoherenceVolatility}) counts, per front, how many times its
 * standing crossed the floor across the deal (`crossings`). v25
 * ({@link computeCoherenceSynchrony}) re-buckets those crossings by *step*. v26
 * ({@link computeCoherenceSettling}) reads the **index** of the *last* crossing
 * (`settling_round`); v27 ({@link computeCoherenceOnset}) the **index** of the
 * *first* (`onset_round`). All four reduce the crossings to a count or a single
 * index — and a count and an index both throw away the **gap between a fall and the
 * recovery that closes it**. Two fronts with the identical crossing count (both fell
 * once and recovered once) can be opposites on the one axis a deal lead asks
 * reviewing a close: **once it fell below the floor, how many rounds did it stay
 * there before it recovered — and did it ever recover at all?**
 *
 * - The **prompt recovery.** Cap falls in round 2 and recovers in round 3 — two
 *   crossings, but exposed for a *single* round.
 * - The **slow recovery.** Cap falls in round 2 and recovers in round 6 — also two
 *   crossings (same `crossings`), yet it sat below floor for *four* rounds.
 *
 * That is a missing **axis**: the *recovery-latency* dimension of the same crossing
 * data. Where v24 sums crossings down the front axis, v25 sums them down the step
 * axis, and v26/v27 read the max/min crossing index, v28 **pairs** each fall crossing
 * with the recovery crossing that closes it and reads the **gap between them** — each
 * episode's `latency` (the rounds it sat below floor), the deal's slowest recovery
 * (`max_latency`), and whether a fall ever went unrecovered (`open_count`).
 *
 * It is a reduction of the **same** floor crossings v24/v25/v26/v27 read —
 * `total_crossings` equals v24's grand total and v25/v26/v27's per-step sum by
 * construction. It adds **no** posture math beyond pairing falls and recoveries across
 * the `below-acceptable` rung v10 defines, over the binding floors v12 derived and
 * v22/v24/v25/v26/v27 already read. The posture filter (spec-v10 §3), restated:
 *  - **Deterministic** — same N coherences in the same order → identical
 *    `latency_hash`, on any machine. Fronts are pinned by `localeCompare(_, "en")`
 *    (the same order the trajectory/exposure/volatility/synchrony/settling/onset
 *    functions pin fronts); the round order is the caller's.
 *  - **Honest about unstated data** — a front no document states in a round does not
 *    cross *into* or *out of* that round: silence is neither a fall nor a recovery
 *    (the §3 contract that keeps `below → unstated → below` one episode in v23). A
 *    crossing across a silent gap is attributed to the transition *into the round that
 *    reveals the new standing*; an episode that begins before the archive (a front
 *    stated below from round 1) has no in-sequence fall to pair, so it contributes no
 *    episode.
 *  - **Advisory** — the report names how many rounds the team's own floor stayed
 *    crossed between a fall and its recovery. It asserts no legal conclusion.
 *  - **Additive** — the latency carries its own `latency_hash`, namespaced apart
 *    from every `coherence_hash`, `movement_hash`, `trajectory_hash`,
 *    `shift_trajectory_hash`, `arc_hash`, `exposure_hash`, `persistence_hash`,
 *    `breadth_hash`, `recurrence_hash`, `volatility_hash`, `synchrony_hash`,
 *    `settling_hash`, and `onset_hash`, so computing it moves no golden.
 */

import type { NegotiationTier } from "../playbooks/custom-interpreter.js";
import { sha256Hex } from "../ingest/hash.js";
import { stableStringify } from "../engine/runner.js";
import type { PostureCoherence } from "./posture-coherence.js";

/** The team's acceptable floor — the one rung whose name means "below what we will accept." */
const BELOW_FLOOR: NegotiationTier = "below-acceptable";

/**
 * A front's recovery-latency class:
 *  - `open` — it fell below floor in-sequence and **never recovered** (an episode left
 *    open at the close — an unbounded latency);
 *  - `recovered` — every in-sequence fall closed with a recovery (≥ 1 closed episode,
 *    none open);
 *  - `steady` — stated, but never *fell* below floor in-sequence (no fall crossing to
 *    pair, including a front that recovered from a *pre-archive* exposure);
 *  - `unstated` — no document ever stated the front (§3: silence is not exposure).
 */
export type LatencyClass = "open" | "recovered" | "steady" | "unstated";

/** One fall-to-recovery span on a single front. */
export type CoherenceLatencyEpisode = {
  /** The 1-based round the front was first seen *below* floor (the fall's `to_round`). */
  fall_round: number;
  /** The 1-based round it was first seen back *at-or-above* floor (`null` when it never recovered). */
  recovery_round: number | null;
  /** The rounds it sat below floor: `recovery_round − fall_round` (`null` when open). */
  latency: number | null;
};

/** One negotiation front's whole-sequence recovery structure. */
export type CoherenceLatencyFront = {
  dimension: string;
  /** The binding floor at each round, in sequence order (`null` = unstated that round). */
  floors: (NegotiationTier | null)[];
  /** How many times the front's standing crossed the floor boundary (equals v24's per-front `crossings`). */
  crossings: number;
  /** The fall-to-recovery spans, in sequence order. */
  episodes: CoherenceLatencyEpisode[];
  /** The front's longest *closed* episode (`null` when none recovered). */
  max_latency: number | null;
  /** The recovery-latency class. */
  latency: LatencyClass;
};

export type CoherenceLatency = {
  /** How many rounds (coherences) the latency spans. */
  rounds: number;
  fronts: CoherenceLatencyFront[];
  /** Per-front tally by latency class. */
  class_counts: Record<LatencyClass, number>;
  /** Every front's crossing, summed — equals v24's grand total and v25/v26/v27's per-step sum. */
  total_crossings: number;
  /** How many fall-to-recovery episodes closed with a recovery (across all fronts). */
  recovered_count: number;
  /** How many episodes were left open (a fall that never recovered) — the gate-worthy count. */
  open_count: number;
  /** The slowest recovery across the deal — the longest *closed* episode (`null` when none recovered). */
  max_latency: number | null;
  /** The front owning {@link max_latency} (earliest on a tie; `null` when none recovered). */
  slowest_dimension: string | null;
  /** Did any front fall below floor in-sequence and never recover? The gate-worthy verdict. */
  unrecovered: boolean;
  /** SHA-256 over the canonical per-front episode set — additive, apart from every other hash. */
  latency_hash: string;
};

function emptyClassCounts(): Record<LatencyClass, number> {
  return { open: 0, recovered: 0, steady: 0, unstated: 0 };
}

/**
 * Scan one front's binding-floor path and pair its falls with the recoveries that
 * close them. A crossing is a transition between two *stated* rounds on opposite
 * sides of the floor — one `below-acceptable`, the other at-or-above it — in either
 * direction. An unstated round (`null`) is skipped: it neither counts as a crossing
 * nor resets the standing (silence is not a fall or a recovery, §3), so a crossing
 * across a silent gap is attributed to the round that *reveals* the new standing.
 *
 * A *fall* (at-or-above → below) opens an episode at the round it reveals; the next
 * *recovery* (below → at-or-above) closes it at the round it reveals. A recovery with
 * no open fall (the front was stated below from the start — its descent predates the
 * archive) opens no episode. A fall left unclosed at the end is an *open* episode
 * (`recovery_round` `null`). Returns the total crossing count (both directions — equal
 * to v24's per-front `crossings`), the episodes, and whether any round was stated.
 */
function scanEpisodes(floors: (NegotiationTier | null)[]): {
  crossings: number;
  episodes: CoherenceLatencyEpisode[];
  stated: boolean;
} {
  let crossings = 0;
  let stated = false;
  let prevBelow: boolean | null = null; // the last *stated* round's below-floor state
  let openFallRound: number | null = null; // the to_round of an in-progress fall
  const episodes: CoherenceLatencyEpisode[] = [];

  for (let i = 0; i < floors.length; i++) {
    const t = floors[i];
    if (t === null) continue; // silence: neither crosses nor resets the standing (§3)
    stated = true;
    const isBelow = t === BELOW_FLOOR;
    if (prevBelow !== null && prevBelow !== isBelow) {
      crossings += 1;
      const round = i + 1; // the round (1-based) that reveals the new standing
      if (isBelow) {
        // A fall: open an episode at the revealing round.
        openFallRound = round;
      } else if (openFallRound !== null) {
        // A recovery that closes an open fall.
        episodes.push({
          fall_round: openFallRound,
          recovery_round: round,
          latency: round - openFallRound,
        });
        openFallRound = null;
      }
      // A recovery with no open fall is a leading recovery (pre-archive descent) — no episode.
    }
    prevBelow = isBelow;
  }

  // A fall never closed by a recovery is an open episode (an unbounded latency).
  if (openFallRound !== null) {
    episodes.push({ fall_round: openFallRound, recovery_round: null, latency: null });
  }

  return { crossings, episodes, stated };
}

/**
 * Walk N cross-document posture coherences — the same bundle at round 1, round
 * 2, …, round N — and report, per negotiation front, how many rounds its binding
 * floor sat *below* the acceptable floor between a fall and the recovery that closes
 * it (`latency`), the deal's slowest such recovery (`max_latency`), and whether any
 * front fell and never recovered (`open_count`), not merely how many times it crossed
 * (v24's count) or where the first/last crossing fell (v26/v27's index).
 *
 * Pure and deterministic: fronts are matched by dimension and pinned by
 * `localeCompare`, the round order is the caller's, and `latency_hash` is over the
 * canonical per-front episode set, so the same N coherences in the same order always
 * yield identical bytes.
 *
 * Every coherence must have been computed against the **same** team positions (the
 * caller applies one active playbook to every document in every round); comparing
 * floors across different ladders is nonsense, the same way v13/v16 refuse a
 * cross-ladder diff. The CLI core ({@link computeCoherenceLatencyArtifacts}) enforces
 * this via the v15/v16 ladder guard before calling this.
 *
 * Requires at least two rounds — a recovery latency is a *between-round* span; a
 * single round has no transition to pair a fall and a recovery over.
 */
export async function computeCoherenceLatency(
  rounds: readonly PostureCoherence[],
): Promise<CoherenceLatency> {
  if (rounds.length < 2) {
    throw new Error(`a latency needs at least two rounds (got ${rounds.length})`);
  }

  const byDim = rounds.map((c) => new Map(c.dimensions.map((d) => [d.dimension, d])));
  const labels = Array.from(
    new Set(rounds.flatMap((c) => c.dimensions.map((d) => d.dimension))),
  ).sort((a, b) => a.localeCompare(b, "en"));

  const class_counts = emptyClassCounts();
  let total_crossings = 0;
  let recovered_count = 0;
  let open_count = 0;
  let max_latency: number | null = null;
  let slowest_dimension: string | null = null;

  const fronts: CoherenceLatencyFront[] = labels.map((dimension) => {
    const floors = byDim.map((m) => m.get(dimension)?.weakest_tier ?? null);
    const { crossings, episodes, stated } = scanEpisodes(floors);
    total_crossings += crossings;

    let frontMax: number | null = null;
    let hasOpen = false;
    let hasClosed = false;
    for (const ep of episodes) {
      if (ep.recovery_round === null) {
        hasOpen = true;
        open_count += 1;
      } else {
        hasClosed = true;
        recovered_count += 1;
        const lat = ep.latency!;
        if (frontMax === null || lat > frontMax) frontMax = lat;
      }
    }

    // The slowest recovery across the deal: the first front (in localeCompare order)
    // whose closed episode reaches the max wins a tie (`>` keeps the earliest).
    if (frontMax !== null && (max_latency === null || frontMax > max_latency)) {
      max_latency = frontMax;
      slowest_dimension = dimension;
    }

    const latency: LatencyClass = !stated
      ? "unstated"
      : hasOpen
        ? "open"
        : hasClosed
          ? "recovered"
          : "steady";
    class_counts[latency] += 1;

    return { dimension, floors, crossings, episodes, max_latency: frontMax, latency };
  });

  const latency_hash = await sha256Hex(
    stableStringify({
      rounds: rounds.length,
      fronts: fronts.map((f) => ({
        dimension: f.dimension,
        floors: f.floors,
        crossings: f.crossings,
        episodes: f.episodes.map((e) => ({
          fall_round: e.fall_round,
          recovery_round: e.recovery_round,
          latency: e.latency,
        })),
        max_latency: f.max_latency,
        latency: f.latency,
      })),
    }),
  );

  return {
    rounds: rounds.length,
    fronts,
    class_counts,
    total_crossings,
    recovered_count,
    open_count,
    max_latency,
    slowest_dimension,
    unrecovered: open_count > 0,
    latency_hash,
  };
}

/**
 * Did any front fall below the team's acceptable floor in-sequence and **never
 * recover** — a fall left unclosed at the close, an unbounded recovery latency? The
 * CI gate predicate — the *recovery-latency* counterpart to v24's per-front
 * instability gate, v26's still-moving-at-the-close gate, and v27's
 * already-moving-at-the-open gate. Unlike `exposureVolatile` (a front crossing ≥ 2
 * times), `exposureUnsettled` (the *last* crossing on the *final* step), and
 * `exposureEarlyOnset` (the *first* crossing on the *opening* step), this fires on a
 * fall that never closed with a recovery. It is **distinct from v21's `exposureOpen`**:
 * v21 fires on a front whose *current standing* is below floor at the last round —
 * including a front stated below from round 1 that never *fell* in-sequence; v28 fires
 * only on a front whose in-sequence *fall* never closed. It needs no tuning — an
 * unrecovered fall *is* an unbounded latency. A front that fell and recovered, however
 * slowly, clears it. A consumer wanting to flag a slow-but-recovered episode reads
 * `max_latency` instead.
 */
export function exposureUnrecovered(latency: CoherenceLatency): boolean {
  return latency.open_count > 0;
}

/**
 * Serialize a {@link CoherenceLatency} to a stable, pretty-printed JSON string. The
 * key order is fixed and the front order is already pinned by
 * {@link computeCoherenceLatency}, so the same latency always yields identical bytes —
 * the `latency_hash` it carries is the canonical fingerprint, reproducible from
 * `fronts`.
 */
export function buildCoherenceLatencyJson(latency: CoherenceLatency): string {
  return JSON.stringify(
    {
      schema: "vaulytica.posture-latency.v1",
      latency_hash: latency.latency_hash,
      rounds: latency.rounds,
      class_counts: latency.class_counts,
      total_crossings: latency.total_crossings,
      recovered_count: latency.recovered_count,
      open_count: latency.open_count,
      max_latency: latency.max_latency,
      slowest_dimension: latency.slowest_dimension,
      unrecovered: latency.unrecovered,
      fronts: latency.fronts.map((f) => ({
        dimension: f.dimension,
        floors: f.floors,
        crossings: f.crossings,
        episodes: f.episodes.map((e) => ({
          fall_round: e.fall_round,
          recovery_round: e.recovery_round,
          latency: e.latency,
        })),
        max_latency: f.max_latency,
        latency: f.latency,
      })),
    },
    null,
    2,
  );
}

/**
 * Render a {@link CoherenceLatency} as human-readable terminal lines: the slowest
 * recovery (the front and its rounds below floor, or steady-throughout when nothing
 * fell-and-recovered), the unrecovered-episode count, then one line per front that
 * holds an episode (its class and its fall-to-recovery spans). A `steady` or
 * `unstated` front is counted but never listed (§3 honesty). Lives beside its JSON
 * sibling so the CLI renders the latency from one definition.
 */
export function renderCoherenceLatencySummary(latency: CoherenceLatency): string {
  const cc = latency.class_counts;
  const n = latency.rounds;
  const lines = [
    `\nCoherence exposure recovery latency across ${n} rounds (rounds below floor per fall-to-recovery episode):`,
    latency.max_latency === null
      ? `  slowest recovery: none — no front fell below the floor and recovered in-sequence.`
      : `  slowest recovery: ${latency.slowest_dimension} — sat below floor for ${latency.max_latency} round${latency.max_latency === 1 ? "" : "s"} before recovering.`,
    `  episodes: ${latency.recovered_count} recovered, ${latency.open_count} unrecovered (a fall that never came back); ${cc.steady} steady, ${cc.unstated} never stated.`,
  ];
  for (const f of latency.fronts) {
    if (f.latency !== "open" && f.latency !== "recovered") continue;
    const path = f.floors.map((t) => t ?? "—").join(" → ");
    const spans = f.episodes
      .map((e) =>
        e.recovery_round === null
          ? `fell round ${e.fall_round}, never recovered`
          : `fell round ${e.fall_round} → recovered round ${e.recovery_round} (${e.latency} round${e.latency === 1 ? "" : "s"} below)`,
      )
      .join("; ");
    const mark = f.latency === "open" ? "⚠" : "·";
    lines.push(`  ${mark} ${f.dimension}: ${f.latency} — ${spans} (${path}).`);
  }
  lines.push(`  latency_hash: ${latency.latency_hash}`);
  return lines.join("\n") + "\n";
}
