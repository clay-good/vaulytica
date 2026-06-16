/**
 * Cross-document negotiation-posture **exposure onset** — the *earliest*
 * round-transition at which any front's binding floor *crossed* the acceptable
 * floor, and whether the package was *already moving* across the floor at the very
 * opening (spec-v27).
 *
 * v24 ({@link computeCoherenceVolatility}) counts, per front, how many times its
 * standing crossed the floor across the deal (`crossings`). v25
 * ({@link computeCoherenceSynchrony}) re-buckets those same crossings by *step*:
 * per round-transition, how many fronts crossed at once (`crossing_fronts`). v26
 * ({@link computeCoherenceSettling}) reads the **index** of the *last* crossing —
 * the deal's `settling_round`, and whether the *final* transition crossed
 * (`unsettled`). All three either reduce the crossings to a count or read the
 * **latest** of them — and the latest throws away *when the first crossing
 * happened*. Two deals with the identical settling round (both still moving at the
 * close) can be opposites on the one axis a deal lead asks opening a close:
 * **how many rounds did the package hold the floor before its first slip — did it
 * start clean, or degrade from the opening?**
 *
 * - A deal whose crossings were a front falling in round 1→2 *and* the final round
 *   degraded *from the opening*: no grace period, exposed from the first exchange.
 * - A deal whose crossings were a front falling in round 4→5 *and* the final round
 *   is identical to the first under v26 (both `unsettled`, both `settling_round`
 *   the final step) — yet it held a clean lead-in of three rounds before its first
 *   slip.
 *
 * That is a missing **axis**: the *time-of-first-movement* dimension of the same
 * crossing data. Where v24 sums crossings down the front axis, v25 sums them down
 * the step axis, and v26 reads the **maximum** crossing index, v27 reads the
 * **minimum** crossing index — the deal's `onset_round` — the length of the clean
 * lead-in of steady rounds *before* it (`lead_in`), and gates on whether the
 * *first* transition itself crossed the floor (`early_onset`). The first and last
 * crossing indices are independent whenever a deal crosses the floor more than
 * once, so v27 separates deals v26 reports identically; they coincide only in the
 * degenerate single-crossing case.
 *
 * It is a reduction of the **same** floor crossings v24/v25/v26 read — `total_crossings`
 * equals v24's grand total, v25's per-step sum, and v26's per-step sum by construction.
 * It adds **no** posture math beyond locating the first crossing across the
 * `below-acceptable` rung v10 defines, over the binding floors v12 derived and
 * v22/v24/v25/v26 already read. The posture filter (spec-v10 §3), restated:
 *  - **Deterministic** — same N coherences in the same order → identical
 *    `onset_hash`, on any machine. The round order is the caller's; the
 *    per-transition crossed-dimension lists are pinned by `localeCompare(_, "en")`
 *    (the same order the trajectory/exposure/volatility/synchrony/settling functions pin
 *    fronts).
 *  - **Honest about unstated data** — a front no document states in a round does not
 *    cross *into* or *out of* that round: silence is neither a fall nor a recovery
 *    (the §3 contract that keeps `below → unstated → below` zero crossings in v24/v25/v26).
 *    A crossing across a silent gap is attributed to the transition *into the round
 *    that reveals the new standing*, so an opening round left entirely unstated is
 *    **not** an onset — the lead-in is honest, never spuriously early because of silence.
 *  - **Advisory** — the report names the round the team's own floor was first crossed.
 *    It asserts no legal conclusion.
 *  - **Additive** — the onset carries its own `onset_hash`, namespaced apart
 *    from every `coherence_hash`, `movement_hash`, `trajectory_hash`,
 *    `shift_trajectory_hash`, `arc_hash`, `exposure_hash`, `persistence_hash`,
 *    `breadth_hash`, `recurrence_hash`, `volatility_hash`, `synchrony_hash`, and
 *    `settling_hash`, so computing it moves no golden.
 */

import type { NegotiationTier } from "../playbooks/custom-interpreter.js";
import { sha256Hex } from "../ingest/hash.js";
import { stableStringify } from "../engine/runner.js";
import type { PostureCoherence } from "./posture-coherence.js";

/** The team's acceptable floor — the one rung whose name means "below what we will accept." */
const BELOW_FLOOR: NegotiationTier = "below-acceptable";

/**
 * One round-transition's onset state:
 *  - `active` — **at least one** front crossed the floor in this step (the package
 *    moved across the floor here);
 *  - `still` — no front crossed the floor this step (the package held steady).
 */
export type OnsetState = "active" | "still";

/** One round-transition's movement, read for *when* the package first crossed the floor. */
export type CoherenceOnsetTransition = {
  /** The 1-based round this step starts at, in sequence order. */
  from_round: number;
  /** The 1-based round this step ends at (`from_round + 1`). */
  to_round: number;
  /** How many fronts crossed the floor boundary in this step (falls and recoveries alike). */
  crossing_fronts: number;
  /** The fronts that crossed this step, pinned by `localeCompare` (so the list is deterministic). */
  crossed_dimensions: string[];
  /** Whether any front crossed the floor in this step. */
  state: OnsetState;
};

export type CoherenceOnset = {
  /** How many rounds (coherences) the onset spans. */
  rounds: number;
  /** The per-transition movement, in sequence order (length = rounds − 1). */
  per_transition: CoherenceOnsetTransition[];
  /** Every front's crossing, summed over the steps — equals v24's grand total and v25/v26's per-step sum. */
  total_crossings: number;
  /** The 1-based `to_round` of the *earliest* step any front crossed the floor — the round the package first moved (`null` when none ever crossed). */
  onset_round: number | null;
  /** How many consecutive leading steps were `still` — the rounds of stability before the first crossing (= all steps when none ever crossed). */
  lead_in: number;
  /** How many steps were `active` (at least one front crossed). */
  active_count: number;
  /** Did the *first* transition cross the floor — was the package already moving from the opening? The gate-worthy verdict. */
  early_onset: boolean;
  /** SHA-256 over the canonical per-transition set — additive, apart from every other hash. */
  onset_hash: string;
};

/**
 * Walk N cross-document posture coherences — the same bundle at round 1, round
 * 2, …, round N — and report *when the package first crossed the acceptable
 * floor*: the earliest round-transition any front crossed (`onset_round`), the
 * length of the clean lead-in of stable rounds before it (`lead_in`), and whether
 * the *first* transition itself crossed the floor (`early_onset` — the package was
 * already in motion from the opening).
 *
 * Pure and deterministic: the round order is the caller's, the per-transition
 * crossed-dimension lists are pinned by `localeCompare`, and `onset_hash` is
 * over the canonical per-transition set, so the same N coherences in the same order
 * always yield identical bytes.
 *
 * A crossing is a transition between two *stated* rounds on opposite sides of the
 * floor (one `below-acceptable`, the other at-or-above it), in either direction. An
 * unstated round is skipped: it neither crosses nor resets the standing (§3), so a
 * crossing across a silent gap is attributed to the transition into the round that
 * *reveals* the new standing — never to the silent step. An opening round left
 * entirely unstated reveals no crossing, so the lead-in is honest (silence at the
 * open is not an onset). Summed over all transitions, the crossing count equals
 * v24's per-front total and v25/v26's per-step total (`total_crossings`): v27 reads
 * the same crossings for the *index* of the first one.
 *
 * Every coherence must have been computed against the **same** team positions (the
 * caller applies one active playbook to every document in every round); comparing
 * floors across different ladders is nonsense, the same way v13/v16 refuse a
 * cross-ladder diff. The CLI core ({@link computeCoherenceOnsetArtifacts})
 * enforces this via the v15/v16 ladder guard before calling this.
 *
 * Requires at least two rounds — onset is a *between-round* movement; a single
 * round has no transition to locate a crossing over.
 */
export async function computeCoherenceOnset(
  rounds: readonly PostureCoherence[],
): Promise<CoherenceOnset> {
  if (rounds.length < 2) {
    throw new Error(`an onset needs at least two rounds (got ${rounds.length})`);
  }

  const byDim = rounds.map((c) => new Map(c.dimensions.map((d) => [d.dimension, d])));
  const labels = Array.from(
    new Set(rounds.flatMap((c) => c.dimensions.map((d) => d.dimension))),
  ).sort((a, b) => a.localeCompare(b, "en"));

  // One bucket per round-transition (round k → round k+1, k = 1…N−1). Each front's
  // crossing is attributed to the step into the round that *reveals* the new
  // standing (the same attribution v24/v25/v26 use), so the per-transition total
  // re-buckets v24's per-front crossings.
  const crossedByTransition: string[][] = Array.from({ length: rounds.length - 1 }, () => []);

  for (const dimension of labels) {
    const floors = byDim.map((m) => m.get(dimension)?.weakest_tier ?? null);
    let prevBelow: boolean | null = null; // the last *stated* round's below-floor state
    for (let i = 0; i < floors.length; i++) {
      const t = floors[i];
      if (t === null) continue; // silence: neither crosses nor resets the standing (§3)
      const isBelow = t === BELOW_FLOOR;
      // A flip vs. the previous stated round is a crossing on the step ending at
      // round i+1 — i.e. transition (i → i+1), held at per-transition index i−1.
      if (prevBelow !== null && prevBelow !== isBelow) {
        crossedByTransition[i - 1]!.push(dimension);
      }
      prevBelow = isBelow;
    }
  }

  let total_crossings = 0;
  let active_count = 0;
  let onset_round: number | null = null;

  const per_transition: CoherenceOnsetTransition[] = crossedByTransition.map((dims, idx) => {
    // The labels were iterated in localeCompare order, so `dims` is already
    // pinned; the explicit sort keeps the list deterministic regardless.
    dims.sort((a, b) => a.localeCompare(b, "en"));
    const crossing_fronts = dims.length;
    total_crossings += crossing_fronts;
    const state: OnsetState = crossing_fronts > 0 ? "active" : "still";
    if (state === "active") {
      active_count += 1;
      // The earliest active step wins: a forward scan keeps the first one only.
      if (onset_round === null) onset_round = idx + 2;
    }
    return {
      from_round: idx + 1,
      to_round: idx + 2,
      crossing_fronts,
      crossed_dimensions: dims,
      state,
    };
  });

  // The lead-in is the run of `still` steps before the first `active` one — the
  // rounds of stability the package held before its first slip. When nothing ever
  // crossed, every step is quiet (the whole sequence is the lead-in).
  const lead_in = onset_round === null ? per_transition.length : onset_round - 2;
  // Early onset iff the *first* transition crossed the floor — the package was
  // already moving across the floor from the opening (equivalently, lead_in === 0
  // with at least one crossing).
  const first = per_transition[0];
  const early_onset = first !== undefined && first.state === "active";

  const onset_hash = await sha256Hex(
    stableStringify({
      rounds: rounds.length,
      per_transition: per_transition.map((t) => ({
        from_round: t.from_round,
        to_round: t.to_round,
        crossing_fronts: t.crossing_fronts,
        crossed_dimensions: t.crossed_dimensions,
        state: t.state,
      })),
    }),
  );

  return {
    rounds: rounds.length,
    per_transition,
    total_crossings,
    onset_round,
    lead_in,
    active_count,
    early_onset,
    onset_hash,
  };
}

/**
 * Was the package *already crossing* the acceptable floor in the **first** round —
 * did it degrade from the very opening with no grace period? The CI gate predicate
 * — the *time-of-first-movement* counterpart to v24's per-front instability gate,
 * v25's per-step co-movement gate, and v26's still-moving-at-the-close gate. Unlike
 * `exposureVolatile` (which fires on any single front crossing the floor ≥ 2 times
 * *across the whole deal*), `exposureSynchronized` (≥ 2 fronts crossing in *one*
 * step), and `exposureUnsettled` (the *last* transition crossed), this fires when
 * the *first* transition crossed the floor at all: a deal already in motion at the
 * opening. It needs no tuning — a crossing in the opening round *is* an early onset.
 * A deal whose crossings all fell in later rounds (a clean lead-in) clears it, even
 * if it had a volatile, synchronized, or unsettled step.
 */
export function exposureEarlyOnset(onset: CoherenceOnset): boolean {
  return onset.early_onset;
}

/**
 * Serialize a {@link CoherenceOnset} to a stable, pretty-printed JSON string.
 * The key order is fixed and the per-transition series is already in sequence order
 * with `localeCompare`-pinned dimension lists, so the same onset always yields
 * identical bytes — the `onset_hash` it carries is the canonical fingerprint,
 * reproducible from `per_transition`.
 */
export function buildCoherenceOnsetJson(onset: CoherenceOnset): string {
  return JSON.stringify(
    {
      schema: "vaulytica.posture-onset.v1",
      onset_hash: onset.onset_hash,
      rounds: onset.rounds,
      total_crossings: onset.total_crossings,
      onset_round: onset.onset_round,
      lead_in: onset.lead_in,
      active_count: onset.active_count,
      early_onset: onset.early_onset,
      per_transition: onset.per_transition.map((t) => ({
        from_round: t.from_round,
        to_round: t.to_round,
        crossing_fronts: t.crossing_fronts,
        crossed_dimensions: t.crossed_dimensions,
        state: t.state,
      })),
    },
    null,
    2,
  );
}

/**
 * Render a {@link CoherenceOnset} as human-readable terminal lines: the
 * onset round (the round the package first crossed the floor), the length of the
 * clean lead-in before it, and whether the opening was an early onset, then one line
 * per step marking the active ones. Lives beside its JSON sibling so the CLI renders
 * the onset from one definition.
 */
export function renderCoherenceOnsetSummary(onset: CoherenceOnset): string {
  const n = onset.rounds;
  const lines = [
    `\nCoherence exposure onset across ${n} rounds (when the package first crossed the floor):`,
    onset.onset_round === null
      ? `  onset: no front ever crossed the floor — the package was steady throughout.`
      : onset.early_onset
        ? `  onset: EARLY — the floor was first crossed in round ${onset.onset_round - 1}→${onset.onset_round}, the opening transition (already moving from the start).`
        : `  onset: at round ${onset.onset_round} — the floor was first crossed in round ${onset.onset_round - 1}→${onset.onset_round}, after ${onset.lead_in} steady step${onset.lead_in === 1 ? "" : "s"} of clean lead-in.`,
    `  active steps (a front crossed the floor): ${onset.active_count} of ${onset.per_transition.length}; clean lead-in: ${onset.lead_in}.`,
  ];
  for (const t of onset.per_transition) {
    const dims = t.crossing_fronts === 0 ? "—" : t.crossed_dimensions.join(", ");
    const mark = t.state === "active" ? "•" : "·";
    lines.push(
      `  ${mark} round ${t.from_round}→${t.to_round}: ${t.crossing_fronts} front${t.crossing_fronts === 1 ? "" : "s"} crossed (${dims}).`,
    );
  }
  lines.push(`  onset_hash: ${onset.onset_hash}`);
  return lines.join("\n") + "\n";
}
