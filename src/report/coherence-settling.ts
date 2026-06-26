/**
 * Cross-document negotiation-posture **exposure settling** — the *latest*
 * round-transition at which any front's binding floor *crossed* the acceptable
 * floor, and whether the package was *still moving* across the floor at the close
 * (spec-v26).
 *
 * v24 ({@link computeCoherenceVolatility}) counts, per front, how many times its
 * standing crossed the floor across the deal (`crossings`). v25
 * ({@link computeCoherenceSynchrony}) re-buckets those same crossings by *step*:
 * per round-transition, how many fronts crossed at once (`crossing_fronts`).
 * Both reduce the crossings to a **count** — and a count throws away *when the
 * last crossing happened*. Two deals with the identical per-front and per-step
 * crossing counts can be opposites on the one axis a deal lead asks at the close:
 * **did the package stop crossing the floor before signing, or was it still in
 * motion at the final round?**
 *
 * - A deal whose only crossing was Cap falling in round 1→2, then five rounds of
 *   stability, *settled early*: the package quieted long before the close.
 * - A deal whose only crossing was Cap falling in the *final* round is the same to
 *   v24 (Cap crossed once, monotone) and to v25 (one isolated step, not
 *   synchronized) — yet it is **unsettled**: the floor was still being crossed as
 *   the deal closed.
 *
 * That is a missing **axis**: the *time-of-last-movement* dimension of the same
 * crossing data. Where v24 sums crossings down the front axis and v25 sums them
 * down the step axis, v26 reads the **index** of the last step any front crossed —
 * the deal's `settling_round` — and the length of the quiet tail after it
 * (`quiet_tail`), and gates on whether the *final* transition itself crossed the
 * floor (`unsettled`).
 *
 * It is a reduction of the **same** floor crossings v24/v25 count — `total_crossings`
 * equals v24's grand total and v25's per-step sum by construction. It adds **no**
 * posture math beyond locating the last crossing across the `below-acceptable` rung
 * v10 defines, over the binding floors v12 derived and v22/v24/v25 already read. The
 * posture filter (spec-v10 §3), restated:
 *  - **Deterministic** — same N coherences in the same order → identical
 *    `settling_hash`, on any machine. The round order is the caller's; the
 *    per-transition crossed-dimension lists are pinned by `localeCompare(_, "en")`
 *    (the same order the trajectory/exposure/volatility/synchrony functions pin
 *    fronts).
 *  - **Honest about unstated data** — a front no document states in a round does not
 *    cross *into* or *out of* that round: silence is neither a fall nor a recovery
 *    (the §3 contract that keeps `below → unstated → below` zero crossings in v24/v25).
 *    A crossing across a silent gap is attributed to the transition *into the round
 *    that reveals the new standing*, so a final round left entirely unstated is
 *    **not** a crossing — the deal is `settled`, never spuriously unsettled by silence.
 *  - **Advisory** — the report names the round the team's own floor was last crossed.
 *    It asserts no legal conclusion.
 *  - **Additive** — the settling carries its own `settling_hash`, namespaced apart
 *    from every `coherence_hash`, `movement_hash`, `trajectory_hash`,
 *    `shift_trajectory_hash`, `arc_hash`, `exposure_hash`, `persistence_hash`,
 *    `breadth_hash`, `recurrence_hash`, `volatility_hash`, and `synchrony_hash`, so
 *    computing it moves no golden.
 */

import type { NegotiationTier } from "../playbooks/custom-interpreter.js";
import { sha256Hex } from "../ingest/hash.js";
import { stableStringify } from "../engine/runner.js";
import type { PostureCoherence } from "./posture-coherence.js";

/** The team's acceptable floor — the one rung whose name means "below what we will accept." */
const BELOW_FLOOR: NegotiationTier = "below-acceptable";

/**
 * One round-transition's settling state:
 *  - `active` — **at least one** front crossed the floor in this step (the package
 *    was still moving across the floor here);
 *  - `still` — no front crossed the floor this step (the package held steady).
 */
export type SettlingState = "active" | "still";

/** One round-transition's movement, read for *when* the package last crossed the floor. */
export type CoherenceSettlingTransition = {
  /** The 1-based round this step starts at, in sequence order. */
  from_round: number;
  /** The 1-based round this step ends at (`from_round + 1`). */
  to_round: number;
  /** How many fronts crossed the floor boundary in this step (falls and recoveries alike). */
  crossing_fronts: number;
  /** The fronts that crossed this step, pinned by `localeCompare` (so the list is deterministic). */
  crossed_dimensions: string[];
  /** Whether any front crossed the floor in this step. */
  state: SettlingState;
};

export type CoherenceSettling = {
  /** How many rounds (coherences) the settling spans. */
  rounds: number;
  /** The per-transition movement, in sequence order (length = rounds − 1). */
  per_transition: CoherenceSettlingTransition[];
  /** Every front's crossing, summed over the steps — equals v24's grand total and v25's per-step sum. */
  total_crossings: number;
  /** The 1-based `to_round` of the *latest* step any front crossed the floor — the round the package last moved (`null` when none ever crossed). */
  settling_round: number | null;
  /** How many consecutive trailing steps were `still` — the rounds of stability after the last crossing (= all steps when none ever crossed). */
  quiet_tail: number;
  /** How many steps were `active` (at least one front crossed). */
  active_count: number;
  /** Did the *final* transition cross the floor — was the package still moving at the close? The gate-worthy verdict. */
  unsettled: boolean;
  /** SHA-256 over the canonical per-transition set — additive, apart from every other hash. */
  settling_hash: string;
};

/**
 * Walk N cross-document posture coherences — the same bundle at round 1, round
 * 2, …, round N — and report *when the package last crossed the acceptable
 * floor*: the latest round-transition any front crossed (`settling_round`), the
 * length of the quiet tail of stable rounds after it (`quiet_tail`), and whether
 * the *final* transition itself crossed the floor (`unsettled` — the package was
 * still in motion at the close).
 *
 * Pure and deterministic: the round order is the caller's, the per-transition
 * crossed-dimension lists are pinned by `localeCompare`, and `settling_hash` is
 * over the canonical per-transition set, so the same N coherences in the same order
 * always yield identical bytes.
 *
 * A crossing is a transition between two *stated* rounds on opposite sides of the
 * floor (one `below-acceptable`, the other at-or-above it), in either direction. An
 * unstated round is skipped: it neither crosses nor resets the standing (§3), so a
 * crossing across a silent gap is attributed to the transition into the round that
 * *reveals* the new standing — never to the silent step. A final round left
 * entirely unstated reveals no crossing, so the deal is `settled` (silence at the
 * close is stability, not movement). Summed over all transitions, the crossing
 * count equals v24's per-front total and v25's per-step total (`total_crossings`):
 * v26 reads the same crossings for the *index* of the last one.
 *
 * Every coherence must have been computed against the **same** team positions (the
 * caller applies one active playbook to every document in every round); comparing
 * floors across different ladders is nonsense, the same way v13/v16 refuse a
 * cross-ladder diff. The CLI core ({@link computeCoherenceSettlingArtifacts})
 * enforces this via the v15/v16 ladder guard before calling this.
 *
 * Requires at least two rounds — settling is a *between-round* movement; a single
 * round has no transition to locate a crossing over.
 */
export async function computeCoherenceSettling(
  rounds: readonly PostureCoherence[],
): Promise<CoherenceSettling> {
  if (rounds.length < 2) {
    throw new Error(`a settling needs at least two rounds (got ${rounds.length})`);
  }

  const byDim = rounds.map((c) => new Map(c.dimensions.map((d) => [d.dimension, d])));
  const labels = Array.from(
    new Set(rounds.flatMap((c) => c.dimensions.map((d) => d.dimension))),
  ).sort((a, b) => a.localeCompare(b, "en"));

  // One bucket per round-transition (round k → round k+1, k = 1…N−1). Each front's
  // crossing is attributed to the step into the round that *reveals* the new
  // standing (the same attribution v24/v25 use), so the per-transition total
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
  let settling_round: number | null = null;

  const per_transition: CoherenceSettlingTransition[] = crossedByTransition.map((dims, idx) => {
    // The labels were iterated in localeCompare order, so `dims` is already
    // pinned; the explicit sort keeps the list deterministic regardless.
    dims.sort((a, b) => a.localeCompare(b, "en"));
    const crossing_fronts = dims.length;
    total_crossings += crossing_fronts;
    const state: SettlingState = crossing_fronts > 0 ? "active" : "still";
    if (state === "active") {
      active_count += 1;
      // The latest active step wins: a plain forward scan keeps the last one.
      settling_round = idx + 2;
    }
    return {
      from_round: idx + 1,
      to_round: idx + 2,
      crossing_fronts,
      crossed_dimensions: dims,
      state,
    };
  });

  // The quiet tail is the run of `still` steps after the last `active` one — the
  // rounds of stability the package held before the close. When nothing ever
  // crossed, every step is quiet (the whole sequence is the tail).
  const quiet_tail =
    settling_round === null ? per_transition.length : per_transition.length - (settling_round - 1);
  // Unsettled iff the *final* transition crossed the floor — the package was still
  // moving across the floor as the deal closed (equivalently, quiet_tail === 0 with
  // at least one crossing).
  const last = per_transition[per_transition.length - 1];
  const unsettled = last !== undefined && last.state === "active";

  const settling_hash = await sha256Hex(
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
    settling_round,
    quiet_tail,
    active_count,
    unsettled,
    settling_hash,
  };
}

/**
 * Was the package *still crossing* the acceptable floor in the **final** round —
 * did it never settle before the close? The CI gate predicate — the
 * *time-of-last-movement* counterpart to v24's per-front instability gate and
 * v25's per-step co-movement gate. Unlike `exposureVolatile` (which fires on any
 * single front crossing the floor ≥ 2 times *across the whole deal*) and
 * `exposureSynchronized` (which fires on two or more fronts crossing in *one*
 * step), this fires when the *last* transition crossed the floor at all: a deal
 * still in motion at signing. It needs no tuning — a crossing in the final round
 * *is* an unsettled close. A deal whose crossings all fell in earlier rounds
 * (quiet at the close) clears it, even if it had a volatile or synchronized step.
 */
export function exposureUnsettled(settling: CoherenceSettling): boolean {
  return settling.unsettled;
}

/**
 * Serialize a {@link CoherenceSettling} to a stable, pretty-printed JSON string.
 * The key order is fixed and the per-transition series is already in sequence order
 * with `localeCompare`-pinned dimension lists, so the same settling always yields
 * identical bytes — the `settling_hash` it carries is the canonical fingerprint,
 * reproducible from `per_transition`.
 */
export function buildCoherenceSettlingJson(settling: CoherenceSettling): string {
  return JSON.stringify(
    {
      schema: "vaulytica.posture-settling.v1",
      settling_hash: settling.settling_hash,
      rounds: settling.rounds,
      total_crossings: settling.total_crossings,
      settling_round: settling.settling_round,
      quiet_tail: settling.quiet_tail,
      active_count: settling.active_count,
      unsettled: settling.unsettled,
      per_transition: settling.per_transition.map((t) => ({
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
 * Render a {@link CoherenceSettling} as human-readable terminal lines: the
 * settling round (the round the package last crossed the floor), the length of the
 * quiet tail after it, and whether the close was unsettled, then one line per step
 * marking the active ones. Lives beside its JSON sibling so the CLI renders the
 * settling from one definition.
 */
export function renderCoherenceSettlingSummary(settling: CoherenceSettling): string {
  const n = settling.rounds;
  const lines = [
    `\nCoherence exposure settling across ${n} rounds (when the package last crossed the floor):`,
    settling.settling_round === null
      ? `  settling: no front ever crossed the floor — the package was steady throughout.`
      : settling.unsettled
        ? `  settling: UNSETTLED — the floor was last crossed in round ${settling.settling_round - 1}→${settling.settling_round}, the final transition (still moving at the close).`
        : `  settling: settled at round ${settling.settling_round} — the floor was last crossed in round ${settling.settling_round - 1}→${settling.settling_round}, then ${settling.quiet_tail} steady step${settling.quiet_tail === 1 ? "" : "s"} to the close.`,
    `  active steps (a front crossed the floor): ${settling.active_count} of ${settling.per_transition.length}; quiet tail: ${settling.quiet_tail}.`,
  ];
  for (const t of settling.per_transition) {
    const dims = t.crossing_fronts === 0 ? "—" : t.crossed_dimensions.join(", ");
    const mark = t.state === "active" ? "•" : "·";
    lines.push(
      `  ${mark} round ${t.from_round}→${t.to_round}: ${t.crossing_fronts} front${t.crossing_fronts === 1 ? "" : "s"} crossed (${dims}).`,
    );
  }
  lines.push(`  settling_hash: ${settling.settling_hash}`);
  return lines.join("\n") + "\n";
}
