/**
 * Cross-document negotiation-posture **exposure cadence** — per front, the *rate* at which its binding
 * floor *flips across* the acceptable floor: how many of its transition opportunities were floor
 * **crossings** (`crossings`) out of the transitions between the rounds that *stated* it
 * (`transitions`), the resulting flip rate (`cadence`), the deal's busiest-churning front
 * (`max_cadence`), and whether any front crossed the floor for a strict **majority** of its
 * transitions — a front that flips more often than it holds (spec-v39).
 *
 * This is the **churn mirror of v31's dwell**. v31 ({@link computeCoherenceTenure}) reads the
 * *occupancy* axis: per front, what *share* of its stated rounds sat below floor — how **long** a
 * front is an unaccepted position. v39 reads the orthogonal *churn* axis: not how long it stays on a
 * side, but how **often** it changes sides. Two fronts v31 reports identically (both `minority` —
 * below floor in half their stated rounds) can be opposites on this axis:
 *
 * - The **steady dip.** Cap is below floor for rounds 1–3 of 6, then holds above for 4–6: 3 of 6
 *   stated rounds below (a 50% tenure, `minority`), but it crosses the floor exactly **once** over 5
 *   transitions — a 20% cadence, **settled**. The counterparty conceded it once and the standing held.
 * - The **flickering front.** Term is below floor in rounds 1, 3, 5 and above in 2, 4, 6: also 3 of 6
 *   stated rounds below (the same 50% tenure, `minority` to v31), but it crosses the floor on **all
 *   five** transitions — a 100% cadence, **oscillating**. It can never settle on a side; every round
 *   reopens what the last one closed.
 *
 * v31 cannot tell these apart — same dwell, opposite churn. v24 ({@link computeCoherenceVolatility})
 * counts the same crossings but gates on the **raw count** (≥ 2 crossings ⟹ `volatile`), blind to
 * *opportunity*: a front that crosses twice in 20 transitions trips v24's gate yet is `settled` here
 * (a 10% rate), while a front that crosses once in one transition is `monotone` to v24 yet
 * `oscillating` here (a 100% rate). v39 reads neither the count (v24) nor the dwell (v31) but the
 * **flip rate** — crossings normalized by the transitions that could have carried one.
 *
 * It adds **no** posture math beyond a per-front crossing count over the `below-acceptable` rung v10
 * defines, taken over the binding floors v12 derived and v24 already counts. `total_crossings` equals
 * v24's crossings summed across fronts by construction. The posture filter (spec-v10 §3), restated:
 *  - **Deterministic** — same N coherences in the same order → identical `cadence_hash`, on any
 *    machine. Fronts are pinned by `localeCompare(_, "en")` (the same order the
 *    trajectory/exposure/tenure/volatility functions use); the round order is the caller's. The
 *    busiest-cadence pick is decided by *integer cross-multiplication* (`crossings × transitions` of
 *    the two fronts), never a float comparison, so the ranking is exact and platform-independent.
 *  - **Honest about unstated data** — a front no document states in a round contributes no transition
 *    into or out of it: silence is neither a crossing nor a held side (the §3 contract that keeps
 *    `below → unstated → below` zero crossings in v24/v35). The denominator is the transitions between
 *    consecutive *stated* rounds, so a crossing across a silent gap is attributed to the transition
 *    into the round that *reveals* the new standing — never diluted by the silent rounds. A front
 *    stated in fewer than two rounds has no transition and carries no cadence (`static`), never ranked.
 *  - **Advisory** — the report names how often each front flipped across the team's own floor. It
 *    asserts no legal conclusion.
 *  - **Additive** — the cadence carries its own `cadence_hash`, namespaced apart from every
 *    `coherence_hash`, `movement_hash`, `trajectory_hash`, `shift_trajectory_hash`, `arc_hash`,
 *    `exposure_hash`, `persistence_hash`, `breadth_hash`, `recurrence_hash`, `volatility_hash`,
 *    `synchrony_hash`, `settling_hash`, `onset_hash`, `latency_hash`, `concurrency_hash`,
 *    `relapse_hash`, `tenure_hash`, `affinity_hash`, `recovery_affinity_hash`, `opposition_hash`,
 *    `precedence_hash`, `concession_hash`, `recovery_order_hash`, and `weak_front_hash`, so computing
 *    it moves no golden.
 */

import type { NegotiationTier } from "../playbooks/custom-interpreter.js";
import { sha256Hex } from "../ingest/hash.js";
import { stableStringify } from "../engine/runner.js";
import type { PostureCoherence } from "./posture-coherence.js";

/** The team's acceptable floor — the one rung whose name means "below what we will accept." */
const BELOW_FLOOR: NegotiationTier = "below-acceptable";

/**
 * A front's floor-crossing churn class:
 *  - `oscillating` — crossed the floor for a *strict majority* of its transitions
 *    (`crossings × 2 > transitions`) — it flipped sides more often than it held one, the gate-worthy
 *    class: every other round reopens what the last one closed;
 *  - `settled` — has ≥ 1 transition but crossed for *not* a strict majority of them (including zero
 *    crossings — a front that held one side the whole time, and an exact split, e.g. 1 of 2);
 *  - `static` — stated in exactly one round: on the table but never re-discussed, so there is no
 *    transition to register a crossing over (§3: a single appearance has no churn);
 *  - `unstated` — no document ever stated the front (§3: silence is not exposure).
 */
export type CadenceClass = "oscillating" | "settled" | "static" | "unstated";

/** One negotiation front's whole-sequence floor-crossing churn. */
export type CoherenceCadenceFront = {
  dimension: string;
  /** The binding floor at each round, in sequence order (`null` = unstated that round). */
  floors: (NegotiationTier | null)[];
  /** How many rounds *stated* the front. */
  stated_rounds: number;
  /** Transition opportunities — comparisons between consecutive *stated* rounds (`max(0, stated_rounds − 1)`). */
  transitions: number;
  /** How many of those transitions flipped the front across the floor (in either direction). */
  crossings: number;
  /** The flip rate `crossings / transitions` (`null` when the front has no transition). */
  cadence: number | null;
  /** The churn class. */
  class: CadenceClass;
};

export type CoherenceCadence = {
  /** How many rounds (coherences) the cadence spans. */
  rounds: number;
  fronts: CoherenceCadenceFront[];
  /** Per-front tally by churn class. */
  class_counts: Record<CadenceClass, number>;
  /** Every front's crossings, summed — equals v24's `crossings` summed across fronts. */
  total_crossings: number;
  /** Every front's transitions, summed — the grand denominator. */
  total_transitions: number;
  /** The busiest churn across the deal — the largest `cadence` (`null` when no front ever crossed). */
  max_cadence: number | null;
  /** The front owning {@link max_cadence} (earliest on a tie; `null` when none ever crossed). */
  busiest_dimension: string | null;
  /** Was any front a strict-majority floor-crosser across its transitions? The gate-worthy verdict. */
  oscillating: boolean;
  /** SHA-256 over the canonical per-front churn set — additive, apart from every other hash. */
  cadence_hash: string;
};

function emptyClassCounts(): Record<CadenceClass, number> {
  return { oscillating: 0, settled: 0, static: 0, unstated: 0 };
}

/**
 * Walk N cross-document posture coherences — the same bundle at round 1, round 2, …, round N — and
 * report, per negotiation front, the *rate* at which its binding floor flips across the acceptable
 * floor: how many of its transitions were crossings (`crossings`) out of the transitions between the
 * rounds that stated it (`transitions`), the flip rate (`cadence`), the deal's busiest such front
 * (`max_cadence`), and whether any front crossed for a strict majority of its transitions
 * (`oscillating`) — not the raw crossing count (v24) nor the below-floor dwell (v31).
 *
 * Pure and deterministic: fronts are matched by dimension and pinned by `localeCompare`, the round
 * order is the caller's, the busiest-cadence pick uses integer cross-multiplication (never a float
 * comparison), and `cadence_hash` is over the canonical per-front churn set, so the same N coherences
 * in the same order always yield identical bytes.
 *
 * A *crossing* of a front (at the transition into the round that reveals a new standing) is exactly
 * v24's: a flip across the floor between two *stated* rounds; an unstated round is skipped (it neither
 * crosses nor resets the standing, §3), so a crossing across a silent gap is attributed to the
 * transition into the round that *reveals* the new standing, and the denominator counts only
 * transitions between consecutive stated rounds.
 *
 * Every coherence must have been computed against the **same** team positions (the caller applies one
 * active playbook to every document in every round); comparing floors across different ladders is
 * nonsense, the same way v13/v16 refuse a cross-ladder diff. The CLI core
 * ({@link computeCoherenceCadenceArtifacts}) enforces this via the v15/v16 ladder guard before
 * calling this.
 *
 * Requires at least two rounds — a crossing is a *between-round* event; a single round has no
 * transition to register one over.
 */
export async function computeCoherenceCadence(
  rounds: readonly PostureCoherence[],
): Promise<CoherenceCadence> {
  if (rounds.length < 2) {
    throw new Error(`a cadence needs at least two rounds (got ${rounds.length})`);
  }

  const byDim = rounds.map((c) => new Map(c.dimensions.map((d) => [d.dimension, d])));
  const labels = Array.from(
    new Set(rounds.flatMap((c) => c.dimensions.map((d) => d.dimension))),
  ).sort((a, b) => a.localeCompare(b, "en"));

  const class_counts = emptyClassCounts();
  let total_crossings = 0;
  let total_transitions = 0;
  // The busiest cadence, tracked as an exact integer ratio (crossings/transitions) to avoid any float
  // comparison: the running best is `(bestCrossings, bestTransitions)`.
  let bestCrossings = 0;
  let bestTransitions = 0;
  let busiest_dimension: string | null = null;
  let oscillating = false;

  const fronts: CoherenceCadenceFront[] = labels.map((dimension) => {
    const floors = byDim.map((m) => m.get(dimension)?.weakest_tier ?? null);

    // Count crossings and stated rounds in one silence-skipping pass (the v24 scan): a flip vs. the
    // previous *stated* round, in either direction, is a crossing; an unstated round neither crosses
    // nor resets the standing (§3).
    let stated_rounds = 0;
    let crossings = 0;
    let prevBelow: boolean | null = null;
    for (const t of floors) {
      if (t === null) continue; // silence: neither a transition nor a crossing (§3)
      stated_rounds += 1;
      const isBelow = t === BELOW_FLOOR;
      if (prevBelow !== null && prevBelow !== isBelow) crossings += 1;
      prevBelow = isBelow;
    }
    // Transitions are the comparisons between consecutive stated rounds: one fewer than the stated
    // rounds (zero when the front is stated at most once).
    const transitions = stated_rounds === 0 ? 0 : stated_rounds - 1;
    total_crossings += crossings;
    total_transitions += transitions;

    const cadence = transitions === 0 ? null : crossings / transitions;

    // Strict majority over the *transitions* (cross-multiplied to stay integer-exact): the front
    // flipped sides more often than it held one.
    const isOscillating = transitions > 0 && crossings * 2 > transitions;

    const klass: CadenceClass =
      stated_rounds === 0
        ? "unstated"
        : transitions === 0
          ? "static"
          : isOscillating
            ? "oscillating"
            : "settled";
    if (klass === "oscillating") oscillating = true;
    class_counts[klass] += 1;

    // The busiest cadence across the deal: the first front (in localeCompare order) whose flip rate
    // strictly exceeds the running best wins. `crossings/transitions > bestCrossings/bestTransitions`
    // ⟺ `crossings × bestTransitions > bestCrossings × transitions` (all non-negative integers), so
    // the ranking is exact — no float comparison, no platform drift.
    if (
      crossings > 0 &&
      (busiest_dimension === null || crossings * bestTransitions > bestCrossings * transitions)
    ) {
      bestCrossings = crossings;
      bestTransitions = transitions;
      busiest_dimension = dimension;
    }

    return { dimension, floors, stated_rounds, transitions, crossings, cadence, class: klass };
  });

  const max_cadence = busiest_dimension === null ? null : bestCrossings / bestTransitions;

  const cadence_hash = await sha256Hex(
    stableStringify({
      rounds: rounds.length,
      fronts: fronts.map((f) => ({
        dimension: f.dimension,
        floors: f.floors,
        stated_rounds: f.stated_rounds,
        transitions: f.transitions,
        crossings: f.crossings,
        class: f.class,
      })),
    }),
  );

  return {
    rounds: rounds.length,
    fronts,
    class_counts,
    total_crossings,
    total_transitions,
    max_cadence,
    busiest_dimension,
    oscillating,
    cadence_hash,
  };
}

/**
 * Did any front cross the acceptable floor for a strict **majority** of its transitions — flipping
 * sides more often than it held one, a front that can never settle? The CI gate predicate — the
 * *churn* counterpart to v31's *dwell* gate and v24's *count* gate. It needs no tuning — a strict
 * majority of the transitions (held sides working against it) *is* "this front flips more often than
 * not." A front that crossed exactly half its transitions (or fewer) is `settled` and clears it; a
 * consumer wanting a different bar reads `cadence` and `max_cadence` from the JSON. **Distinct from
 * v24's `exposureVolatile`**: a front that crossed twice in 20 transitions is `volatile` to v24 (gate
 * trips on the raw count) but `settled` here (a 10% rate, gate clears); a front that crossed once in
 * its one transition is `monotone` to v24 (gate clears) but `oscillating` here (a 100% rate, gate
 * trips). **Distinct from v31's `exposureMajorityBelow`**: a front below floor for rounds 1–3 of 6
 * that holds is a `majority` dwell to v31 but a `settled` cadence here (one crossing in five
 * transitions); a front flipping every round is a `minority` dwell to v31 (below half the time) but
 * `oscillating` here.
 */
export function exposureOscillates(cadence: CoherenceCadence): boolean {
  return cadence.oscillating;
}

/**
 * Serialize a {@link CoherenceCadence} to a stable, pretty-printed JSON string. The key order is fixed
 * and the front order is already pinned by {@link computeCoherenceCadence}, so the same cadence always
 * yields identical bytes — the `cadence_hash` it carries is the canonical fingerprint, reproducible
 * from `fronts` (over the integer churn counts, the derived `cadence` aside).
 */
export function buildCoherenceCadenceJson(cadence: CoherenceCadence): string {
  return JSON.stringify(
    {
      schema: "vaulytica.posture-cadence.v1",
      cadence_hash: cadence.cadence_hash,
      rounds: cadence.rounds,
      class_counts: cadence.class_counts,
      total_crossings: cadence.total_crossings,
      total_transitions: cadence.total_transitions,
      max_cadence: cadence.max_cadence,
      busiest_dimension: cadence.busiest_dimension,
      oscillating: cadence.oscillating,
      fronts: cadence.fronts.map((f) => ({
        dimension: f.dimension,
        floors: f.floors,
        stated_rounds: f.stated_rounds,
        transitions: f.transitions,
        crossings: f.crossings,
        cadence: f.cadence,
        class: f.class,
      })),
    },
    null,
    2,
  );
}

/** Render a flip rate (0–1) as a whole-percent string, e.g. `0.8` → `"80%"`. */
function pct(cadence: number): string {
  return `${Math.round(cadence * 100)}%`;
}

/**
 * Render a {@link CoherenceCadence} as human-readable terminal lines: the busiest churn (the front and
 * the share of its transitions that were crossings, or none-crossed when no front ever flipped), the
 * class tally, then one line per front that crossed the floor in any transition (its class, its flip
 * rate, and its floor path), `oscillating` fronts first. A `settled`-with-zero-crossings, `static`, or
 * `unstated` front is counted but never listed (§3 honesty). Lives beside its JSON sibling so the CLI
 * renders the cadence from one definition.
 */
export function renderCoherenceCadenceSummary(cadence: CoherenceCadence): string {
  const cc = cadence.class_counts;
  const n = cadence.rounds;
  const lines = [
    `\nCoherence exposure cadence across ${n} rounds (how often each front flips across the floor):`,
    cadence.max_cadence === null
      ? `  busiest churn: none — no front ever crossed the floor in-sequence.`
      : `  busiest churn: ${cadence.busiest_dimension} — crossed the floor on ${pct(cadence.max_cadence)} of its transitions.`,
    `  fronts: ${cc.oscillating} oscillating (flip more often than they hold), ${cc.settled} settled; ${cc.static} stated once, ${cc.unstated} never stated.`,
  ];
  const churned = cadence.fronts.filter((f) => f.crossings > 0);
  // Oscillating fronts first (the heavier churn), then any settled front that still crossed; each
  // group keeps the localeCompare order the fronts already carry.
  for (const f of [
    ...churned.filter((f) => f.class === "oscillating"),
    ...churned.filter((f) => f.class === "settled"),
  ]) {
    const path = f.floors.map((t) => t ?? "—").join(" → ");
    const mark = f.class === "oscillating" ? "⚠" : "·";
    lines.push(
      `  ${mark} ${f.dimension}: ${f.class} — crossed ${f.crossings} of ${f.transitions} transition${f.transitions === 1 ? "" : "s"} (${pct(f.cadence!)}) (${path}).`,
    );
  }
  lines.push(`  cadence_hash: ${cadence.cadence_hash}`);
  return lines.join("\n") + "\n";
}
