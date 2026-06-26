/**
 * Cross-document negotiation-posture **exposure precedence** (lead-lag) — per unordered *pair*
 * of fronts, when the two both cross the acceptable floor (in any direction), does one
 * consistently cross **first**? For each pair, how many round-transitions saw front A cross
 * *before* front B (`a_leads`), how many saw B cross before A (`b_leads`), how many saw the two
 * cross in the *same* step (`co_crossings` — a timing tie), out of all `comparisons`
 * (`a_leads + b_leads + co_crossings`); the pair's `leader` (the front that crossed first more
 * often, `null` on an exact split), the `affinity` (the leader's share of all comparisons), the
 * deal's **most-leading pairing** (`max_affinity` / `most_leading_pair` / `leading_front`), and
 * whether any pair has a front that crossed first for a strict **majority** of the comparisons
 * (`leads`) (spec-v35).
 *
 * This is the family's **first directional** pairwise read. v32 ({@link computeCoherenceAffinity},
 * co-fall), v33 ({@link computeCoherenceRecoveryAffinity}, co-recovery), and v34
 * ({@link computeCoherenceOpposition}, counter-move) are all **same-step** relations — they read
 * which two fronts crossed *together* in one transition, aligned or opposed, and are blind to
 * *order across* transitions. The ordering relation is unread: across the deal, when fronts A and
 * B both eventually cross the floor, does A reliably move **first**? A *lead-lag* pairing is
 * strategic information a same-step read structurally cannot pose — a front that consistently
 * crosses before its partner is an *early-warning indicator* for the follower: movement on the
 * leader reliably precedes movement on the follower, so a deal lead watching the leader gets
 * advance notice on the follower. Two deals with byte-identical v32/v33/v34 same-step couplings
 * can have opposite precedence:
 *
 * - The **leader.** Cap crosses the floor in rounds 1 and 3; Term crosses in rounds 2 and 4 —
 *   every comparison, Cap moved first. Cap *leads* Term: watch Cap to anticipate Term.
 * - The **interleaved pair.** Cap and Term cross in mixed order — sometimes Cap first, sometimes
 *   Term — with no consistent first-mover. No lead-lag signal.
 *
 * The crossing events are exactly v24's (a *fall* at-or-above → below, or a *recovery* below →
 * at-or-above, between two *stated* rounds; an unstated round is skipped, §3) — so v35 reuses the
 * same per-front crossing-step sets v24 counts and v25 buckets per step, and adds **no** posture
 * math beyond a per-pair *ordered* comparison of those step indices. By construction, each pair's
 * `co_crossings` (the same-step ties) equals v34's `joint_moves` for that pair, and summed over
 * all pairs `total_co_crossings` equals `Σ_t C(crossing_t, 2)` (v25's per-step crossing count
 * choose-two'd) — the same total v34 splits into aligned + opposed. The posture filter
 * (spec-v10 §3), restated:
 *  - **Deterministic** — same N coherences in the same order → identical `precedence_hash`, on any
 *    machine. Fronts are pinned by `localeCompare(_, "en")` (the same order the
 *    trajectory/exposure/concurrency/affinity functions use); unordered pairs are enumerated in
 *    that pinned order (`dimension_a < dimension_b`); the most-leading pick is decided by *integer
 *    cross-multiplication* (`leads × comparisons` of the two pairs), never a float compare.
 *  - **Honest about unstated data** — a front no document states in a round does not *cross* into
 *    or out of that round: silence is neither a fall nor a recovery (the §3 contract that keeps
 *    `below → unstated → below` zero crossings in v24/v25/v34). A pair the two never crossed in a
 *    *different* step (no ordered comparison — one never crossed, or they always crossed together)
 *    has no lead-lag edge and is omitted from `pairs[]`, never ranked.
 *  - **Advisory** — the report names which front the counterparty moved *first* across the team's
 *    own floor, and how reliably. It asserts no legal conclusion.
 *  - **Additive** — the report carries its own `precedence_hash`, namespaced apart from every
 *    `coherence_hash`, `movement_hash`, `trajectory_hash`, `shift_trajectory_hash`, `arc_hash`,
 *    `exposure_hash`, `persistence_hash`, `breadth_hash`, `recurrence_hash`, `volatility_hash`,
 *    `synchrony_hash`, `settling_hash`, `onset_hash`, `latency_hash`, `concurrency_hash`,
 *    `relapse_hash`, `tenure_hash`, `affinity_hash`, `recovery_affinity_hash`, and
 *    `opposition_hash`, so computing it moves no golden.
 */

import type { NegotiationTier } from "../playbooks/custom-interpreter.js";
import { sha256Hex } from "../ingest/hash.js";
import { stableStringify } from "../engine/runner.js";
import type { PostureCoherence } from "./posture-coherence.js";

/** The team's acceptable floor — the one rung whose name means "below what we will accept." */
const BELOW_FLOOR: NegotiationTier = "below-acceptable";

/**
 * One pair's lead-lag coupling class:
 *  - `leading` — one front crossed the floor *before* the other for a *strict majority* of the
 *    comparisons (`max(a_leads, b_leads) × 2 > comparisons`) — a consistent first-mover, the
 *    gate-worthy class; the leader is an early-warning indicator for the follower;
 *  - `interleaved` — the two crossed in mixed order with no strict-majority first-mover (including
 *    an exact split, and a pair whose comparisons are dominated by same-step ties).
 *
 * Only pairs with ≥ 1 *ordered* comparison (`a_leads + b_leads ≥ 1`) are classified; a pair the
 * two never crossed in a different step (one never crossed, or they always crossed together) has
 * no lead-lag edge and is omitted from the report.
 */
export type PrecedenceClass = "leading" | "interleaved";

/** One unordered pair of fronts' whole-sequence lead-lag relation. */
export type CoherencePrecedencePair = {
  /** The earlier front of the pair (`localeCompare` order). */
  dimension_a: string;
  /** The later front of the pair (`dimension_a < dimension_b`). */
  dimension_b: string;
  /** How many comparisons saw `dimension_a` cross the floor in an *earlier* step than `dimension_b`. */
  a_leads: number;
  /** How many comparisons saw `dimension_b` cross the floor in an *earlier* step than `dimension_a`. */
  b_leads: number;
  /** How many comparisons saw the two cross in the *same* step — a timing tie (equals v34's `joint_moves`). */
  co_crossings: number;
  /** All comparisons of one A-crossing against one B-crossing (`a_leads + b_leads + co_crossings`). */
  comparisons: number;
  /** The front that crossed first more often (`null` on an exact `a_leads === b_leads` split). */
  leader: string | null;
  /** The leader's share of all comparisons (`max(a_leads, b_leads) / comparisons`). */
  affinity: number;
  /** The coupling class. */
  class: PrecedenceClass;
};

export type CoherencePrecedence = {
  /** How many rounds (coherences) the report spans. */
  rounds: number;
  /** The lead-lag pairs (`a_leads + b_leads ≥ 1`), pinned by `(dimension_a, dimension_b)`. */
  pairs: CoherencePrecedencePair[];
  /** Per-pair tally by coupling class. */
  class_counts: Record<PrecedenceClass, number>;
  /** Every pair's *ordered* comparisons summed (`Σ (a_leads + b_leads)` over all pairs). */
  total_ordered_comparisons: number;
  /** Every pair's same-step ties summed — equals `Σ_t C(crossing_t, 2)` (v25), the same total v34 splits. */
  total_co_crossings: number;
  /** The most-leading coupling across the deal — the largest `affinity` among pairs with a leader (`null` when none). */
  max_affinity: number | null;
  /** The pair owning {@link max_affinity} (earliest on a tie; `null` when no pair has a leader). */
  most_leading_pair: [string, string] | null;
  /** The leading front of {@link most_leading_pair} (`null` when none). */
  leading_front: string | null;
  /** Was any pair a strict-majority lead-lag coupling? The gate-worthy verdict. */
  leads: boolean;
  /** SHA-256 over the canonical per-pair set — additive, apart from every other hash. */
  precedence_hash: string;
};

function emptyClassCounts(): Record<PrecedenceClass, number> {
  return { leading: 0, interleaved: 0 };
}

/**
 * Walk N cross-document posture coherences — the same bundle at round 1, round 2, …, round N —
 * and report, *per unordered pair of fronts*, when the two both cross the acceptable floor (in
 * any direction), whether one consistently crosses *first*: how many comparisons saw A cross
 * before B (`a_leads`), B before A (`b_leads`), the two together (`co_crossings`), out of all
 * `comparisons`; the pair's `leader`, the resulting `affinity`, the deal's most-leading such
 * pairing (`max_affinity` / `most_leading_pair` / `leading_front`), and whether any pair has a
 * front that crossed first for a strict majority of the comparisons (`leads`) — not a *same-step*
 * coupling (v32's co-fall, v33's co-recovery, v34's counter-move).
 *
 * Pure and deterministic: fronts are matched by dimension and pinned by `localeCompare`,
 * unordered pairs are enumerated in that order, the round order is the caller's, the most-leading
 * pick uses integer cross-multiplication (never a float comparison), and `precedence_hash` is
 * over the canonical per-pair set, so the same N coherences in the same order always yield
 * identical bytes.
 *
 * A *crossing* of a front (at the transition into the round that reveals a new standing) is
 * exactly v24's: a flip across the floor between two *stated* rounds; an unstated round is skipped
 * (it neither crosses nor resets the standing, §3), so a crossing across a silent gap is
 * attributed to the transition into the round that *reveals* the new standing. A *comparison* of a
 * pair pairs one A-crossing step against one B-crossing step; A *leads* when its step is the
 * earlier one. Summed over all pairs, the same-step ties (`co_crossings`) equal `Σ_t C(crossing_t,
 * 2)` (v25's per-step crossing count choose-two'd), the same total v34 splits into aligned +
 * opposed moves.
 *
 * Every coherence must have been computed against the **same** team positions (the caller applies
 * one active playbook to every document in every round); comparing floors across different ladders
 * is nonsense, the same way v13/v16 refuse a cross-ladder diff. The CLI core
 * ({@link computeCoherencePrecedenceArtifacts}) enforces this via the v15/v16 ladder guard before
 * calling this.
 *
 * Requires at least two rounds — a crossing is a *between-round* event; a single round has no
 * transition to register one over.
 */
export async function computeCoherencePrecedence(
  rounds: readonly PostureCoherence[],
): Promise<CoherencePrecedence> {
  if (rounds.length < 2) {
    throw new Error(`a precedence needs at least two rounds (got ${rounds.length})`);
  }

  const byDim = rounds.map((c) => new Map(c.dimensions.map((d) => [d.dimension, d])));
  const labels = Array.from(
    new Set(rounds.flatMap((c) => c.dimensions.map((d) => d.dimension))),
  ).sort((a, b) => a.localeCompare(b, "en"));

  // Per front, the *sorted* list of transition indices (0…N−2) at which it crossed the floor in
  // either direction — the same v24 crossings, silence-skipping (§3): a flip vs. the previous
  // *stated* round, held at the transition into the round that reveals the new standing. A front
  // crosses at most once per transition, so each list is strictly increasing.
  const crossStepsByDim = new Map<string, number[]>();
  for (const dimension of labels) {
    const floors = byDim.map((m) => m.get(dimension)?.weakest_tier ?? null);
    const crossSteps: number[] = [];
    let prevBelow: boolean | null = null; // the last *stated* round's below-floor state
    for (let i = 0; i < floors.length; i++) {
      const t = floors[i];
      if (t === null) continue; // silence: neither crosses nor resets the standing (§3)
      const isBelow = t === BELOW_FLOOR;
      // A crossing vs. the previous stated round (either direction) is held at index i−1.
      if (prevBelow !== null && prevBelow !== isBelow) crossSteps.push(i - 1);
      prevBelow = isBelow;
    }
    crossStepsByDim.set(dimension, crossSteps);
  }

  const class_counts = emptyClassCounts();
  let total_ordered_comparisons = 0;
  let total_co_crossings = 0;

  // The most-leading affinity, tracked as an exact integer ratio (leads/comparisons) to avoid any
  // float comparison: the running best is `(bestLeads, bestComparisons)`.
  let bestLeads = 0;
  let bestComparisons = 0;
  let most_leading_pair: [string, string] | null = null;
  let leading_front: string | null = null;
  let leads = false;

  const pairs: CoherencePrecedencePair[] = [];
  for (let i = 0; i < labels.length; i++) {
    const dimension_a = labels[i]!;
    const ca = crossStepsByDim.get(dimension_a)!;
    for (let j = i + 1; j < labels.length; j++) {
      const dimension_b = labels[j]!;
      const cb = crossStepsByDim.get(dimension_b)!;

      // Ordered comparisons of one A-crossing step against one B-crossing step.
      let a_leads = 0;
      let b_leads = 0;
      let co_crossings = 0;
      for (const sa of ca) {
        for (const sb of cb) {
          if (sa < sb) a_leads += 1;
          else if (sb < sa) b_leads += 1;
          else co_crossings += 1;
        }
      }

      // Accumulate the deal-level totals over *every* pair (an omitted no-ordered-comparison pair
      // still contributes its same-step ties to total_co_crossings), so the join invariant to
      // v25/v34 holds across the whole matrix.
      total_ordered_comparisons += a_leads + b_leads;
      total_co_crossings += co_crossings;

      if (a_leads + b_leads === 0) continue; // no lead-lag edge — no ordered comparison to rank

      const comparisons = a_leads + b_leads + co_crossings;
      const leaderLeads = Math.max(a_leads, b_leads);
      const leader = a_leads > b_leads ? dimension_a : b_leads > a_leads ? dimension_b : null;
      const affinity = leaderLeads / comparisons;
      // Strict majority of *all* comparisons (cross-multiplied to stay integer-exact): the leader
      // crossed first more often than the ties and reverse-order comparisons combined. This is
      // only reachable when a_leads ≠ b_leads, so `class === "leading"` implies a non-null leader.
      const klass: PrecedenceClass = leaderLeads * 2 > comparisons ? "leading" : "interleaved";
      if (klass === "leading") leads = true;
      class_counts[klass] += 1;

      // The most-leading affinity across the deal, among pairs that *have* a leader (a direction to
      // name). The first pair (in label order) whose affinity strictly exceeds the running best
      // wins. `leaderLeads/comparisons > bestLeads/bestComparisons` ⟺
      // `leaderLeads × bestComparisons > bestLeads × comparisons` (all non-negative integers), so
      // the ranking is exact — no float comparison, no platform drift.
      if (
        leader !== null &&
        (most_leading_pair === null || leaderLeads * bestComparisons > bestLeads * comparisons)
      ) {
        bestLeads = leaderLeads;
        bestComparisons = comparisons;
        most_leading_pair = [dimension_a, dimension_b];
        leading_front = leader;
      }

      pairs.push({
        dimension_a,
        dimension_b,
        a_leads,
        b_leads,
        co_crossings,
        comparisons,
        leader,
        affinity,
        class: klass,
      });
    }
  }

  const max_affinity = most_leading_pair === null ? null : bestLeads / bestComparisons;

  const precedence_hash = await sha256Hex(
    stableStringify({
      rounds: rounds.length,
      pairs: pairs.map((p) => ({
        dimension_a: p.dimension_a,
        dimension_b: p.dimension_b,
        a_leads: p.a_leads,
        b_leads: p.b_leads,
        co_crossings: p.co_crossings,
        leader: p.leader,
        class: p.class,
      })),
    }),
  );

  return {
    rounds: rounds.length,
    pairs,
    class_counts,
    total_ordered_comparisons,
    total_co_crossings,
    max_affinity,
    most_leading_pair,
    leading_front,
    leads,
    precedence_hash,
  };
}

/**
 * Did any pair of fronts have one that crossed the acceptable floor *before* the other — in any
 * direction — for a strict **majority** of the comparisons: is there a stable lead-lag pairing
 * whose leader is an early-warning indicator for its follower? The CI gate predicate — the family's
 * first *directional* verdict (v32/v33/v34 gate on *same-step* couplings; v25/v29 on per-step
 * counts). It needs no tuning — a strict majority of the comparisons (ties and reverse-order
 * working against it) *is* "this front consistently crosses first." A pair that led once but
 * crossed together twice, or split its leads evenly, is `interleaved` and clears it; a consumer
 * wanting a different bar reads `affinity` and `max_affinity` from the JSON. **Distinct from
 * v32/v33/v34**: those read which two fronts cross *together* (aligned or opposed) in one step;
 * this reads, *across* steps, which front crosses *first* — an ordering relation a same-step read
 * cannot pose.
 */
export function exposureLeads(precedence: CoherencePrecedence): boolean {
  return precedence.leads;
}

/**
 * Serialize a {@link CoherencePrecedence} to a stable, pretty-printed JSON string. The key order
 * is fixed and the pair order is already pinned by {@link computeCoherencePrecedence}, so the same
 * report always yields identical bytes — the `precedence_hash` it carries is the canonical
 * fingerprint, reproducible from `pairs` (over the integer lead counts, ties, leader, and class;
 * the derived float `affinity` and derived integer `comparisons` aside).
 */
export function buildCoherencePrecedenceJson(precedence: CoherencePrecedence): string {
  return JSON.stringify(
    {
      schema: "vaulytica.posture-precedence.v1",
      precedence_hash: precedence.precedence_hash,
      rounds: precedence.rounds,
      class_counts: precedence.class_counts,
      total_ordered_comparisons: precedence.total_ordered_comparisons,
      total_co_crossings: precedence.total_co_crossings,
      max_affinity: precedence.max_affinity,
      most_leading_pair: precedence.most_leading_pair,
      leading_front: precedence.leading_front,
      leads: precedence.leads,
      pairs: precedence.pairs.map((p) => ({
        dimension_a: p.dimension_a,
        dimension_b: p.dimension_b,
        a_leads: p.a_leads,
        b_leads: p.b_leads,
        co_crossings: p.co_crossings,
        comparisons: p.comparisons,
        leader: p.leader,
        affinity: p.affinity,
        class: p.class,
      })),
    },
    null,
    2,
  );
}

/** Render a lead-lag affinity (0–1) as a whole-percent string, e.g. `0.75` → `"75%"`. */
function pct(affinity: number): string {
  return `${Math.round(affinity * 100)}%`;
}

/**
 * Render a {@link CoherencePrecedence} as human-readable terminal lines: the most-leading pairing
 * (the leader, its follower, and the share of the comparisons it crossed first, or none-leading
 * when no front ever consistently crossed first), the class tally, then one line per lead-lag pair
 * (its class, its leader and lead share, and the ordered-vs-tied split), `leading` pairs first. A
 * pair the two never crossed in a different step is never listed (§3 honesty — no lead-lag edge).
 * Lives beside its JSON sibling so the CLI renders the report from one definition.
 */
export function renderCoherencePrecedenceSummary(precedence: CoherencePrecedence): string {
  const cc = precedence.class_counts;
  const n = precedence.rounds;
  const lines = [
    `\nCoherence exposure precedence across ${n} rounds (which front the counterparty moves first within a pair):`,
    precedence.most_leading_pair === null
      ? `  most-leading pairing: none — no front ever crossed the floor first for a strict majority of the comparisons.`
      : `  most-leading pairing: ${precedence.leading_front} leads ${
          precedence.most_leading_pair[0] === precedence.leading_front
            ? precedence.most_leading_pair[1]
            : precedence.most_leading_pair[0]
        } — crossed first ${pct(precedence.max_affinity!)} of the comparisons.`,
    `  pairs: ${cc.leading} leading (one front consistently crosses first), ${cc.interleaved} interleaved.`,
  ];
  // Leading pairs first (the stable lead-lag), then interleaved; each group keeps the
  // (dimension_a, dimension_b) order the pairs already carry.
  for (const p of [
    ...precedence.pairs.filter((p) => p.class === "leading"),
    ...precedence.pairs.filter((p) => p.class === "interleaved"),
  ]) {
    const mark = p.class === "leading" ? "⚠" : "·";
    const order =
      p.leader === null
        ? `${p.a_leads}/${p.b_leads} split`
        : `${p.leader} first ${p.leader === p.dimension_a ? p.a_leads : p.b_leads} of ${p.comparisons}`;
    lines.push(
      `  ${mark} ${p.dimension_a} + ${p.dimension_b}: ${p.class} — ${order} (${pct(p.affinity)}); ${p.co_crossings} same-step tie${p.co_crossings === 1 ? "" : "s"}.`,
    );
  }
  lines.push(`  precedence_hash: ${precedence.precedence_hash}`);
  return lines.join("\n") + "\n";
}
