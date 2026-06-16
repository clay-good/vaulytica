/**
 * Cross-document negotiation-posture **exposure concession order** (fall-precedence) — per unordered
 * *pair* of fronts, when the two both *fall* below the acceptable floor, does one consistently
 * concede **first**? For each pair, how many round-transitions saw front A fall in an *earlier* step
 * than front B (`a_concedes_first`), how many saw B fall before A (`b_concedes_first`), how many saw
 * the two fall in the *same* step (`co_falls` — a timing tie), out of all `comparisons`
 * (`a_concedes_first + b_concedes_first + co_falls`); the pair's `first_conceder` (the front that fell
 * first more often, `null` on an exact split), the `affinity` (the first-conceder's share of all
 * comparisons), the deal's **most-conceding pairing** (`max_affinity` / `most_conceding_pair` /
 * `first_conceding_front`), and whether any pair has a front that conceded first for a strict
 * **majority** of the comparisons (`concedes`) (spec-v36).
 *
 * This is the family's **first direction-resolved precedence**. v35
 * ({@link computeCoherencePrecedence}) orders *crossings* of either direction (a fall or a recovery),
 * so it answers "which front *moves* first?" — and a pair can lead there because one front
 * *recovers* first, not because it *concedes* first. v36 restricts the ordering to *falls* only, so
 * it answers the sharper question a deal lead actually asks: "which front does the counterparty give
 * ground on **first**?" — the early-warning indicator for a coming concession. Two deals with byte-
 * identical v35 (direction-blind) precedence can have opposite concession order:
 *
 * - The **first conceder.** Cap falls below floor in rounds 1 and 3; Term falls in rounds 2 and 4 —
 *   every comparison, Cap conceded first. Cap leads the concession: watch Cap to anticipate Term
 *   giving ground.
 * - The **interleaved pair.** Cap and Term concede in mixed order — sometimes Cap first, sometimes
 *   Term — with no consistent first-conceder. No concession-order signal, even if v35 sees a clear
 *   lead (one front may always *recover* first while the falls interleave).
 *
 * The fall event is exactly v32's ({@link computeCoherenceAffinity}): an at-or-above → below
 * transition between two *stated* rounds; an unstated round is skipped (it neither falls nor resets
 * the standing, §3) — so v36 reuses the same per-front fall-step sets v32 overlaps and v29 buckets
 * per step, and adds **no** posture math beyond a per-pair *ordered* comparison of those step
 * indices. By construction, each pair's `co_falls` (the same-step fall ties) equals v32's `co_falls`
 * for that pair, and summed over all pairs `total_co_falls` equals `Σ_t C(falling_t, 2)` (v29's
 * per-step fall count choose-two'd) — the same total v32 reports. The posture filter (spec-v10 §3),
 * restated:
 *  - **Deterministic** — same N coherences in the same order → identical `concession_hash`, on any
 *    machine. Fronts are pinned by `localeCompare(_, "en")` (the same order the
 *    trajectory/exposure/affinity/precedence functions use); unordered pairs are enumerated in that
 *    pinned order (`dimension_a < dimension_b`); the most-conceding pick is decided by *integer
 *    cross-multiplication* (`leads × comparisons` of the two pairs), never a float compare.
 *  - **Honest about unstated data** — a front no document states in a round does not *fall* into or
 *    out of that round: silence is neither a fall nor a recovery (the §3 contract that keeps
 *    `below → unstated → below` zero falls in v29/v32). A pair the two never both *fell* in a
 *    *different* step (no ordered comparison — one never fell, or they always fell together) has no
 *    concession-order edge and is omitted from `pairs[]`, never ranked.
 *  - **Advisory** — the report names which front the counterparty conceded *first* across the team's
 *    own floor, and how reliably. It asserts no legal conclusion.
 *  - **Additive** — the report carries its own `concession_hash`, namespaced apart from every
 *    `coherence_hash`, `movement_hash`, `trajectory_hash`, `shift_trajectory_hash`, `arc_hash`,
 *    `exposure_hash`, `persistence_hash`, `breadth_hash`, `recurrence_hash`, `volatility_hash`,
 *    `synchrony_hash`, `settling_hash`, `onset_hash`, `latency_hash`, `concurrency_hash`,
 *    `relapse_hash`, `tenure_hash`, `affinity_hash`, `recovery_affinity_hash`, `opposition_hash`, and
 *    `precedence_hash`, so computing it moves no golden.
 */

import type { NegotiationTier } from "../playbooks/custom-interpreter.js";
import { sha256Hex } from "../ingest/hash.js";
import { stableStringify } from "../engine/runner.js";
import type { PostureCoherence } from "./posture-coherence.js";

/** The team's acceptable floor — the one rung whose name means "below what we will accept." */
const BELOW_FLOOR: NegotiationTier = "below-acceptable";

/**
 * One pair's concession-order coupling class:
 *  - `leading` — one front *fell* below the floor *before* the other for a *strict majority* of the
 *    comparisons (`max(a_concedes_first, b_concedes_first) × 2 > comparisons`) — a consistent
 *    first-conceder, the gate-worthy class; the first-conceder is an early-warning indicator that the
 *    follower is about to give ground too;
 *  - `interleaved` — the two conceded in mixed order with no strict-majority first-conceder
 *    (including an exact split, and a pair whose comparisons are dominated by same-step ties).
 *
 * Only pairs with ≥ 1 *ordered* comparison (`a_concedes_first + b_concedes_first ≥ 1`) are
 * classified; a pair the two never both fell in a different step (one never fell, or they always
 * fell together) has no concession-order edge and is omitted from the report.
 */
export type ConcessionClass = "leading" | "interleaved";

/** One unordered pair of fronts' whole-sequence concession-order relation. */
export type CoherenceConcessionPair = {
  /** The earlier front of the pair (`localeCompare` order). */
  dimension_a: string;
  /** The later front of the pair (`dimension_a < dimension_b`). */
  dimension_b: string;
  /** How many comparisons saw `dimension_a` fall below the floor in an *earlier* step than `dimension_b`. */
  a_concedes_first: number;
  /** How many comparisons saw `dimension_b` fall below the floor in an *earlier* step than `dimension_a`. */
  b_concedes_first: number;
  /** How many comparisons saw the two fall in the *same* step — a timing tie (equals v32's `co_falls`). */
  co_falls: number;
  /** All comparisons of one A-fall against one B-fall (`a_concedes_first + b_concedes_first + co_falls`). */
  comparisons: number;
  /** The front that fell first more often (`null` on an exact `a_concedes_first === b_concedes_first` split). */
  first_conceder: string | null;
  /** The first-conceder's share of all comparisons (`max(a_concedes_first, b_concedes_first) / comparisons`). */
  affinity: number;
  /** The coupling class. */
  class: ConcessionClass;
};

export type CoherenceConcession = {
  /** How many rounds (coherences) the report spans. */
  rounds: number;
  /** The concession-order pairs (`a_concedes_first + b_concedes_first ≥ 1`), pinned by `(dimension_a, dimension_b)`. */
  pairs: CoherenceConcessionPair[];
  /** Per-pair tally by coupling class. */
  class_counts: Record<ConcessionClass, number>;
  /** Every pair's *ordered* comparisons summed (`Σ (a_concedes_first + b_concedes_first)` over all pairs). */
  total_ordered_comparisons: number;
  /** Every pair's same-step fall ties summed — equals `Σ_t C(falling_t, 2)` (v29), the same total v32 reports as `total_co_falls`. */
  total_co_falls: number;
  /** The most-conceding coupling across the deal — the largest `affinity` among pairs with a first-conceder (`null` when none). */
  max_affinity: number | null;
  /** The pair owning {@link max_affinity} (earliest on a tie; `null` when no pair has a first-conceder). */
  most_conceding_pair: [string, string] | null;
  /** The first-conceding front of {@link most_conceding_pair} (`null` when none). */
  first_conceding_front: string | null;
  /** Was any pair a strict-majority concession-order coupling? The gate-worthy verdict. */
  concedes: boolean;
  /** SHA-256 over the canonical per-pair set — additive, apart from every other hash. */
  concession_hash: string;
};

function emptyClassCounts(): Record<ConcessionClass, number> {
  return { leading: 0, interleaved: 0 };
}

/**
 * Walk N cross-document posture coherences — the same bundle at round 1, round 2, …, round N —
 * and report, *per unordered pair of fronts*, when the two both *fall* below the acceptable floor,
 * whether one consistently concedes *first*: how many comparisons saw A fall before B
 * (`a_concedes_first`), B before A (`b_concedes_first`), the two together (`co_falls`), out of all
 * `comparisons`; the pair's `first_conceder`, the resulting `affinity`, the deal's most-conceding
 * such pairing (`max_affinity` / `most_conceding_pair` / `first_conceding_front`), and whether any
 * pair has a front that conceded first for a strict majority of the comparisons (`concedes`) — not a
 * *direction-blind* ordering (v35's precedence, which also orders recoveries) nor a *same-step*
 * coupling (v32's co-fall).
 *
 * Pure and deterministic: fronts are matched by dimension and pinned by `localeCompare`, unordered
 * pairs are enumerated in that order, the round order is the caller's, the most-conceding pick uses
 * integer cross-multiplication (never a float comparison), and `concession_hash` is over the
 * canonical per-pair set, so the same N coherences in the same order always yield identical bytes.
 *
 * A *fall* of a front (at the transition into the round that reveals a new standing) is exactly
 * v32's: an at-or-above → below flip between two *stated* rounds; an unstated round is skipped (it
 * neither falls nor resets the standing, §3), so a fall across a silent gap is attributed to the
 * transition into the round that *reveals* the new standing. A *comparison* of a pair pairs one
 * A-fall step against one B-fall step; A *concedes first* when its step is the earlier one. Summed
 * over all pairs, the same-step ties (`co_falls`) equal `Σ_t C(falling_t, 2)` (v29's per-step fall
 * count choose-two'd), the same total v32 reports as `total_co_falls`.
 *
 * Every coherence must have been computed against the **same** team positions (the caller applies
 * one active playbook to every document in every round); comparing floors across different ladders
 * is nonsense, the same way v13/v16 refuse a cross-ladder diff. The CLI core
 * ({@link computeCoherenceConcessionArtifacts}) enforces this via the v15/v16 ladder guard before
 * calling this.
 *
 * Requires at least two rounds — a fall is a *between-round* event; a single round has no transition
 * to register one over.
 */
export async function computeCoherenceConcession(
  rounds: readonly PostureCoherence[],
): Promise<CoherenceConcession> {
  if (rounds.length < 2) {
    throw new Error(`a concession order needs at least two rounds (got ${rounds.length})`);
  }

  const byDim = rounds.map((c) => new Map(c.dimensions.map((d) => [d.dimension, d])));
  const labels = Array.from(
    new Set(rounds.flatMap((c) => c.dimensions.map((d) => d.dimension))),
  ).sort((a, b) => a.localeCompare(b, "en"));

  // Per front, the *sorted* list of transition indices (0…N−2) at which it *fell* below the floor —
  // the same v32 fall event, silence-skipping (§3): an at-or-above → below flip vs. the previous
  // *stated* round, held at the transition into the round that reveals the new standing. A front
  // falls at most once per transition, so each list is strictly increasing.
  const fallStepsByDim = new Map<string, number[]>();
  for (const dimension of labels) {
    const floors = byDim.map((m) => m.get(dimension)?.weakest_tier ?? null);
    const fallSteps: number[] = [];
    let prevBelow: boolean | null = null; // the last *stated* round's below-floor state
    for (let i = 0; i < floors.length; i++) {
      const t = floors[i];
      if (t === null) continue; // silence: neither falls nor resets the standing (§3)
      const isBelow = t === BELOW_FLOOR;
      // A fall (at-or-above → below) vs. the previous stated round is held at index i−1.
      if (prevBelow === false && isBelow) fallSteps.push(i - 1);
      prevBelow = isBelow;
    }
    fallStepsByDim.set(dimension, fallSteps);
  }

  const class_counts = emptyClassCounts();
  let total_ordered_comparisons = 0;
  let total_co_falls = 0;

  // The most-conceding affinity, tracked as an exact integer ratio (leads/comparisons) to avoid any
  // float comparison: the running best is `(bestLeads, bestComparisons)`.
  let bestLeads = 0;
  let bestComparisons = 0;
  let most_conceding_pair: [string, string] | null = null;
  let first_conceding_front: string | null = null;
  let concedes = false;

  const pairs: CoherenceConcessionPair[] = [];
  for (let i = 0; i < labels.length; i++) {
    const dimension_a = labels[i]!;
    const fa = fallStepsByDim.get(dimension_a)!;
    for (let j = i + 1; j < labels.length; j++) {
      const dimension_b = labels[j]!;
      const fb = fallStepsByDim.get(dimension_b)!;

      // Ordered comparisons of one A-fall step against one B-fall step.
      let a_concedes_first = 0;
      let b_concedes_first = 0;
      let co_falls = 0;
      for (const sa of fa) {
        for (const sb of fb) {
          if (sa < sb) a_concedes_first += 1;
          else if (sb < sa) b_concedes_first += 1;
          else co_falls += 1;
        }
      }

      // Accumulate the deal-level totals over *every* pair (an omitted no-ordered-comparison pair
      // still contributes its same-step fall ties to total_co_falls), so the join invariant to
      // v29/v32 holds across the whole matrix.
      total_ordered_comparisons += a_concedes_first + b_concedes_first;
      total_co_falls += co_falls;

      if (a_concedes_first + b_concedes_first === 0) continue; // no concession-order edge

      const comparisons = a_concedes_first + b_concedes_first + co_falls;
      const leaderLeads = Math.max(a_concedes_first, b_concedes_first);
      const first_conceder =
        a_concedes_first > b_concedes_first
          ? dimension_a
          : b_concedes_first > a_concedes_first
            ? dimension_b
            : null;
      const affinity = leaderLeads / comparisons;
      // Strict majority of *all* comparisons (cross-multiplied to stay integer-exact): the
      // first-conceder fell first more often than the ties and reverse-order comparisons combined.
      // This is only reachable when a_concedes_first ≠ b_concedes_first, so `class === "leading"`
      // implies a non-null first_conceder.
      const klass: ConcessionClass = leaderLeads * 2 > comparisons ? "leading" : "interleaved";
      if (klass === "leading") concedes = true;
      class_counts[klass] += 1;

      // The most-conceding affinity across the deal, among pairs that *have* a first-conceder (a
      // direction to name). The first pair (in label order) whose affinity strictly exceeds the
      // running best wins. `leaderLeads/comparisons > bestLeads/bestComparisons` ⟺
      // `leaderLeads × bestComparisons > bestLeads × comparisons` (all non-negative integers), so
      // the ranking is exact — no float comparison, no platform drift.
      if (
        first_conceder !== null &&
        (most_conceding_pair === null || leaderLeads * bestComparisons > bestLeads * comparisons)
      ) {
        bestLeads = leaderLeads;
        bestComparisons = comparisons;
        most_conceding_pair = [dimension_a, dimension_b];
        first_conceding_front = first_conceder;
      }

      pairs.push({
        dimension_a,
        dimension_b,
        a_concedes_first,
        b_concedes_first,
        co_falls,
        comparisons,
        first_conceder,
        affinity,
        class: klass,
      });
    }
  }

  const max_affinity = most_conceding_pair === null ? null : bestLeads / bestComparisons;

  const concession_hash = await sha256Hex(
    stableStringify({
      rounds: rounds.length,
      pairs: pairs.map((p) => ({
        dimension_a: p.dimension_a,
        dimension_b: p.dimension_b,
        a_concedes_first: p.a_concedes_first,
        b_concedes_first: p.b_concedes_first,
        co_falls: p.co_falls,
        first_conceder: p.first_conceder,
        class: p.class,
      })),
    }),
  );

  return {
    rounds: rounds.length,
    pairs,
    class_counts,
    total_ordered_comparisons,
    total_co_falls,
    max_affinity,
    most_conceding_pair,
    first_conceding_front,
    concedes,
    concession_hash,
  };
}

/**
 * Did any pair of fronts have one that *fell* below the acceptable floor *before* the other for a
 * strict **majority** of the comparisons: is there a stable concession-order pairing whose
 * first-conceder is an early-warning indicator that the follower is about to give ground? The CI gate
 * predicate — the family's first *direction-resolved* precedence verdict (v35 gates on a
 * direction-blind ordering of any crossing; v32/v33/v34 on *same-step* couplings; v25/v29 on per-step
 * counts). It needs no tuning — a strict majority of the comparisons (ties and reverse-order working
 * against it) *is* "this front consistently concedes first." A pair that conceded first once but fell
 * together twice, or split its concessions evenly, is `interleaved` and clears it; a consumer wanting
 * a different bar reads `affinity` and `max_affinity` from the JSON. **Distinct from v35**: v35 orders
 * *every* crossing (a fall or a recovery), so a pair can lead there because one front *recovers* first;
 * this orders *falls* only, so it isolates which front *concedes* first. **Distinct from v32**: v32
 * reads which two fronts fall *together* in one step; this reads, *across* steps, which front falls
 * *first* — an ordering relation a same-step read cannot pose.
 */
export function exposureConcedes(concession: CoherenceConcession): boolean {
  return concession.concedes;
}

/**
 * Serialize a {@link CoherenceConcession} to a stable, pretty-printed JSON string. The key order is
 * fixed and the pair order is already pinned by {@link computeCoherenceConcession}, so the same
 * report always yields identical bytes — the `concession_hash` it carries is the canonical
 * fingerprint, reproducible from `pairs` (over the integer concession counts, ties, first-conceder,
 * and class; the derived float `affinity` and derived integer `comparisons` aside).
 */
export function buildCoherenceConcessionJson(concession: CoherenceConcession): string {
  return JSON.stringify(
    {
      schema: "vaulytica.posture-concession.v1",
      concession_hash: concession.concession_hash,
      rounds: concession.rounds,
      class_counts: concession.class_counts,
      total_ordered_comparisons: concession.total_ordered_comparisons,
      total_co_falls: concession.total_co_falls,
      max_affinity: concession.max_affinity,
      most_conceding_pair: concession.most_conceding_pair,
      first_conceding_front: concession.first_conceding_front,
      concedes: concession.concedes,
      pairs: concession.pairs.map((p) => ({
        dimension_a: p.dimension_a,
        dimension_b: p.dimension_b,
        a_concedes_first: p.a_concedes_first,
        b_concedes_first: p.b_concedes_first,
        co_falls: p.co_falls,
        comparisons: p.comparisons,
        first_conceder: p.first_conceder,
        affinity: p.affinity,
        class: p.class,
      })),
    },
    null,
    2,
  );
}

/** Render a concession-order affinity (0–1) as a whole-percent string, e.g. `0.75` → `"75%"`. */
function pct(affinity: number): string {
  return `${Math.round(affinity * 100)}%`;
}

/**
 * Render a {@link CoherenceConcession} as human-readable terminal lines: the most-conceding pairing
 * (the first-conceder, its follower, and the share of the comparisons it fell first, or none-conceding
 * when no front ever consistently conceded first), the class tally, then one line per
 * concession-order pair (its class, its first-conceder and lead share, and the ordered-vs-tied split),
 * `leading` pairs first. A pair the two never both fell in a different step is never listed (§3
 * honesty — no concession-order edge). Lives beside its JSON sibling so the CLI renders the report
 * from one definition.
 */
export function renderCoherenceConcessionSummary(concession: CoherenceConcession): string {
  const cc = concession.class_counts;
  const n = concession.rounds;
  const lines = [
    `\nCoherence exposure concession order across ${n} rounds (which front the counterparty concedes first within a pair):`,
    concession.most_conceding_pair === null
      ? `  most-conceding pairing: none — no front ever fell below the floor first for a strict majority of the comparisons.`
      : `  most-conceding pairing: ${concession.first_conceding_front} concedes before ${
          concession.most_conceding_pair[0] === concession.first_conceding_front
            ? concession.most_conceding_pair[1]
            : concession.most_conceding_pair[0]
        } — fell first ${pct(concession.max_affinity!)} of the comparisons.`,
    `  pairs: ${cc.leading} leading (one front consistently concedes first), ${cc.interleaved} interleaved.`,
  ];
  // Leading pairs first (the stable concession order), then interleaved; each group keeps the
  // (dimension_a, dimension_b) order the pairs already carry.
  for (const p of [
    ...concession.pairs.filter((p) => p.class === "leading"),
    ...concession.pairs.filter((p) => p.class === "interleaved"),
  ]) {
    const mark = p.class === "leading" ? "⚠" : "·";
    const order =
      p.first_conceder === null
        ? `${p.a_concedes_first}/${p.b_concedes_first} split`
        : `${p.first_conceder} first ${p.first_conceder === p.dimension_a ? p.a_concedes_first : p.b_concedes_first} of ${p.comparisons}`;
    lines.push(
      `  ${mark} ${p.dimension_a} + ${p.dimension_b}: ${p.class} — ${order} (${pct(p.affinity)}); ${p.co_falls} same-step tie${p.co_falls === 1 ? "" : "s"}.`,
    );
  }
  lines.push(`  concession_hash: ${concession.concession_hash}`);
  return lines.join("\n") + "\n";
}
