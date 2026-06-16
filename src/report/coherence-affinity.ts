/**
 * Cross-document negotiation-posture **exposure co-fall affinity** — per unordered
 * *pair* of fronts, how reliably the two fell below the acceptable floor *together*
 * across the whole sequence: how many round-transitions saw **both** fall (`co_falls`),
 * out of the transitions in which **either** fell (`union_falls`), the resulting
 * `affinity` (`co_falls / union_falls` — the Jaccard overlap of the two fronts' fall-step
 * sets), the deal's **tightest pairing** (`max_affinity` / `tightest_pair`), and whether
 * any pair fell together for a strict **majority** of the steps either fell (`coupled`)
 * (spec-v32).
 *
 * v29 ({@link computeCoherenceConcurrency}) reads the posture archive on the *per-step
 * fall count* axis: for each round-transition, how many fronts *fell* below floor
 * together (the deal's coordinated collapse, `falling ≥ 2`, a *concerted fall*). Its gate
 * fires on the **endpoint of a single step** — was there a round the package lurched,
 * two-plus fronts down at once? But it records the event and discards the **relation**:
 * v29 lists *which* fronts fell each step (`falling_dimensions`) but never asks, across
 * the sequence, **is it the same two fronts, again and again?** Two deals with byte-
 * identical v29 concurrency profiles (same per-step fall counts) can be opposites:
 *
 * - The **stable coupling.** Cap and Term fall together in rounds 3, 5, and 6 — every
 *   time either fell, the other fell with it. The counterparty concedes them as a
 *   **block** (a linked concession).
 * - The **coincidence.** Round 3 it was Cap and Term, round 5 Cap and Fee, round 6 Term
 *   and Risk — three concerted falls, three *different* pairs, none repeating. The same
 *   `concerted_fall_count` (3), the same per-step counts, but **no coupling**.
 *
 * To v29 these are indistinguishable (same counts). The difference is **pairwise**, and
 * it is the first axis the posture family has that is *not* a per-front, per-round, or
 * per-episode scalar: a per-**pair** relation, aggregated across the whole deal.
 *
 * It reuses v29's exact *fall* event (at-or-above → below, silence-skipping per §3), so a
 * co-fall is two fronts both registering a v29 fall in the same transition; it adds **no**
 * posture math beyond a per-pair overlap of those fall-step sets. By construction
 * `total_co_falls` equals `Σ_t C(falling_t, 2)` (v29's per-step fall counts choose-two'd)
 * and `total_falls` equals v29's `total_falls`. The posture filter (spec-v10 §3), restated:
 *  - **Deterministic** — same N coherences in the same order → identical `affinity_hash`,
 *    on any machine. Fronts are pinned by `localeCompare(_, "en")` (the same order the
 *    trajectory/exposure/concurrency functions use); unordered pairs are enumerated in
 *    that pinned order (`dimension_a < dimension_b`); the tightest-pair pick is decided by
 *    *integer cross-multiplication* (`co × union` of the two pairs), never a float compare.
 *  - **Honest about unstated data** — a front no document states in a round does not
 *    *fall* into or out of that round: silence is neither a fall nor a recovery (the §3
 *    contract that keeps `below → unstated → below` zero falls in v29). A pair that never
 *    both-fell is omitted from `pairs[]` (no affinity edge), never ranked.
 *  - **Advisory** — the report names which fronts fell below the team's own floor together,
 *    and how reliably. It asserts no legal conclusion.
 *  - **Additive** — the affinity carries its own `affinity_hash`, namespaced apart from
 *    every `coherence_hash`, `movement_hash`, `trajectory_hash`, `shift_trajectory_hash`,
 *    `arc_hash`, `exposure_hash`, `persistence_hash`, `breadth_hash`, `recurrence_hash`,
 *    `volatility_hash`, `synchrony_hash`, `settling_hash`, `onset_hash`, `latency_hash`,
 *    `concurrency_hash`, `relapse_hash`, and `tenure_hash`, so computing it moves no golden.
 */

import type { NegotiationTier } from "../playbooks/custom-interpreter.js";
import { sha256Hex } from "../ingest/hash.js";
import { stableStringify } from "../engine/runner.js";
import type { PostureCoherence } from "./posture-coherence.js";

/** The team's acceptable floor — the one rung whose name means "below what we will accept." */
const BELOW_FLOOR: NegotiationTier = "below-acceptable";

/**
 * One pair's co-fall coupling class:
 *  - `coupled` — the two fronts fell together for a *strict majority* of the steps in
 *    which either fell (`co_falls × 2 > union_falls`) — they fell together more often than
 *    apart, a stable concession pairing (the gate-worthy class);
 *  - `incidental` — they fell together in ≥ 1 step but not a strict majority of the union
 *    (including an exact split, e.g. together 1 of a 2-step union).
 *
 * Only pairs with `co_falls ≥ 1` are classified; a pair that never both-fell has no
 * affinity edge and is omitted from the report.
 */
export type AffinityClass = "coupled" | "incidental";

/** One unordered pair of fronts' whole-sequence co-fall relation. */
export type CoherenceAffinityPair = {
  /** The earlier front of the pair (`localeCompare` order). */
  dimension_a: string;
  /** The later front of the pair (`dimension_a < dimension_b`). */
  dimension_b: string;
  /** Front A's total falls across the sequence (at-or-above → below transitions). */
  a_falls: number;
  /** Front B's total falls across the sequence. */
  b_falls: number;
  /** How many transitions saw *both* fronts fall in the same step (the numerator). */
  co_falls: number;
  /** How many transitions saw *either* front fall (`a_falls + b_falls − co_falls`, the denominator). */
  union_falls: number;
  /** The co-fall affinity `co_falls / union_falls` (the Jaccard overlap of the fall-step sets). */
  affinity: number;
  /** The coupling class. */
  class: AffinityClass;
};

export type CoherenceAffinity = {
  /** How many rounds (coherences) the affinity spans. */
  rounds: number;
  /** The co-falling pairs (`co_falls ≥ 1`), pinned by `(dimension_a, dimension_b)`. */
  pairs: CoherenceAffinityPair[];
  /** Per-pair tally by coupling class. */
  class_counts: Record<AffinityClass, number>;
  /** Every pair's co-falls, summed — equals `Σ_t C(falling_t, 2)` over v29's per-step fall counts. */
  total_co_falls: number;
  /** Every front's falls, summed — equals v29's `total_falls` (and v24's per-front fall-crossing sum). */
  total_falls: number;
  /** The tightest coupling across the deal — the largest `affinity` (`null` when no two fronts ever fell together). */
  max_affinity: number | null;
  /** The pair owning {@link max_affinity} (earliest on a tie; `null` when none ever co-fell). */
  tightest_pair: [string, string] | null;
  /** Was any pair a strict-majority coupling? The gate-worthy verdict. */
  coupled: boolean;
  /** SHA-256 over the canonical per-pair set — additive, apart from every other hash. */
  affinity_hash: string;
};

function emptyClassCounts(): Record<AffinityClass, number> {
  return { coupled: 0, incidental: 0 };
}

/**
 * Walk N cross-document posture coherences — the same bundle at round 1, round 2, …,
 * round N — and report, *per unordered pair of fronts*, how reliably the two fell below
 * the acceptable floor *together*: how many transitions saw both fall (`co_falls`) out of
 * the transitions either fell (`union_falls`), the resulting `affinity`, the deal's
 * tightest such pairing (`max_affinity` / `tightest_pair`), and whether any pair fell
 * together for a strict majority of the steps either fell (`coupled`) — not merely how
 * many fronts fell in a single step (v29's per-step count).
 *
 * Pure and deterministic: fronts are matched by dimension and pinned by `localeCompare`,
 * unordered pairs are enumerated in that order, the round order is the caller's, the
 * tightest-pair pick uses integer cross-multiplication (never a float comparison), and
 * `affinity_hash` is over the canonical per-pair set, so the same N coherences in the same
 * order always yield identical bytes.
 *
 * A *fall* is exactly v29's: a transition between two *stated* rounds from at-or-above the
 * floor to below it; an unstated round is skipped (it neither falls nor resets the
 * standing, §3), so a fall across a silent gap is attributed to the transition into the
 * round that *reveals* the new standing. A *co-fall* of a pair is a transition at which
 * **both** fronts fell. Summed over all pairs, the co-fall count equals `Σ_t C(falling_t,
 * 2)` over v29's per-step fall counts; `total_falls` equals v29's `total_falls`.
 *
 * Every coherence must have been computed against the **same** team positions (the caller
 * applies one active playbook to every document in every round); comparing floors across
 * different ladders is nonsense, the same way v13/v16 refuse a cross-ladder diff. The CLI
 * core ({@link computeCoherenceAffinityArtifacts}) enforces this via the v15/v16 ladder
 * guard before calling this.
 *
 * Requires at least two rounds — a co-fall is a *between-round* event; a single round has
 * no transition to register a fall over.
 */
export async function computeCoherenceAffinity(
  rounds: readonly PostureCoherence[],
): Promise<CoherenceAffinity> {
  if (rounds.length < 2) {
    throw new Error(`an affinity needs at least two rounds (got ${rounds.length})`);
  }

  const byDim = rounds.map((c) => new Map(c.dimensions.map((d) => [d.dimension, d])));
  const labels = Array.from(
    new Set(rounds.flatMap((c) => c.dimensions.map((d) => d.dimension))),
  ).sort((a, b) => a.localeCompare(b, "en"));

  // Per front, the set of transition indices (0…N−2) at which it *fell* — the same v29
  // fall event, silence-skipping (§3): a flip at-or-above → below vs. the previous *stated*
  // round, held at the transition into the round that reveals the new standing.
  const fallStepsByDim = new Map<string, Set<number>>();
  for (const dimension of labels) {
    const floors = byDim.map((m) => m.get(dimension)?.weakest_tier ?? null);
    const fallSteps = new Set<number>();
    let prevBelow: boolean | null = null; // the last *stated* round's below-floor state
    for (let i = 0; i < floors.length; i++) {
      const t = floors[i];
      if (t === null) continue; // silence: neither falls nor resets the standing (§3)
      const isBelow = t === BELOW_FLOOR;
      // A fall (at-or-above → below) is registered on the step ending at round i+1, i.e.
      // transition (i → i+1), held at per-transition index i−1.
      if (prevBelow === false && isBelow) fallSteps.add(i - 1);
      prevBelow = isBelow;
    }
    fallStepsByDim.set(dimension, fallSteps);
  }

  const class_counts = emptyClassCounts();
  let total_co_falls = 0;
  let total_falls = 0;
  for (const dimension of labels) total_falls += fallStepsByDim.get(dimension)!.size;

  // The tightest affinity, tracked as an exact integer ratio (co/union) to avoid any float
  // comparison: the running best is `(bestCo, bestUnion)`.
  let bestCo = 0;
  let bestUnion = 0;
  let tightest_pair: [string, string] | null = null;
  let coupled = false;

  const pairs: CoherenceAffinityPair[] = [];
  for (let i = 0; i < labels.length; i++) {
    const dimension_a = labels[i]!;
    const fa = fallStepsByDim.get(dimension_a)!;
    for (let j = i + 1; j < labels.length; j++) {
      const dimension_b = labels[j]!;
      const fb = fallStepsByDim.get(dimension_b)!;

      let co_falls = 0;
      for (const step of fa) if (fb.has(step)) co_falls += 1;
      if (co_falls === 0) continue; // no affinity edge — both fronts never fell the same step

      const a_falls = fa.size;
      const b_falls = fb.size;
      const union_falls = a_falls + b_falls - co_falls;
      const affinity = co_falls / union_falls;
      // Strict majority of the union (cross-multiplied to stay integer-exact).
      const klass: AffinityClass = co_falls * 2 > union_falls ? "coupled" : "incidental";
      if (klass === "coupled") coupled = true;
      class_counts[klass] += 1;
      total_co_falls += co_falls;

      // The tightest affinity across the deal: the first pair (in label order) whose
      // affinity strictly exceeds the running best wins. `co/union > bestCo/bestUnion`
      // ⟺ `co × bestUnion > bestCo × union` (all non-negative integers), so the ranking is
      // exact — no float comparison, no platform drift.
      if (tightest_pair === null || co_falls * bestUnion > bestCo * union_falls) {
        bestCo = co_falls;
        bestUnion = union_falls;
        tightest_pair = [dimension_a, dimension_b];
      }

      pairs.push({
        dimension_a,
        dimension_b,
        a_falls,
        b_falls,
        co_falls,
        union_falls,
        affinity,
        class: klass,
      });
    }
  }

  const max_affinity = tightest_pair === null ? null : bestCo / bestUnion;

  const affinity_hash = await sha256Hex(
    stableStringify({
      rounds: rounds.length,
      pairs: pairs.map((p) => ({
        dimension_a: p.dimension_a,
        dimension_b: p.dimension_b,
        a_falls: p.a_falls,
        b_falls: p.b_falls,
        co_falls: p.co_falls,
        class: p.class,
      })),
    }),
  );

  return {
    rounds: rounds.length,
    pairs,
    class_counts,
    total_co_falls,
    total_falls,
    max_affinity,
    tightest_pair,
    coupled,
    affinity_hash,
  };
}

/**
 * Did any pair of fronts fall below the team's acceptable floor *together* for a strict
 * **majority** of the steps in which either fell — is there a stable concession pairing
 * the counterparty trades as a block? The CI gate predicate — the *pairwise* counterpart
 * to v29's *per-step* gate. Unlike `exposureConcerted` (which fires on a single step where
 * ≥2 fronts fell at once — a one-off lurch trips it, even three *different* pairs each
 * falling together once), this fires on a *stable relation*: two fronts that fell together
 * more often than they fell apart, across the deal, **even if no single step ever saw a
 * third front down**. It needs no tuning — a strict majority of the union *is* "they fall
 * together more often than not." A pair that fell together once but apart twice is
 * `incidental` and clears it; a consumer wanting a different bar reads `affinity` and
 * `max_affinity` from the JSON. **Distinct from v29's `exposureConcerted`**: every co-fall
 * step is a v29 concerted-fall step (two fronts down at once), so `coupled` for a pair
 * implies a concerted step — but the reverse fails where it matters: three coincidental
 * concerted falls (different pairs) trip v29 yet leave every pair `incidental` here.
 */
export function exposureCoupled(affinity: CoherenceAffinity): boolean {
  return affinity.coupled;
}

/**
 * Serialize a {@link CoherenceAffinity} to a stable, pretty-printed JSON string. The key
 * order is fixed and the pair order is already pinned by {@link computeCoherenceAffinity},
 * so the same affinity always yields identical bytes — the `affinity_hash` it carries is
 * the canonical fingerprint, reproducible from `pairs` (over the integer fall counts; the
 * derived float `affinity` and derived integer `union_falls` aside).
 */
export function buildCoherenceAffinityJson(affinity: CoherenceAffinity): string {
  return JSON.stringify(
    {
      schema: "vaulytica.posture-affinity.v1",
      affinity_hash: affinity.affinity_hash,
      rounds: affinity.rounds,
      class_counts: affinity.class_counts,
      total_co_falls: affinity.total_co_falls,
      total_falls: affinity.total_falls,
      max_affinity: affinity.max_affinity,
      tightest_pair: affinity.tightest_pair,
      coupled: affinity.coupled,
      pairs: affinity.pairs.map((p) => ({
        dimension_a: p.dimension_a,
        dimension_b: p.dimension_b,
        a_falls: p.a_falls,
        b_falls: p.b_falls,
        co_falls: p.co_falls,
        union_falls: p.union_falls,
        affinity: p.affinity,
        class: p.class,
      })),
    },
    null,
    2,
  );
}

/** Render a co-fall affinity (0–1) as a whole-percent string, e.g. `0.75` → `"75%"`. */
function pct(affinity: number): string {
  return `${Math.round(affinity * 100)}%`;
}

/**
 * Render a {@link CoherenceAffinity} as human-readable terminal lines: the tightest
 * pairing (the pair and the share of the steps either fell that both fell, or none-paired
 * when no two fronts ever fell together), the class tally, then one line per co-falling
 * pair (its class, its overlap, and each front's own fall count), `coupled` pairs first.
 * A pair that never both-fell is never listed (§3 honesty — no affinity edge). Lives beside
 * its JSON sibling so the CLI renders the affinity from one definition.
 */
export function renderCoherenceAffinitySummary(affinity: CoherenceAffinity): string {
  const cc = affinity.class_counts;
  const n = affinity.rounds;
  const lines = [
    `\nCoherence exposure co-fall affinity across ${n} rounds (which fronts fell below floor together):`,
    affinity.tightest_pair === null
      ? `  tightest pairing: none — no two fronts ever fell below the floor in the same step.`
      : `  tightest pairing: ${affinity.tightest_pair[0]} + ${affinity.tightest_pair[1]} — fell together ${pct(affinity.max_affinity!)} of the steps either fell.`,
    `  pairs: ${cc.coupled} coupled (fell together more often than apart), ${cc.incidental} incidental.`,
  ];
  // Coupled pairs first (the stable linkage), then incidental; each group keeps the
  // (dimension_a, dimension_b) order the pairs already carry.
  for (const p of [
    ...affinity.pairs.filter((p) => p.class === "coupled"),
    ...affinity.pairs.filter((p) => p.class === "incidental"),
  ]) {
    const mark = p.class === "coupled" ? "⚠" : "·";
    lines.push(
      `  ${mark} ${p.dimension_a} + ${p.dimension_b}: ${p.class} — together ${p.co_falls} of ${p.union_falls} step${p.union_falls === 1 ? "" : "s"} either fell (${pct(p.affinity)}); ${p.dimension_a} fell ${p.a_falls}×, ${p.dimension_b} fell ${p.b_falls}×.`,
    );
  }
  lines.push(`  affinity_hash: ${affinity.affinity_hash}`);
  return lines.join("\n") + "\n";
}
