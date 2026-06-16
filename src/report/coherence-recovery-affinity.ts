/**
 * Cross-document negotiation-posture **exposure co-recovery affinity** — per unordered
 * *pair* of fronts, how reliably the two climbed back at-or-above the acceptable floor
 * *together* across the whole sequence: how many round-transitions saw **both** recover
 * (`co_recoveries`), out of the transitions in which **either** recovered
 * (`union_recoveries`), the resulting `affinity` (`co_recoveries / union_recoveries` — the
 * Jaccard overlap of the two fronts' recovery-step sets), the deal's **tightest pairing**
 * (`max_affinity` / `tightest_pair`), and whether any pair recovered together for a strict
 * **majority** of the steps either recovered (`coupled`) (spec-v33).
 *
 * This is the exact mirror of v32 ({@link computeCoherenceAffinity}) on the **recovery**
 * direction, as v30 mirrors v28's latency on the relapse direction and v27 mirrors v26's
 * settling on the onset direction. v32 reads, per pair, how reliably two fronts *fell*
 * below floor together — the *concession* linkage the counterparty trades as a block. But
 * the floor is crossed two ways, and v32 reads only one. v29 resolved each step into *falls*
 * and *recoveries*; v32 took the pairwise overlap of the **fall** direction. The mirror is
 * unread: across the deal, **which two fronts does the counterparty keep *restoring* as a
 * block?** A recovery on front A that only ever lands alongside a recovery on front B is a
 * *linked recovery* — A is hostage to B, repaired as a bundle, never alone. Two deals with
 * byte-identical v32 co-fall affinity (the same fronts conceded together) can be opposites:
 *
 * - The **linked recovery.** Cap and Term recover together in rounds 4 and 6 — every time
 *   either climbed back above floor, the other climbed with it. The counterparty restores
 *   them as a **block** (a recovery linkage — you cannot get Cap back without Term).
 * - The **independent recovery.** Round 4 Cap recovered alone, round 5 Term alone, round 6
 *   Fee alone — three recoveries, none repeating. The same v29 per-step recovery counts, but
 *   **no recovery coupling**.
 *
 * To v32 these are indistinguishable (v32 reads only falls). The difference is **pairwise on
 * the recovery direction** — the missing mirror of v32's pairwise reduction.
 *
 * It reuses v29's exact *recovery* event (below → at-or-above, silence-skipping per §3), so a
 * co-recovery is two fronts both registering a v29 recovery in the same transition; it adds
 * **no** posture math beyond a per-pair overlap of those recovery-step sets. By construction
 * `total_co_recoveries` equals `Σ_t C(recovering_t, 2)` (v29's per-step recovery counts
 * choose-two'd) and `total_recoveries` equals v29's `total_recoveries`. The posture filter
 * (spec-v10 §3), restated:
 *  - **Deterministic** — same N coherences in the same order → identical
 *    `recovery_affinity_hash`, on any machine. Fronts are pinned by `localeCompare(_, "en")`
 *    (the same order the trajectory/exposure/concurrency/affinity functions use); unordered
 *    pairs are enumerated in that pinned order (`dimension_a < dimension_b`); the
 *    tightest-pair pick is decided by *integer cross-multiplication* (`co × union` of the two
 *    pairs), never a float compare.
 *  - **Honest about unstated data** — a front no document states in a round does not
 *    *recover* into or out of that round: silence is neither a fall nor a recovery (the §3
 *    contract that keeps `below → unstated → below` zero recoveries in v29). A pair that
 *    never both-recovered is omitted from `pairs[]` (no affinity edge), never ranked.
 *  - **Advisory** — the report names which fronts climbed back above the team's own floor
 *    together, and how reliably. It asserts no legal conclusion.
 *  - **Additive** — the affinity carries its own `recovery_affinity_hash`, namespaced apart
 *    from every `coherence_hash`, `movement_hash`, `trajectory_hash`, `shift_trajectory_hash`,
 *    `arc_hash`, `exposure_hash`, `persistence_hash`, `breadth_hash`, `recurrence_hash`,
 *    `volatility_hash`, `synchrony_hash`, `settling_hash`, `onset_hash`, `latency_hash`,
 *    `concurrency_hash`, `relapse_hash`, `tenure_hash`, and `affinity_hash`, so computing it
 *    moves no golden.
 */

import type { NegotiationTier } from "../playbooks/custom-interpreter.js";
import { sha256Hex } from "../ingest/hash.js";
import { stableStringify } from "../engine/runner.js";
import type { PostureCoherence } from "./posture-coherence.js";

/** The team's acceptable floor — the one rung whose name means "below what we will accept." */
const BELOW_FLOOR: NegotiationTier = "below-acceptable";

/**
 * One pair's co-recovery coupling class:
 *  - `coupled` — the two fronts recovered together for a *strict majority* of the steps in
 *    which either recovered (`co_recoveries × 2 > union_recoveries`) — they recovered together
 *    more often than apart, a stable restoration pairing (the gate-worthy class);
 *  - `incidental` — they recovered together in ≥ 1 step but not a strict majority of the union
 *    (including an exact split, e.g. together 1 of a 2-step union).
 *
 * Only pairs with `co_recoveries ≥ 1` are classified; a pair that never both-recovered has no
 * affinity edge and is omitted from the report.
 */
export type RecoveryAffinityClass = "coupled" | "incidental";

/** One unordered pair of fronts' whole-sequence co-recovery relation. */
export type CoherenceRecoveryAffinityPair = {
  /** The earlier front of the pair (`localeCompare` order). */
  dimension_a: string;
  /** The later front of the pair (`dimension_a < dimension_b`). */
  dimension_b: string;
  /** Front A's total recoveries across the sequence (below → at-or-above transitions). */
  a_recoveries: number;
  /** Front B's total recoveries across the sequence. */
  b_recoveries: number;
  /** How many transitions saw *both* fronts recover in the same step (the numerator). */
  co_recoveries: number;
  /** How many transitions saw *either* front recover (`a_recoveries + b_recoveries − co_recoveries`, the denominator). */
  union_recoveries: number;
  /** The co-recovery affinity `co_recoveries / union_recoveries` (the Jaccard overlap of the recovery-step sets). */
  affinity: number;
  /** The coupling class. */
  class: RecoveryAffinityClass;
};

export type CoherenceRecoveryAffinity = {
  /** How many rounds (coherences) the affinity spans. */
  rounds: number;
  /** The co-recovering pairs (`co_recoveries ≥ 1`), pinned by `(dimension_a, dimension_b)`. */
  pairs: CoherenceRecoveryAffinityPair[];
  /** Per-pair tally by coupling class. */
  class_counts: Record<RecoveryAffinityClass, number>;
  /** Every pair's co-recoveries, summed — equals `Σ_t C(recovering_t, 2)` over v29's per-step recovery counts. */
  total_co_recoveries: number;
  /** Every front's recoveries, summed — equals v29's `total_recoveries` (and the recovery half of v24's crossings). */
  total_recoveries: number;
  /** The tightest coupling across the deal — the largest `affinity` (`null` when no two fronts ever recovered together). */
  max_affinity: number | null;
  /** The pair owning {@link max_affinity} (earliest on a tie; `null` when none ever co-recovered). */
  tightest_pair: [string, string] | null;
  /** Was any pair a strict-majority coupling? The gate-worthy verdict. */
  coupled: boolean;
  /** SHA-256 over the canonical per-pair set — additive, apart from every other hash. */
  recovery_affinity_hash: string;
};

function emptyClassCounts(): Record<RecoveryAffinityClass, number> {
  return { coupled: 0, incidental: 0 };
}

/**
 * Walk N cross-document posture coherences — the same bundle at round 1, round 2, …,
 * round N — and report, *per unordered pair of fronts*, how reliably the two climbed back
 * at-or-above the acceptable floor *together*: how many transitions saw both recover
 * (`co_recoveries`) out of the transitions either recovered (`union_recoveries`), the
 * resulting `affinity`, the deal's tightest such pairing (`max_affinity` / `tightest_pair`),
 * and whether any pair recovered together for a strict majority of the steps either recovered
 * (`coupled`) — not merely how many fronts recovered in a single step (v29's per-step count),
 * and not the *fall* direction (v32's co-fall affinity).
 *
 * Pure and deterministic: fronts are matched by dimension and pinned by `localeCompare`,
 * unordered pairs are enumerated in that order, the round order is the caller's, the
 * tightest-pair pick uses integer cross-multiplication (never a float comparison), and
 * `recovery_affinity_hash` is over the canonical per-pair set, so the same N coherences in
 * the same order always yield identical bytes.
 *
 * A *recovery* is exactly v29's: a transition between two *stated* rounds from below the floor
 * to at-or-above it; an unstated round is skipped (it neither recovers nor resets the
 * standing, §3), so a recovery across a silent gap is attributed to the transition into the
 * round that *reveals* the new standing. A *co-recovery* of a pair is a transition at which
 * **both** fronts recovered. Summed over all pairs, the co-recovery count equals
 * `Σ_t C(recovering_t, 2)` over v29's per-step recovery counts; `total_recoveries` equals
 * v29's `total_recoveries`.
 *
 * Every coherence must have been computed against the **same** team positions (the caller
 * applies one active playbook to every document in every round); comparing floors across
 * different ladders is nonsense, the same way v13/v16 refuse a cross-ladder diff. The CLI
 * core ({@link computeCoherenceRecoveryAffinityArtifacts}) enforces this via the v15/v16
 * ladder guard before calling this.
 *
 * Requires at least two rounds — a co-recovery is a *between-round* event; a single round has
 * no transition to register a recovery over.
 */
export async function computeCoherenceRecoveryAffinity(
  rounds: readonly PostureCoherence[],
): Promise<CoherenceRecoveryAffinity> {
  if (rounds.length < 2) {
    throw new Error(`a recovery affinity needs at least two rounds (got ${rounds.length})`);
  }

  const byDim = rounds.map((c) => new Map(c.dimensions.map((d) => [d.dimension, d])));
  const labels = Array.from(
    new Set(rounds.flatMap((c) => c.dimensions.map((d) => d.dimension))),
  ).sort((a, b) => a.localeCompare(b, "en"));

  // Per front, the set of transition indices (0…N−2) at which it *recovered* — the same v29
  // recovery event, silence-skipping (§3): a flip below → at-or-above vs. the previous *stated*
  // round, held at the transition into the round that reveals the new standing.
  const recoveryStepsByDim = new Map<string, Set<number>>();
  for (const dimension of labels) {
    const floors = byDim.map((m) => m.get(dimension)?.weakest_tier ?? null);
    const recoverySteps = new Set<number>();
    let prevBelow: boolean | null = null; // the last *stated* round's below-floor state
    for (let i = 0; i < floors.length; i++) {
      const t = floors[i];
      if (t === null) continue; // silence: neither recovers nor resets the standing (§3)
      const isBelow = t === BELOW_FLOOR;
      // A recovery (below → at-or-above) is registered on the step ending at round i+1, i.e.
      // transition (i → i+1), held at per-transition index i−1.
      if (prevBelow === true && !isBelow) recoverySteps.add(i - 1);
      prevBelow = isBelow;
    }
    recoveryStepsByDim.set(dimension, recoverySteps);
  }

  const class_counts = emptyClassCounts();
  let total_co_recoveries = 0;
  let total_recoveries = 0;
  for (const dimension of labels) total_recoveries += recoveryStepsByDim.get(dimension)!.size;

  // The tightest affinity, tracked as an exact integer ratio (co/union) to avoid any float
  // comparison: the running best is `(bestCo, bestUnion)`.
  let bestCo = 0;
  let bestUnion = 0;
  let tightest_pair: [string, string] | null = null;
  let coupled = false;

  const pairs: CoherenceRecoveryAffinityPair[] = [];
  for (let i = 0; i < labels.length; i++) {
    const dimension_a = labels[i]!;
    const ra = recoveryStepsByDim.get(dimension_a)!;
    for (let j = i + 1; j < labels.length; j++) {
      const dimension_b = labels[j]!;
      const rb = recoveryStepsByDim.get(dimension_b)!;

      let co_recoveries = 0;
      for (const step of ra) if (rb.has(step)) co_recoveries += 1;
      if (co_recoveries === 0) continue; // no affinity edge — both fronts never recovered the same step

      const a_recoveries = ra.size;
      const b_recoveries = rb.size;
      const union_recoveries = a_recoveries + b_recoveries - co_recoveries;
      const affinity = co_recoveries / union_recoveries;
      // Strict majority of the union (cross-multiplied to stay integer-exact).
      const klass: RecoveryAffinityClass =
        co_recoveries * 2 > union_recoveries ? "coupled" : "incidental";
      if (klass === "coupled") coupled = true;
      class_counts[klass] += 1;
      total_co_recoveries += co_recoveries;

      // The tightest affinity across the deal: the first pair (in label order) whose affinity
      // strictly exceeds the running best wins. `co/union > bestCo/bestUnion` ⟺
      // `co × bestUnion > bestCo × union` (all non-negative integers), so the ranking is exact
      // — no float comparison, no platform drift.
      if (tightest_pair === null || co_recoveries * bestUnion > bestCo * union_recoveries) {
        bestCo = co_recoveries;
        bestUnion = union_recoveries;
        tightest_pair = [dimension_a, dimension_b];
      }

      pairs.push({
        dimension_a,
        dimension_b,
        a_recoveries,
        b_recoveries,
        co_recoveries,
        union_recoveries,
        affinity,
        class: klass,
      });
    }
  }

  const max_affinity = tightest_pair === null ? null : bestCo / bestUnion;

  const recovery_affinity_hash = await sha256Hex(
    stableStringify({
      rounds: rounds.length,
      pairs: pairs.map((p) => ({
        dimension_a: p.dimension_a,
        dimension_b: p.dimension_b,
        a_recoveries: p.a_recoveries,
        b_recoveries: p.b_recoveries,
        co_recoveries: p.co_recoveries,
        class: p.class,
      })),
    }),
  );

  return {
    rounds: rounds.length,
    pairs,
    class_counts,
    total_co_recoveries,
    total_recoveries,
    max_affinity,
    tightest_pair,
    coupled,
    recovery_affinity_hash,
  };
}

/**
 * Did any pair of fronts climb back at-or-above the team's acceptable floor *together* for a
 * strict **majority** of the steps in which either recovered — is there a stable restoration
 * pairing the counterparty trades as a block? The CI gate predicate — the *recovery-direction*
 * counterpart to v32's *fall-direction* gate (`exposureCoupled`). Where v32 fires on a stable
 * *concession* pairing (two fronts that fell together more often than apart), this fires on a
 * stable *restoration* pairing (two fronts that recovered together more often than apart): a
 * front hostage to another on the way back up, never repaired alone. It needs no tuning — a
 * strict majority of the union *is* "they recover together more often than not." A pair that
 * recovered together once but apart twice is `incidental` and clears it; a consumer wanting a
 * different bar reads `affinity` and `max_affinity` from the JSON. **Distinct from v29's
 * `exposureConcerted`** (which fires on a single step where ≥2 fronts *fell*) and from v32's
 * `exposureCoupled` (the fall-direction pairing): a pair `coupled` on falls can be `incidental`
 * on recoveries and vice versa — the two directions are independent relations over the same
 * `floors[]` matrix.
 */
export function exposureRecoveryCoupled(affinity: CoherenceRecoveryAffinity): boolean {
  return affinity.coupled;
}

/**
 * Serialize a {@link CoherenceRecoveryAffinity} to a stable, pretty-printed JSON string. The
 * key order is fixed and the pair order is already pinned by
 * {@link computeCoherenceRecoveryAffinity}, so the same affinity always yields identical bytes
 * — the `recovery_affinity_hash` it carries is the canonical fingerprint, reproducible from
 * `pairs` (over the integer recovery counts; the derived float `affinity` and derived integer
 * `union_recoveries` aside).
 */
export function buildCoherenceRecoveryAffinityJson(affinity: CoherenceRecoveryAffinity): string {
  return JSON.stringify(
    {
      schema: "vaulytica.posture-recovery-affinity.v1",
      recovery_affinity_hash: affinity.recovery_affinity_hash,
      rounds: affinity.rounds,
      class_counts: affinity.class_counts,
      total_co_recoveries: affinity.total_co_recoveries,
      total_recoveries: affinity.total_recoveries,
      max_affinity: affinity.max_affinity,
      tightest_pair: affinity.tightest_pair,
      coupled: affinity.coupled,
      pairs: affinity.pairs.map((p) => ({
        dimension_a: p.dimension_a,
        dimension_b: p.dimension_b,
        a_recoveries: p.a_recoveries,
        b_recoveries: p.b_recoveries,
        co_recoveries: p.co_recoveries,
        union_recoveries: p.union_recoveries,
        affinity: p.affinity,
        class: p.class,
      })),
    },
    null,
    2,
  );
}

/** Render a co-recovery affinity (0–1) as a whole-percent string, e.g. `0.75` → `"75%"`. */
function pct(affinity: number): string {
  return `${Math.round(affinity * 100)}%`;
}

/**
 * Render a {@link CoherenceRecoveryAffinity} as human-readable terminal lines: the tightest
 * pairing (the pair and the share of the steps either recovered that both recovered, or
 * none-paired when no two fronts ever recovered together), the class tally, then one line per
 * co-recovering pair (its class, its overlap, and each front's own recovery count), `coupled`
 * pairs first. A pair that never both-recovered is never listed (§3 honesty — no affinity
 * edge). Lives beside its JSON sibling so the CLI renders the affinity from one definition.
 */
export function renderCoherenceRecoveryAffinitySummary(
  affinity: CoherenceRecoveryAffinity,
): string {
  const cc = affinity.class_counts;
  const n = affinity.rounds;
  const lines = [
    `\nCoherence exposure co-recovery affinity across ${n} rounds (which fronts climbed back above floor together):`,
    affinity.tightest_pair === null
      ? `  tightest pairing: none — no two fronts ever recovered above the floor in the same step.`
      : `  tightest pairing: ${affinity.tightest_pair[0]} + ${affinity.tightest_pair[1]} — recovered together ${pct(affinity.max_affinity!)} of the steps either recovered.`,
    `  pairs: ${cc.coupled} coupled (recovered together more often than apart), ${cc.incidental} incidental.`,
  ];
  // Coupled pairs first (the stable linkage), then incidental; each group keeps the
  // (dimension_a, dimension_b) order the pairs already carry.
  for (const p of [
    ...affinity.pairs.filter((p) => p.class === "coupled"),
    ...affinity.pairs.filter((p) => p.class === "incidental"),
  ]) {
    const mark = p.class === "coupled" ? "⚠" : "·";
    lines.push(
      `  ${mark} ${p.dimension_a} + ${p.dimension_b}: ${p.class} — together ${p.co_recoveries} of ${p.union_recoveries} step${p.union_recoveries === 1 ? "" : "s"} either recovered (${pct(p.affinity)}); ${p.dimension_a} recovered ${p.a_recoveries}×, ${p.dimension_b} recovered ${p.b_recoveries}×.`,
    );
  }
  lines.push(`  recovery_affinity_hash: ${affinity.recovery_affinity_hash}`);
  return lines.join("\n") + "\n";
}
