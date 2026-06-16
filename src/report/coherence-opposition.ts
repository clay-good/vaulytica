/**
 * Cross-document negotiation-posture **exposure counter-move affinity** — per unordered
 * *pair* of fronts, how often the two crossed the acceptable floor in the *same step* but in
 * **opposite directions** (one *fell*, the other *recovered*): a *see-saw* the counterparty
 * trades one front against the other. For each pair, how many transitions saw the two move
 * **opposite** ways (`opposed_moves`), out of the transitions in which **both** crossed
 * (`joint_moves` — `co_falls + co_recoveries + opposed_moves`), the resulting `affinity`
 * (`opposed_moves / joint_moves`), the deal's **most-opposed pairing** (`max_affinity` /
 * `most_opposed_pair`), and whether any pair counter-moved for a strict **majority** of the
 * steps both crossed (`opposed`) (spec-v34).
 *
 * This is the **off-diagonal completion** of v32 ({@link computeCoherenceAffinity}, co-fall)
 * and v33 ({@link computeCoherenceRecoveryAffinity}, co-recovery). v32 reads, per pair, how
 * reliably two fronts *fell* below floor together (the concession linkage); v33 reads how
 * reliably two fronts *recovered* together (the restoration linkage). Those are the two
 * **aligned** cells of the 2×2 of {A falls/recovers} × {B falls/recovers}. The remaining cell
 * is unread: across the deal, **which two fronts does the counterparty move in *opposite*
 * directions at once?** A step where Cap *falls* exactly as Term *recovers* is a *counter-move*
 * — a trade-off, the counterparty giving ground on one front precisely as it takes ground on
 * another. The two fronts are *substitutes*, bargaining chips swapped against each other. Two
 * deals with byte-identical v32 co-fall and v33 co-recovery affinity can be opposites:
 *
 * - The **see-saw.** Cap and Term swap in rounds 3 and 5 — every joint step, one fell as the
 *   other recovered. The counterparty trades them against each other (a substitution linkage —
 *   you concede Cap to recover Term, and back).
 * - The **aligned pair.** Cap and Term only ever fell together (v32) or recovered together
 *   (v33), never opposed. The same per-front crossing counts, but **no counter-movement**.
 *
 * To v32 and v33 these are indistinguishable (both read same-*direction* overlaps only). The
 * difference is **pairwise on the opposed direction** — the missing diagonal of the same
 * pairwise reduction.
 *
 * It reuses v29's exact *fall* and *recovery* events (silence-skipping per §3), so a
 * counter-move is one front registering a v29 fall while the other registers a v29 recovery in
 * the same transition; it adds **no** posture math beyond a per-pair overlap of those step
 * sets. By construction `total_opposed_moves` equals `Σ_t falling_t × recovering_t` (v29's
 * per-step counts cross-multiplied) and `total_aligned_moves` equals
 * `total_co_falls` (v32) `+ total_co_recoveries` (v33) `= Σ_t [C(falling_t, 2) + C(recovering_t, 2)]`;
 * their sum is `Σ_t C(crossing_t, 2)` (v25's per-step crossing count choose-two'd). The posture
 * filter (spec-v10 §3), restated:
 *  - **Deterministic** — same N coherences in the same order → identical `opposition_hash`, on
 *    any machine. Fronts are pinned by `localeCompare(_, "en")` (the same order the
 *    trajectory/exposure/concurrency/affinity functions use); unordered pairs are enumerated in
 *    that pinned order (`dimension_a < dimension_b`); the most-opposed pick is decided by
 *    *integer cross-multiplication* (`opposed × joint` of the two pairs), never a float compare.
 *  - **Honest about unstated data** — a front no document states in a round does not *cross*
 *    into or out of that round: silence is neither a fall nor a recovery (the §3 contract that
 *    keeps `below → unstated → below` zero crossings in v29). A pair that never counter-moved is
 *    omitted from `pairs[]` (no counter-move edge), never ranked.
 *  - **Advisory** — the report names which fronts the counterparty moved opposite ways across
 *    the team's own floor together, and how reliably. It asserts no legal conclusion.
 *  - **Additive** — the affinity carries its own `opposition_hash`, namespaced apart from every
 *    `coherence_hash`, `movement_hash`, `trajectory_hash`, `shift_trajectory_hash`, `arc_hash`,
 *    `exposure_hash`, `persistence_hash`, `breadth_hash`, `recurrence_hash`, `volatility_hash`,
 *    `synchrony_hash`, `settling_hash`, `onset_hash`, `latency_hash`, `concurrency_hash`,
 *    `relapse_hash`, `tenure_hash`, `affinity_hash`, and `recovery_affinity_hash`, so computing
 *    it moves no golden.
 */

import type { NegotiationTier } from "../playbooks/custom-interpreter.js";
import { sha256Hex } from "../ingest/hash.js";
import { stableStringify } from "../engine/runner.js";
import type { PostureCoherence } from "./posture-coherence.js";

/** The team's acceptable floor — the one rung whose name means "below what we will accept." */
const BELOW_FLOOR: NegotiationTier = "below-acceptable";

/**
 * One pair's counter-move coupling class:
 *  - `opposed` — the two fronts moved *opposite* ways for a *strict majority* of the steps in
 *    which both crossed (`opposed_moves × 2 > joint_moves`) — they counter-moved more often than
 *    they moved together, a stable see-saw pairing the counterparty trades one against the other
 *    (the gate-worthy class);
 *  - `incidental` — they counter-moved in ≥ 1 step but not a strict majority of their joint
 *    moves (including an exact split, e.g. opposed 1 of a 2-step joint set).
 *
 * Only pairs with `opposed_moves ≥ 1` are classified; a pair that never counter-moved (always
 * aligned, or never jointly crossed) has no counter-move edge and is omitted from the report.
 */
export type OppositionClass = "opposed" | "incidental";

/** One unordered pair of fronts' whole-sequence counter-move relation. */
export type CoherenceOppositionPair = {
  /** The earlier front of the pair (`localeCompare` order). */
  dimension_a: string;
  /** The later front of the pair (`dimension_a < dimension_b`). */
  dimension_b: string;
  /** How many transitions saw *both* fronts *fall* in the same step (a v32 co-fall — an aligned move). */
  co_falls: number;
  /** How many transitions saw *both* fronts *recover* in the same step (a v33 co-recovery — an aligned move). */
  co_recoveries: number;
  /** How many transitions saw the two move *opposite* ways (one fell, one recovered) — the numerator. */
  opposed_moves: number;
  /** How many transitions saw *both* fronts cross (`co_falls + co_recoveries + opposed_moves`) — the denominator. */
  joint_moves: number;
  /** The counter-move affinity `opposed_moves / joint_moves` (the share of joint moves that opposed). */
  affinity: number;
  /** The coupling class. */
  class: OppositionClass;
};

export type CoherenceOpposition = {
  /** How many rounds (coherences) the affinity spans. */
  rounds: number;
  /** The counter-moving pairs (`opposed_moves ≥ 1`), pinned by `(dimension_a, dimension_b)`. */
  pairs: CoherenceOppositionPair[];
  /** Per-pair tally by coupling class. */
  class_counts: Record<OppositionClass, number>;
  /** Every pair's opposed moves, summed — equals `Σ_t falling_t × recovering_t` over v29's per-step counts. */
  total_opposed_moves: number;
  /** Every pair's aligned moves, summed — equals `total_co_falls` (v32) `+ total_co_recoveries` (v33). */
  total_aligned_moves: number;
  /** The most-opposed coupling across the deal — the largest `affinity` (`null` when no two fronts ever counter-moved). */
  max_affinity: number | null;
  /** The pair owning {@link max_affinity} (earliest on a tie; `null` when none ever counter-moved). */
  most_opposed_pair: [string, string] | null;
  /** Was any pair a strict-majority counter-move coupling? The gate-worthy verdict. */
  opposed: boolean;
  /** SHA-256 over the canonical per-pair set — additive, apart from every other hash. */
  opposition_hash: string;
};

function emptyClassCounts(): Record<OppositionClass, number> {
  return { opposed: 0, incidental: 0 };
}

/**
 * Walk N cross-document posture coherences — the same bundle at round 1, round 2, …, round N —
 * and report, *per unordered pair of fronts*, how often the two crossed the acceptable floor in
 * the same step but in *opposite directions* (one fell while the other recovered): how many
 * transitions saw the pair counter-move (`opposed_moves`) out of the transitions both crossed
 * (`joint_moves`), the resulting `affinity`, the deal's most-opposed such pairing
 * (`max_affinity` / `most_opposed_pair`), and whether any pair counter-moved for a strict
 * majority of the steps both crossed (`opposed`) — not the *aligned* directions (v32's co-fall,
 * v33's co-recovery), and not a per-step count (v29).
 *
 * Pure and deterministic: fronts are matched by dimension and pinned by `localeCompare`,
 * unordered pairs are enumerated in that order, the round order is the caller's, the
 * most-opposed pick uses integer cross-multiplication (never a float comparison), and
 * `opposition_hash` is over the canonical per-pair set, so the same N coherences in the same
 * order always yield identical bytes.
 *
 * A *fall* (at-or-above → below) and a *recovery* (below → at-or-above) are exactly v29's:
 * transitions between two *stated* rounds; an unstated round is skipped (it neither crosses nor
 * resets the standing, §3), so a crossing across a silent gap is attributed to the transition
 * into the round that *reveals* the new standing. A *counter-move* of a pair is a transition at
 * which one front fell and the other recovered. Summed over all pairs, the opposed count equals
 * `Σ_t falling_t × recovering_t`; the aligned count equals v32's `total_co_falls` plus v33's
 * `total_co_recoveries`.
 *
 * Every coherence must have been computed against the **same** team positions (the caller
 * applies one active playbook to every document in every round); comparing floors across
 * different ladders is nonsense, the same way v13/v16 refuse a cross-ladder diff. The CLI core
 * ({@link computeCoherenceOppositionArtifacts}) enforces this via the v15/v16 ladder guard
 * before calling this.
 *
 * Requires at least two rounds — a counter-move is a *between-round* event; a single round has
 * no transition to register a crossing over.
 */
export async function computeCoherenceOpposition(
  rounds: readonly PostureCoherence[],
): Promise<CoherenceOpposition> {
  if (rounds.length < 2) {
    throw new Error(`an opposition needs at least two rounds (got ${rounds.length})`);
  }

  const byDim = rounds.map((c) => new Map(c.dimensions.map((d) => [d.dimension, d])));
  const labels = Array.from(
    new Set(rounds.flatMap((c) => c.dimensions.map((d) => d.dimension))),
  ).sort((a, b) => a.localeCompare(b, "en"));

  // Per front, the sets of transition indices (0…N−2) at which it *fell* and at which it
  // *recovered* — the same v29 events, silence-skipping (§3): a flip vs. the previous *stated*
  // round, held at the transition into the round that reveals the new standing. A front cannot
  // both fall and recover at the same transition index (one standing flip per step), so the two
  // sets are disjoint.
  const fallStepsByDim = new Map<string, Set<number>>();
  const recoveryStepsByDim = new Map<string, Set<number>>();
  for (const dimension of labels) {
    const floors = byDim.map((m) => m.get(dimension)?.weakest_tier ?? null);
    const fallSteps = new Set<number>();
    const recoverySteps = new Set<number>();
    let prevBelow: boolean | null = null; // the last *stated* round's below-floor state
    for (let i = 0; i < floors.length; i++) {
      const t = floors[i];
      if (t === null) continue; // silence: neither crosses nor resets the standing (§3)
      const isBelow = t === BELOW_FLOOR;
      // A crossing vs. the previous stated round is held at per-transition index i−1.
      if (prevBelow === false && isBelow) fallSteps.add(i - 1);
      else if (prevBelow === true && !isBelow) recoverySteps.add(i - 1);
      prevBelow = isBelow;
    }
    fallStepsByDim.set(dimension, fallSteps);
    recoveryStepsByDim.set(dimension, recoverySteps);
  }

  const class_counts = emptyClassCounts();
  let total_opposed_moves = 0;
  let total_aligned_moves = 0;

  // The most-opposed affinity, tracked as an exact integer ratio (opposed/joint) to avoid any
  // float comparison: the running best is `(bestOpp, bestJoint)`.
  let bestOpp = 0;
  let bestJoint = 0;
  let most_opposed_pair: [string, string] | null = null;
  let opposed = false;

  const pairs: CoherenceOppositionPair[] = [];
  for (let i = 0; i < labels.length; i++) {
    const dimension_a = labels[i]!;
    const fa = fallStepsByDim.get(dimension_a)!;
    const ra = recoveryStepsByDim.get(dimension_a)!;
    for (let j = i + 1; j < labels.length; j++) {
      const dimension_b = labels[j]!;
      const fb = fallStepsByDim.get(dimension_b)!;
      const rb = recoveryStepsByDim.get(dimension_b)!;

      let co_falls = 0;
      for (const step of fa) if (fb.has(step)) co_falls += 1;
      let co_recoveries = 0;
      for (const step of ra) if (rb.has(step)) co_recoveries += 1;
      // Opposed: A fell while B recovered, plus A recovered while B fell.
      let opposed_moves = 0;
      for (const step of fa) if (rb.has(step)) opposed_moves += 1;
      for (const step of ra) if (fb.has(step)) opposed_moves += 1;

      // Accumulate the deal-level totals over *every* pair (an omitted aligned-only pair still
      // contributes its co_falls/co_recoveries to total_aligned_moves), so the join invariants
      // to v29/v32/v33 hold across the whole matrix.
      total_opposed_moves += opposed_moves;
      total_aligned_moves += co_falls + co_recoveries;

      if (opposed_moves === 0) continue; // no counter-move edge — the two never moved opposite ways

      const joint_moves = co_falls + co_recoveries + opposed_moves;
      const affinity = opposed_moves / joint_moves;
      // Strict majority of the joint moves (cross-multiplied to stay integer-exact).
      const klass: OppositionClass = opposed_moves * 2 > joint_moves ? "opposed" : "incidental";
      if (klass === "opposed") opposed = true;
      class_counts[klass] += 1;

      // The most-opposed affinity across the deal: the first pair (in label order) whose affinity
      // strictly exceeds the running best wins. `opposed/joint > bestOpp/bestJoint` ⟺
      // `opposed × bestJoint > bestOpp × joint` (all non-negative integers), so the ranking is
      // exact — no float comparison, no platform drift.
      if (most_opposed_pair === null || opposed_moves * bestJoint > bestOpp * joint_moves) {
        bestOpp = opposed_moves;
        bestJoint = joint_moves;
        most_opposed_pair = [dimension_a, dimension_b];
      }

      pairs.push({
        dimension_a,
        dimension_b,
        co_falls,
        co_recoveries,
        opposed_moves,
        joint_moves,
        affinity,
        class: klass,
      });
    }
  }

  const max_affinity = most_opposed_pair === null ? null : bestOpp / bestJoint;

  const opposition_hash = await sha256Hex(
    stableStringify({
      rounds: rounds.length,
      pairs: pairs.map((p) => ({
        dimension_a: p.dimension_a,
        dimension_b: p.dimension_b,
        co_falls: p.co_falls,
        co_recoveries: p.co_recoveries,
        opposed_moves: p.opposed_moves,
        class: p.class,
      })),
    }),
  );

  return {
    rounds: rounds.length,
    pairs,
    class_counts,
    total_opposed_moves,
    total_aligned_moves,
    max_affinity,
    most_opposed_pair,
    opposed,
    opposition_hash,
  };
}

/**
 * Did any pair of fronts move *opposite* ways across the team's acceptable floor — one falling
 * as the other recovered — for a strict **majority** of the steps in which both crossed: is
 * there a stable see-saw pairing the counterparty trades one front against the other? The CI
 * gate predicate — the *off-diagonal* counterpart to v32's co-fall gate (`exposureCoupled`) and
 * v33's co-recovery gate (`exposureRecoveryCoupled`). Where those fire on a stable *aligned*
 * pairing (both fronts moving the same way together), this fires on a stable *opposed* pairing:
 * a substitution the counterparty makes again and again — conceding one front exactly as it
 * restores the other. It needs no tuning — a strict majority of the joint moves *is* "they
 * counter-move more often than they move together." A pair that opposed once but aligned twice
 * is `incidental` and clears it; a consumer wanting a different bar reads `affinity` and
 * `max_affinity` from the JSON. **Distinct from v32/v33**: a pair `coupled` on falls (v32) or
 * recoveries (v33) can be `incidental` (or have no edge) here, and vice versa — the aligned and
 * opposed relations are independent reads of the same `floors[]` matrix.
 */
export function exposureOpposed(opposition: CoherenceOpposition): boolean {
  return opposition.opposed;
}

/**
 * Serialize a {@link CoherenceOpposition} to a stable, pretty-printed JSON string. The key order
 * is fixed and the pair order is already pinned by {@link computeCoherenceOpposition}, so the
 * same opposition always yields identical bytes — the `opposition_hash` it carries is the
 * canonical fingerprint, reproducible from `pairs` (over the integer move counts; the derived
 * float `affinity` and derived integer `joint_moves` aside).
 */
export function buildCoherenceOppositionJson(opposition: CoherenceOpposition): string {
  return JSON.stringify(
    {
      schema: "vaulytica.posture-opposition.v1",
      opposition_hash: opposition.opposition_hash,
      rounds: opposition.rounds,
      class_counts: opposition.class_counts,
      total_opposed_moves: opposition.total_opposed_moves,
      total_aligned_moves: opposition.total_aligned_moves,
      max_affinity: opposition.max_affinity,
      most_opposed_pair: opposition.most_opposed_pair,
      opposed: opposition.opposed,
      pairs: opposition.pairs.map((p) => ({
        dimension_a: p.dimension_a,
        dimension_b: p.dimension_b,
        co_falls: p.co_falls,
        co_recoveries: p.co_recoveries,
        opposed_moves: p.opposed_moves,
        joint_moves: p.joint_moves,
        affinity: p.affinity,
        class: p.class,
      })),
    },
    null,
    2,
  );
}

/** Render a counter-move affinity (0–1) as a whole-percent string, e.g. `0.75` → `"75%"`. */
function pct(affinity: number): string {
  return `${Math.round(affinity * 100)}%`;
}

/**
 * Render a {@link CoherenceOpposition} as human-readable terminal lines: the most-opposed pairing
 * (the pair and the share of the steps both crossed that opposed, or none-paired when no two
 * fronts ever counter-moved), the class tally, then one line per counter-moving pair (its class,
 * its opposed share, and the aligned vs. opposed split), `opposed` pairs first. A pair that never
 * counter-moved is never listed (§3 honesty — no counter-move edge). Lives beside its JSON
 * sibling so the CLI renders the affinity from one definition.
 */
export function renderCoherenceOppositionSummary(opposition: CoherenceOpposition): string {
  const cc = opposition.class_counts;
  const n = opposition.rounds;
  const lines = [
    `\nCoherence exposure counter-move affinity across ${n} rounds (which fronts the counterparty trades against each other):`,
    opposition.most_opposed_pair === null
      ? `  most-opposed pairing: none — no two fronts ever moved opposite ways across the floor in the same step.`
      : `  most-opposed pairing: ${opposition.most_opposed_pair[0]} + ${opposition.most_opposed_pair[1]} — counter-moved ${pct(opposition.max_affinity!)} of the steps both crossed.`,
    `  pairs: ${cc.opposed} opposed (counter-moved more often than aligned), ${cc.incidental} incidental.`,
  ];
  // Opposed pairs first (the stable see-saw), then incidental; each group keeps the
  // (dimension_a, dimension_b) order the pairs already carry.
  for (const p of [
    ...opposition.pairs.filter((p) => p.class === "opposed"),
    ...opposition.pairs.filter((p) => p.class === "incidental"),
  ]) {
    const mark = p.class === "opposed" ? "⚠" : "·";
    const aligned = p.co_falls + p.co_recoveries;
    lines.push(
      `  ${mark} ${p.dimension_a} + ${p.dimension_b}: ${p.class} — opposed ${p.opposed_moves} of ${p.joint_moves} step${p.joint_moves === 1 ? "" : "s"} both crossed (${pct(p.affinity)}); aligned ${aligned} (${p.co_falls} co-fell, ${p.co_recoveries} co-recovered).`,
    );
  }
  lines.push(`  opposition_hash: ${opposition.opposition_hash}`);
  return lines.join("\n") + "\n";
}
