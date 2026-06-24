/**
 * Cross-document negotiation-posture **exposure recovery chain** — the *transitive closure* of
 * v37's pairwise recovery-order relation: compose the per-pair strict-majority `first_recoverer →
 * last_recoverer` edges into a directed graph and read, per front, who it recovers *before* through
 * a chain (not just directly), the deal's **tailwater** (the front the counterparty restores *last*
 * across a whole cascade — left exposed below the floor longest of all), and whether the recovery
 * order is **rankable at all** — or contains a directed **cycle** that no pairwise read can see
 * (spec-v43). It is the **recovery mirror of v42** (the way v37 mirrors v36, v33 mirrors v32, v30
 * mirrors v28): v42 composes v35's lead-lag (crossing) edges; v43 composes v37's recovery-order
 * edges over the *same* `localeCompare`-pinned fronts.
 *
 * v37 ({@link computeCoherenceRecoveryOrder}) reads each *pair* in isolation — when fronts A and B
 * both *recover* (climb back at-or-above the acceptable floor), A recovers in an earlier step than B
 * for a strict majority of their comparisons, so A is the pair's `first_recoverer` and B the
 * `last_recoverer` (the laggard left exposed longer). But a deal lead does not watch one pair; they
 * want a single **restoration order**: the front restored *after everything else* — the deal's
 * persistent weak point, the last to climb back above the floor across the whole close. That is a
 * *transitive* read, and it is invisible to a pairwise scan in two ways:
 *
 * - **The chain.** Cap recovers before Term, Term recovers before Indemnity. v37 reports two pairs
 *   and *never* the composed fact: Indemnity is restored after Cap *through* Term — even though Cap
 *   and Indemnity may never have recovered in different steps (no direct edge). The deal lead reading
 *   the close wants to know Indemnity is the *tailwater* — the front left exposed longest of all;
 *   v37 cannot name it, because it never composes the edges.
 * - **The cycle.** Cap recovers before Term, Term before Indemnity, Indemnity before Cap — three
 *   pairwise recovery orders, each a perfectly consistent strict majority, that **cannot be globally
 *   ranked**. There is no last-recoverer; the recovery-order relation is *intransitive* (a Condorcet
 *   cycle). Every pair looks clean to v37; only composing all three reveals the paradox. When this
 *   happens, the per-pair laggard signal v37 reports *does not compose* into a restoration order —
 *   there is no single front restored last, because the order loops.
 *
 * v43 builds the directed graph whose edges are exactly v37's strict-majority `leading` pairs
 * (`first_recoverer → last_recoverer`, the same edges v37's `--fail-on-lagging-recovery` gate fires
 * on), computes its transitive closure, and reports per front its direct out-neighbours
 * (`recovers_before_directly`), its transitive `reach` (how many fronts it recovers before through
 * any chain) and `recovered_before_by` (how many recover before it), whether it sits on a cycle
 * (`in_cycle`), and its `class` (`source` / `relay` / `sink` / `cyclic` / `isolated`); plus the
 * deal's `tailwater` (the greatest-`recovered_before_by` *sink* — a front that recovers before
 * nothing and is recovered-before by the most, the last restored of all), `max_lag`, the `edges`
 * count (= v37's `leading` tally, by construction), `acyclic`, and `cyclic` (the gate verdict). It
 * adds **no** posture math beyond reachability over the recovery-order edges v37 already derives over
 * the `below-acceptable` rung v10 defines — `computeCoherenceRecoveryOrder` is imported and reused
 * unchanged (the join pattern v38/v40/v41/v42 use). The posture filter (spec-v10 §3), restated:
 *  - **Deterministic** — same N coherences in the same order → identical `recovery_chain_hash`, on
 *    any machine. Fronts are pinned by `localeCompare(_, "en")` (the order v37 already pins); edges
 *    are enumerated in that order; the closure is a plain integer reachability fixpoint; the
 *    tailwater pick is the greatest `recovered_before_by` with the earliest label on a tie. No float
 *    enters the verdict.
 *  - **Honest about unstated data** — a front no document states never recovers, so it has no
 *    recovery-order edge (the §3 contract v37 already enforces): it is `isolated` (reach 0, led-by
 *    0), counted but carrying no chain. A pair with no consistent first-recoverer (v37 `interleaved`)
 *    is no edge — it joins no chain.
 *  - **Advisory** — the report names which front the counterparty restores *last* across the team's
 *    own floor *through a chain*, and whether that ordering is coherent. It asserts no legal
 *    conclusion.
 *  - **Additive** — the chain carries its own `recovery_chain_hash`, namespaced apart from every
 *    `coherence_hash`, `movement_hash`, `trajectory_hash`, `shift_trajectory_hash`, `arc_hash`,
 *    `exposure_hash`, `persistence_hash`, `breadth_hash`, `recurrence_hash`, `volatility_hash`,
 *    `synchrony_hash`, `settling_hash`, `onset_hash`, `latency_hash`, `concurrency_hash`,
 *    `relapse_hash`, `tenure_hash`, `affinity_hash`, `recovery_affinity_hash`, `opposition_hash`,
 *    `precedence_hash`, `concession_hash`, `recovery_order_hash`, `weak_front_hash`, `cadence_hash`,
 *    `duration_hash`, `durability_hash`, and `chain_hash`, so computing it moves no golden.
 */

import { sha256Hex } from "../ingest/hash.js";
import { stableStringify } from "../engine/runner.js";
import type { PostureCoherence } from "./posture-coherence.js";
import { computeCoherenceRecoveryOrder } from "./coherence-recovery-order.js";

/**
 * A front's role in the transitive recovery-order graph:
 *  - `cyclic` — it sits on a directed cycle (it transitively recovers before itself): the recovery
 *    order cannot be ranked, the gate-worthy class — there is no consistent "last" among its loop;
 *  - `source` — not on a cycle, it transitively recovers before ≥ 1 front and *nothing* recovers
 *    before it (`recovered_before_by` 0): the front restored first of all, with everything downstream
 *    of it;
 *  - `sink` — not on a cycle, ≥ 1 front transitively recovers before it and it recovers before
 *    *none*: the **tailwater** candidate — the last restored, the front left exposed below the floor
 *    longest;
 *  - `relay` — not on a cycle, it both recovers before some and is recovered-before by others (an
 *    intermediate link in the restoration chain);
 *  - `isolated` — no recovery-order edge touches it (reach 0 and led-by 0): a front that never
 *    recovered first or last for a strict majority against anyone (incl. an unstated/never-recovering
 *    front, §3).
 */
export type RecoveryChainRole = "cyclic" | "source" | "sink" | "relay" | "isolated";

/** One negotiation front's place in the whole-sequence transitive recovery-order graph. */
export type CoherenceRecoveryChainFront = {
  dimension: string;
  /** The fronts it *directly* recovers before (a strict-majority v37 `leading` edge), sorted by label. */
  recovers_before_directly: string[];
  /** How many fronts it recovers before through *any* chain (transitive out-reach, excluding itself). */
  reach: number;
  /** How many fronts transitively recover before it (transitive in-reach, excluding itself). */
  recovered_before_by: number;
  /** Does it sit on a directed cycle — does it transitively recover before itself? */
  in_cycle: boolean;
  /** Its role in the graph. */
  class: RecoveryChainRole;
};

export type CoherenceRecoveryChain = {
  /** How many rounds (coherences) the chain spans. */
  rounds: number;
  /** Every front, pinned by `dimension` (`localeCompare`). */
  fronts: CoherenceRecoveryChainFront[];
  /** Per-front tally by role. */
  class_counts: Record<RecoveryChainRole, number>;
  /** How many directed recovery-order edges the graph has — equals v37's `leading` pair count. */
  edges: number;
  /** The greatest transitive `recovered_before_by` among *sink* fronts (0 when no sink exists). */
  max_lag: number;
  /** The sink front owning {@link max_lag} — the deal's last-restored front (earliest label on a tie; `null` when no sink). */
  tailwater: string | null;
  /** Is the recovery-order relation acyclic — rankable into a single restoration order? */
  acyclic: boolean;
  /** Does the recovery-order relation contain a directed cycle? The gate-worthy verdict. */
  cyclic: boolean;
  /** SHA-256 over the canonical per-front edge set — additive, apart from every other hash. */
  recovery_chain_hash: string;
};

function emptyClassCounts(): Record<RecoveryChainRole, number> {
  return { cyclic: 0, source: 0, sink: 0, relay: 0, isolated: 0 };
}

/**
 * Walk N cross-document posture coherences — the same bundle at round 1, round 2, …, round N —
 * and report the **transitive closure** of v37's pairwise recovery-order relation: per front, the
 * fronts it recovers *before* directly and *through a chain*, the deal's tailwater (the
 * greatest-`recovered_before_by` sink — the front restored last of all, left exposed longest), and
 * whether the relation is acyclic (rankable into one restoration order) or contains a directed
 * **cycle** that no pairwise read (v37) can see.
 *
 * Pure and deterministic: it delegates the per-pair recovery-order derivation to
 * {@link computeCoherenceRecoveryOrder} (reused unchanged — the join pattern v38/v40/v41/v42 use),
 * keeps only its strict-majority `leading` pairs as directed `first_recoverer → last_recoverer`
 * edges, computes a plain integer reachability fixpoint over the `localeCompare`-pinned fronts, and
 * picks the tailwater by greatest `recovered_before_by` (earliest label on a tie). No float enters
 * the verdict, so the same N coherences in the same order always yield identical bytes.
 *
 * Requires at least two rounds — a recovery-order edge is a *between-round* ordering; a single round
 * has no transition to register a recovery over (v37 enforces this).
 */
export async function computeCoherenceRecoveryChain(
  rounds: readonly PostureCoherence[],
): Promise<CoherenceRecoveryChain> {
  const recoveryOrder = await computeCoherenceRecoveryOrder(rounds);

  // The fronts, pinned by label — every dimension v37 saw, in the order it pins them. v37 only lists
  // pairs with an ordered comparison, so we reconstruct the full label set from the coherences
  // directly, in the same localeCompare order v37 uses, so a front that never recovered is still
  // reported as `isolated` rather than silently dropped.
  const labels = Array.from(
    new Set(rounds.flatMap((c) => c.dimensions.map((d) => d.dimension))),
  ).sort((a, b) => a.localeCompare(b, "en"));
  const index = new Map(labels.map((l, i) => [l, i]));
  const n = labels.length;

  // Direct adjacency over the strict-majority `leading` edges only (first_recoverer →
  // last_recoverer) — exactly the edges v37's `--fail-on-lagging-recovery` gate fires on; an
  // `interleaved` pair is no edge.
  const adj: boolean[][] = labels.map(() => new Array<boolean>(n).fill(false));
  const directOut: string[][] = labels.map(() => []);
  let edges = 0;
  for (const p of recoveryOrder.pairs) {
    if (p.class !== "leading" || p.first_recoverer === null || p.last_recoverer === null) continue;
    const fi = index.get(p.first_recoverer)!;
    const li = index.get(p.last_recoverer)!;
    adj[fi]![li] = true;
    directOut[fi]!.push(p.last_recoverer);
    edges += 1;
  }

  // Transitive closure (paths of length ≥ 1) by a Floyd–Warshall reachability fixpoint. `reach[i][j]`
  // is true iff some directed chain of `first_recoverer → last_recoverer` edges runs from front i to
  // front j; `reach[v][v]` is true iff v sits on a directed cycle (it recovers before itself).
  const reach: boolean[][] = adj.map((row) => row.slice());
  for (let k = 0; k < n; k++) {
    for (let i = 0; i < n; i++) {
      if (!reach[i]![k]) continue;
      for (let j = 0; j < n; j++) {
        if (reach[k]![j]) reach[i]![j] = true;
      }
    }
  }

  const class_counts = emptyClassCounts();
  let max_lag = 0;
  let tailwater: string | null = null;
  let cyclic = false;

  const fronts: CoherenceRecoveryChainFront[] = labels.map((dimension, i) => {
    let outReach = 0;
    let inReach = 0;
    for (let j = 0; j < n; j++) {
      if (j === i) continue;
      if (reach[i]![j]) outReach += 1;
      if (reach[j]![i]) inReach += 1;
    }
    const in_cycle = reach[i]![i] === true;
    if (in_cycle) cyclic = true;

    const klass: RecoveryChainRole = in_cycle
      ? "cyclic"
      : outReach > 0 && inReach === 0
        ? "source"
        : outReach === 0 && inReach > 0
          ? "sink"
          : outReach > 0 && inReach > 0
            ? "relay"
            : "isolated";
    class_counts[klass] += 1;

    // The tailwater: the greatest-`recovered_before_by` *sink* (a front that recovers before nothing
    // and is recovered-before by the most — the last restored of all, left exposed below the floor
    // longest). The first sink (in label order) whose in-reach strictly exceeds the running best
    // wins, so the pick is integer-exact and label-stable.
    if (klass === "sink" && (tailwater === null || inReach > max_lag)) {
      max_lag = inReach;
      tailwater = dimension;
    }

    return {
      dimension,
      recovers_before_directly: directOut[i]!.slice().sort((a, b) => a.localeCompare(b, "en")),
      reach: outReach,
      recovered_before_by: inReach,
      in_cycle,
      class: klass,
    };
  });

  const recovery_chain_hash = await sha256Hex(
    stableStringify({
      rounds: recoveryOrder.rounds,
      fronts: fronts.map((f) => ({
        dimension: f.dimension,
        recovers_before_directly: f.recovers_before_directly,
        class: f.class,
      })),
    }),
  );

  return {
    rounds: recoveryOrder.rounds,
    fronts,
    class_counts,
    edges,
    max_lag,
    tailwater,
    acyclic: !cyclic,
    cyclic,
    recovery_chain_hash,
  };
}

/**
 * Does the transitive recovery-order relation contain a directed **cycle** — three (or more) fronts
 * each a strict-majority first-recoverer over the next, in a loop that cannot be globally ranked? The
 * CI gate predicate — the *transitive* verdict v37 structurally cannot pose. v37 reads each pair in
 * isolation, and every pair on a cycle looks perfectly consistent to it; only composing the edges
 * reveals the intransitivity. It needs no tuning — a directed cycle either exists or it does not, a
 * pure boolean over the integer-derived edges. When it fires, the per-pair laggard signal v37 reports
 * does *not* compose into a single restoration order: there is no front restored last, because the
 * order loops. A consumer wanting the (common) acyclic case — a clean restoration order with a
 * tailwater — reads `acyclic`, `tailwater`, and `max_lag` from the JSON. The recovery mirror of v42's
 * `exposureCyclic` (v42 composes the lead-lag/crossing edges; v43 the recovery-order edges).
 */
export function exposureRecoveryCyclic(chain: CoherenceRecoveryChain): boolean {
  return chain.cyclic;
}

/**
 * Serialize a {@link CoherenceRecoveryChain} to a stable, pretty-printed JSON string. The key order
 * is fixed and the front order is already pinned by {@link computeCoherenceRecoveryChain}, so the
 * same chain always yields identical bytes — the `recovery_chain_hash` it carries is the canonical
 * fingerprint, reproducible from `fronts` (over each front's direct edges and role; the derived
 * transitive `reach` / `recovered_before_by` integers, fully determined by the edge set, aside).
 */
export function buildCoherenceRecoveryChainJson(chain: CoherenceRecoveryChain): string {
  return JSON.stringify(
    {
      schema: "vaulytica.posture-recovery-chain.v1",
      recovery_chain_hash: chain.recovery_chain_hash,
      rounds: chain.rounds,
      class_counts: chain.class_counts,
      edges: chain.edges,
      max_lag: chain.max_lag,
      tailwater: chain.tailwater,
      acyclic: chain.acyclic,
      cyclic: chain.cyclic,
      fronts: chain.fronts.map((f) => ({
        dimension: f.dimension,
        recovers_before_directly: f.recovers_before_directly,
        reach: f.reach,
        recovered_before_by: f.recovered_before_by,
        in_cycle: f.in_cycle,
        class: f.class,
      })),
    },
    null,
    2,
  );
}

/**
 * Render a {@link CoherenceRecoveryChain} as human-readable terminal lines: the tailwater (the front
 * the counterparty restores last across the whole cascade — left exposed longest, or none when no
 * clean sink exists), whether the relation is acyclic or contains an intransitive cycle, the role
 * tally, then one line per front that touches the recovery-order graph (its role, its transitive
 * reach, and its direct edges), sinks first, then relays, then cyclic fronts, then sources. An
 * `isolated` front is counted but never listed (§3 honesty — it joins no chain). Lives beside its
 * JSON sibling so the CLI renders the chain from one definition.
 */
export function renderCoherenceRecoveryChainSummary(chain: CoherenceRecoveryChain): string {
  const cc = chain.class_counts;
  const n = chain.rounds;
  const lines = [
    `\nCoherence exposure recovery chain across ${n} rounds (which front the counterparty restores last through a chain, not just a pair):`,
    chain.tailwater === null
      ? `  tailwater: none — no sink front is restored after a cascade with nothing downstream.`
      : `  tailwater: ${chain.tailwater} — transitively recovered after ${chain.max_lag} front${chain.max_lag === 1 ? "" : "s"}, restored last of all.`,
    chain.cyclic
      ? `  ordering: intransitive — the recovery-order relation contains a directed cycle, so no single restoration order ranks every front.`
      : `  ordering: acyclic — the recovery-order relation ranks into a single restoration order.`,
    `  fronts: ${cc.sink} sink, ${cc.relay} relay, ${cc.cyclic} cyclic, ${cc.source} source, ${cc.isolated} isolated (${chain.edges} edge${chain.edges === 1 ? "" : "s"}).`,
  ];
  const order: Record<RecoveryChainRole, number> = {
    sink: 0,
    relay: 1,
    cyclic: 2,
    source: 3,
    isolated: 4,
  };
  for (const f of chain.fronts
    .filter((f) => f.class !== "isolated")
    .slice()
    .sort((a, b) => order[a.class] - order[b.class])) {
    const mark = f.class === "cyclic" ? "⚠" : f.class === "sink" ? "◆" : "·";
    const edgesNote =
      f.recovers_before_directly.length > 0
        ? `directly recovers before ${f.recovers_before_directly.join(", ")}`
        : "recovers before none directly";
    lines.push(
      `  ${mark} ${f.dimension}: ${f.class} — recovers before ${f.reach}, recovered after by ${f.recovered_before_by} (${edgesNote}).`,
    );
  }
  lines.push(`  recovery_chain_hash: ${chain.recovery_chain_hash}`);
  return lines.join("\n") + "\n";
}
