/**
 * Cross-document negotiation-posture **exposure lead chain** — the *transitive closure* of
 * v35's pairwise lead-lag relation: compose the per-pair strict-majority `leader` edges into
 * a directed graph and read, per front, who it leads *through a chain* (not just directly),
 * the deal's **headwater** (the earliest-warning source front, with nothing upstream), and
 * whether the relation is **rankable at all** — or contains a directed **cycle** that no
 * pairwise read can see (spec-v42).
 *
 * v35 ({@link computeCoherencePrecedence}) reads each *pair* in isolation — front A crosses the
 * acceptable floor *before* front B for a strict majority of their comparisons, so A `leads` B
 * (A is an early-warning indicator for B). But a deal lead does not watch one pair; they want a
 * single **watch-order**: a front upstream of *everything*, whose movement gives advance notice
 * on a whole cascade. That is a *transitive* read, and it is invisible to a pairwise scan in two
 * ways:
 *
 * - **The chain.** Cap leads Term, Term leads Indemnity. v35 reports two pairs and *never* the
 *   composed fact: Cap is a transitive early-warning indicator for Indemnity *through* Term —
 *   even though Cap and Indemnity may never have crossed in different steps (no direct edge). The
 *   deal lead who watches Cap gets advance notice on the entire downstream pipeline; v35 cannot
 *   name that Cap is the *headwater*.
 * - **The cycle.** Cap leads Term, Term leads Indemnity, Indemnity leads Cap — three pairwise
 *   leads, each a perfectly consistent strict majority, that **cannot be globally ranked**. There
 *   is no first-mover; the lead-lag relation is *intransitive* (a Condorcet cycle). Every pair
 *   looks clean to v35; only composing all three reveals the paradox. When this happens, the
 *   per-pair early-warning signal v35 sells *does not compose* into a watch-order — there is no
 *   single front to watch first, because movement propagates around a loop.
 *
 * v42 builds the directed graph whose edges are exactly v35's strict-majority `leading` pairs
 * (`leader → follower`, the same edges v35's `--fail-on-leading-front` gate fires on), computes
 * its transitive closure, and reports per front its direct out-neighbours (`leads_directly`), its
 * transitive `reach` (how many fronts it leads through any chain) and `led_by` (how many lead it),
 * whether it sits on a cycle (`in_cycle`), and its `class` (`source` / `relay` / `sink` /
 * `cyclic` / `isolated`); plus the deal's `headwater` (the greatest-reach *source* — a front with
 * nothing upstream), `max_reach`, the `edges` count (= v35's `leading` tally, by construction),
 * `acyclic`, and `cyclic` (the gate verdict). It adds **no** posture math beyond reachability over
 * the lead-lag edges v35 already derives over the `below-acceptable` rung v10 defines —
 * `computeCoherencePrecedence` is imported and reused unchanged (the join pattern v38/v40/v41 use).
 * The posture filter (spec-v10 §3), restated:
 *  - **Deterministic** — same N coherences in the same order → identical `chain_hash`, on any
 *    machine. Fronts are pinned by `localeCompare(_, "en")` (the order v35 already pins); edges are
 *    enumerated in that order; the closure is a plain integer reachability fixpoint; the headwater
 *    pick is the greatest `reach` with the earliest label on a tie. No float enters the verdict.
 *  - **Honest about unstated data** — a front no document states never crosses the floor, so it has
 *    no lead-lag edge (the §3 contract v35 already enforces): it is `isolated` (reach 0, led-by 0),
 *    counted but carrying no chain. A pair with no consistent first-mover (v35 `interleaved`) is no
 *    edge — it joins no chain.
 *  - **Advisory** — the report names which front the counterparty moves *first* across the team's
 *    own floor *through a chain*, and whether that ordering is coherent. It asserts no legal
 *    conclusion.
 *  - **Additive** — the chain carries its own `chain_hash`, namespaced apart from every
 *    `coherence_hash`, `movement_hash`, `trajectory_hash`, `shift_trajectory_hash`, `arc_hash`,
 *    `exposure_hash`, `persistence_hash`, `breadth_hash`, `recurrence_hash`, `volatility_hash`,
 *    `synchrony_hash`, `settling_hash`, `onset_hash`, `latency_hash`, `concurrency_hash`,
 *    `relapse_hash`, `tenure_hash`, `affinity_hash`, `recovery_affinity_hash`, `opposition_hash`,
 *    `precedence_hash`, `concession_hash`, `recovery_order_hash`, `weak_front_hash`, `cadence_hash`,
 *    `duration_hash`, and `durability_hash`, so computing it moves no golden.
 */

import { sha256Hex } from "../ingest/hash.js";
import { stableStringify } from "../engine/runner.js";
import type { PostureCoherence } from "./posture-coherence.js";
import { computeCoherencePrecedence } from "./coherence-precedence.js";

/**
 * A front's role in the transitive lead-lag graph:
 *  - `cyclic` — it sits on a directed cycle (it transitively leads itself): the lead-lag relation
 *    cannot be ranked, the gate-worthy class — there is no consistent "first" among its loop;
 *  - `source` — not on a cycle, it transitively leads ≥ 1 front and *nothing* leads it (`led_by`
 *    0): a headwater / pure early-warning origin, the front to watch with nothing upstream;
 *  - `sink` — not on a cycle, ≥ 1 front transitively leads it and it leads *none*: a terminal
 *    follower, the last to move;
 *  - `relay` — not on a cycle, it both leads and is led (an intermediate link in a chain);
 *  - `isolated` — no lead-lag edge touches it (reach 0 and led-by 0): a front that never crossed
 *    the floor first or last for a strict majority against anyone (incl. an unstated front, §3).
 */
export type ChainRole = "cyclic" | "source" | "sink" | "relay" | "isolated";

/** One negotiation front's place in the whole-sequence transitive lead-lag graph. */
export type CoherenceChainFront = {
  dimension: string;
  /** The fronts it *directly* leads (a strict-majority v35 `leading` edge), sorted by label. */
  leads_directly: string[];
  /** How many fronts it leads through *any* chain (transitive out-reach, excluding itself). */
  reach: number;
  /** How many fronts transitively lead it (transitive in-reach, excluding itself). */
  led_by: number;
  /** Does it sit on a directed cycle — does it transitively lead itself? */
  in_cycle: boolean;
  /** Its role in the graph. */
  class: ChainRole;
};

export type CoherenceChain = {
  /** How many rounds (coherences) the chain spans. */
  rounds: number;
  /** Every front, pinned by `dimension` (`localeCompare`). */
  fronts: CoherenceChainFront[];
  /** Per-front tally by role. */
  class_counts: Record<ChainRole, number>;
  /** How many directed lead-lag edges the graph has — equals v35's `leading` pair count. */
  edges: number;
  /** The greatest transitive `reach` among *source* fronts (0 when no source exists). */
  max_reach: number;
  /** The source front owning {@link max_reach} (earliest label on a tie; `null` when no source). */
  headwater: string | null;
  /** Is the lead-lag relation acyclic — rankable into a single watch-order? */
  acyclic: boolean;
  /** Does the lead-lag relation contain a directed cycle? The gate-worthy verdict. */
  cyclic: boolean;
  /** SHA-256 over the canonical per-front edge set — additive, apart from every other hash. */
  chain_hash: string;
};

function emptyClassCounts(): Record<ChainRole, number> {
  return { cyclic: 0, source: 0, sink: 0, relay: 0, isolated: 0 };
}

/**
 * Walk N cross-document posture coherences — the same bundle at round 1, round 2, …, round N —
 * and report the **transitive closure** of v35's pairwise lead-lag relation: per front, the
 * fronts it leads *directly* and *through a chain*, the deal's headwater (the greatest-reach
 * source, a front with nothing upstream), and whether the relation is acyclic (rankable into one
 * watch-order) or contains a directed **cycle** that no pairwise read (v35) can see.
 *
 * Pure and deterministic: it delegates the per-pair lead-lag derivation to
 * {@link computeCoherencePrecedence} (reused unchanged — the join pattern v38/v40/v41 use), keeps
 * only its strict-majority `leading` pairs as directed `leader → follower` edges, computes a plain
 * integer reachability fixpoint over the `localeCompare`-pinned fronts, and picks the headwater by
 * greatest `reach` (earliest label on a tie). No float enters the verdict, so the same N coherences
 * in the same order always yield identical bytes.
 *
 * Requires at least two rounds — a lead-lag edge is a *between-round* ordering; a single round has
 * no transition to register a crossing over (v35 enforces this).
 */
export async function computeCoherenceChain(
  rounds: readonly PostureCoherence[],
): Promise<CoherenceChain> {
  const precedence = await computeCoherencePrecedence(rounds);

  // The fronts, pinned by label — every dimension v35 saw, in the order it pins them. v35 only
  // lists pairs with an ordered comparison, so gather labels from those pairs *and* keep an
  // index so isolated fronts (no edge) still appear. We reconstruct the full label set from the
  // coherences directly, in the same localeCompare order v35 uses, so a front that never crossed
  // the floor is still reported as `isolated` rather than silently dropped.
  const labels = Array.from(
    new Set(rounds.flatMap((c) => c.dimensions.map((d) => d.dimension))),
  ).sort((a, b) => a.localeCompare(b, "en"));
  const index = new Map(labels.map((l, i) => [l, i]));
  const n = labels.length;

  // Direct adjacency over the strict-majority `leading` edges only (leader → follower) — exactly
  // the edges v35's `--fail-on-leading-front` gate fires on; an `interleaved` pair is no edge.
  const adj: boolean[][] = labels.map(() => new Array<boolean>(n).fill(false));
  const directOut: string[][] = labels.map(() => []);
  let edges = 0;
  for (const p of precedence.pairs) {
    if (p.class !== "leading" || p.leader === null) continue;
    const follower = p.leader === p.dimension_a ? p.dimension_b : p.dimension_a;
    const li = index.get(p.leader)!;
    const fi = index.get(follower)!;
    adj[li]![fi] = true;
    directOut[li]!.push(follower);
    edges += 1;
  }

  // Transitive closure (paths of length ≥ 1) by a Floyd–Warshall reachability fixpoint. `reach[i][j]`
  // is true iff some directed chain of `leading` edges runs from front i to front j; `reach[v][v]`
  // is true iff v sits on a directed cycle (it leads itself).
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
  let max_reach = 0;
  let headwater: string | null = null;
  let cyclic = false;

  const fronts: CoherenceChainFront[] = labels.map((dimension, i) => {
    let outReach = 0;
    let inReach = 0;
    for (let j = 0; j < n; j++) {
      if (j === i) continue;
      if (reach[i]![j]) outReach += 1;
      if (reach[j]![i]) inReach += 1;
    }
    const in_cycle = reach[i]![i] === true;
    if (in_cycle) cyclic = true;

    const klass: ChainRole = in_cycle
      ? "cyclic"
      : outReach > 0 && inReach === 0
        ? "source"
        : outReach === 0 && inReach > 0
          ? "sink"
          : outReach > 0 && inReach > 0
            ? "relay"
            : "isolated";
    class_counts[klass] += 1;

    // The headwater: the greatest-reach *source* (a front with nothing upstream — the front to
    // watch with no advance warning of its own). The first source (in label order) whose reach
    // strictly exceeds the running best wins, so the pick is integer-exact and label-stable.
    if (klass === "source" && (headwater === null || outReach > max_reach)) {
      max_reach = outReach;
      headwater = dimension;
    }

    return {
      dimension,
      leads_directly: directOut[i]!.slice().sort((a, b) => a.localeCompare(b, "en")),
      reach: outReach,
      led_by: inReach,
      in_cycle,
      class: klass,
    };
  });

  const chain_hash = await sha256Hex(
    stableStringify({
      rounds: precedence.rounds,
      fronts: fronts.map((f) => ({
        dimension: f.dimension,
        leads_directly: f.leads_directly,
        class: f.class,
      })),
    }),
  );

  return {
    rounds: precedence.rounds,
    fronts,
    class_counts,
    edges,
    max_reach,
    headwater,
    acyclic: !cyclic,
    cyclic,
    chain_hash,
  };
}

/**
 * Does the transitive lead-lag relation contain a directed **cycle** — three (or more) fronts each
 * a strict-majority first-mover over the next, in a loop that cannot be globally ranked? The CI
 * gate predicate — the *transitive* verdict v35 structurally cannot pose. v35 reads each pair in
 * isolation, and every pair on a cycle looks perfectly consistent to it; only composing the edges
 * reveals the intransitivity. It needs no tuning — a directed cycle either exists or it does not, a
 * pure boolean over the integer-derived edges. When it fires, the per-pair early-warning signal v35
 * reports does *not* compose into a single watch-order: there is no front to watch first, because
 * movement propagates around a loop. A consumer wanting the (common) acyclic case — a clean
 * pipeline with a headwater — reads `acyclic`, `headwater`, and `max_reach` from the JSON.
 */
export function exposureCyclic(chain: CoherenceChain): boolean {
  return chain.cyclic;
}

/**
 * Serialize a {@link CoherenceChain} to a stable, pretty-printed JSON string. The key order is
 * fixed and the front order is already pinned by {@link computeCoherenceChain}, so the same chain
 * always yields identical bytes — the `chain_hash` it carries is the canonical fingerprint,
 * reproducible from `fronts` (over each front's direct edges and role; the derived transitive
 * `reach` / `led_by` integers, fully determined by the edge set, aside).
 */
export function buildCoherenceChainJson(chain: CoherenceChain): string {
  return JSON.stringify(
    {
      schema: "vaulytica.posture-chain.v1",
      chain_hash: chain.chain_hash,
      rounds: chain.rounds,
      class_counts: chain.class_counts,
      edges: chain.edges,
      max_reach: chain.max_reach,
      headwater: chain.headwater,
      acyclic: chain.acyclic,
      cyclic: chain.cyclic,
      fronts: chain.fronts.map((f) => ({
        dimension: f.dimension,
        leads_directly: f.leads_directly,
        reach: f.reach,
        led_by: f.led_by,
        in_cycle: f.in_cycle,
        class: f.class,
      })),
    },
    null,
    2,
  );
}

/**
 * Render a {@link CoherenceChain} as human-readable terminal lines: the headwater (the source the
 * counterparty moves first across the whole cascade, or none when no clean source exists), whether
 * the relation is acyclic or contains an intransitive cycle, the role tally, then one line per
 * front that touches the lead-lag graph (its role, its transitive reach, and its direct edges),
 * sources first, then relays, then cyclic fronts, then sinks. An `isolated` front is counted but
 * never listed (§3 honesty — it joins no chain). Lives beside its JSON sibling so the CLI renders
 * the chain from one definition.
 */
export function renderCoherenceChainSummary(chain: CoherenceChain): string {
  const cc = chain.class_counts;
  const n = chain.rounds;
  const lines = [
    `\nCoherence exposure lead chain across ${n} rounds (who the counterparty moves first through a chain, not just a pair):`,
    chain.headwater === null
      ? `  headwater: none — no source front leads a cascade with nothing upstream.`
      : `  headwater: ${chain.headwater} — transitively leads ${chain.max_reach} front${chain.max_reach === 1 ? "" : "s"} with nothing upstream.`,
    chain.cyclic
      ? `  ordering: intransitive — the lead-lag relation contains a directed cycle, so no single watch-order ranks every front.`
      : `  ordering: acyclic — the lead-lag relation ranks into a single watch-order.`,
    `  fronts: ${cc.source} source, ${cc.relay} relay, ${cc.cyclic} cyclic, ${cc.sink} sink, ${cc.isolated} isolated (${chain.edges} edge${chain.edges === 1 ? "" : "s"}).`,
  ];
  const order: Record<ChainRole, number> = { source: 0, relay: 1, cyclic: 2, sink: 3, isolated: 4 };
  for (const f of chain.fronts
    .filter((f) => f.class !== "isolated")
    .slice()
    .sort((a, b) => order[a.class] - order[b.class])) {
    const mark = f.class === "cyclic" ? "⚠" : f.class === "source" ? "◆" : "·";
    const edgesNote =
      f.leads_directly.length > 0
        ? `directly leads ${f.leads_directly.join(", ")}`
        : "leads none directly";
    lines.push(
      `  ${mark} ${f.dimension}: ${f.class} — reaches ${f.reach}, led by ${f.led_by} (${edgesNote}).`,
    );
  }
  lines.push(`  chain_hash: ${chain.chain_hash}`);
  return lines.join("\n") + "\n";
}
