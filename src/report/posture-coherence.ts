/**
 * Cross-document negotiation-posture coherence (spec-v12 Thrust A).
 *
 * v10 reports which rung of the team's ladder a *single* draft meets on each
 * front; v11 reports how that rung *moved* between two versions of the *same*
 * document. A deal, though, is rarely one document — it is a **bundle**: an MSA,
 * a SOW, an order form, a DPA. The same negotiation front (the liability cap,
 * the governing law, the indemnity) can land on a *different* rung in each one.
 * The MSA may state an ideal cap while the order form quietly states a
 * below-floor one — and in a deal package the **weakest** document usually
 * governs your exposure, so a posture that looks ideal in isolation can be
 * undercut two documents over.
 *
 * This module is the cross-document axis (spec-v4) of the posture idea: given
 * one {@link NegotiationPosture} per document — all classified against the
 * **same** team positions — it reports, per dimension, whether the documents
 * **agree** on the rung or **diverge**, and surfaces the bundle's binding floor
 * (the weakest stated rung and which document carries it).
 *
 * It is a deterministic diff of postures the v10 evaluator already produces —
 * no AI, no server, no new probabilistic step. The posture filter (spec-v10 §3),
 * restated:
 *  - **Deterministic** — same postures, same input order → identical
 *    `coherence_hash`, on any machine. Dimensions are pinned by
 *    `localeCompare(_, "en")`; documents keep the caller's order.
 *  - **Honest about unstated data** — a dimension a document does not state is
 *    `unevaluable`, which is **unranked** (the §3 contract forbids conflating
 *    "not stated" with "below floor"). An unstated front is never folded into a
 *    divergence and never lowers the binding floor; it gets its own honest
 *    `single`/`unstated` label.
 *  - **Advisory** — coherence reports where a front sits across the team's own
 *    ladder. It never asserts a term is legally adequate, enforceable, or that
 *    the weakest document legally governs — only that it is the weakest *rung*.
 *  - **Additive** — the coherence carries its own `coherence_hash`, namespaced
 *    apart from each document's `result_hash` and the bundle fingerprint, so
 *    computing it moves no golden.
 */

import type { NegotiationPosture, NegotiationTier } from "../playbooks/custom-interpreter.js";
import { sha256Hex } from "../ingest/hash.js";
import { stableStringify } from "../engine/runner.js";
import { TIER_RANK } from "./posture-movement.js";

/**
 * How one negotiation front sits across the documents of a bundle.
 *
 *  - `aligned`   — two or more documents state the front and they all land on
 *                  the **same** rung. The position is held consistently.
 *  - `divergent` — two or more documents state the front and they land on
 *                  **different** rungs (e.g. ideal in the MSA, below-floor in
 *                  the order form). The bundle disagrees with itself.
 *  - `single`    — exactly one document states the front. There is nothing
 *                  cross-document to compare; the other documents are silent.
 *  - `unstated`  — no document states the front (all `unevaluable`). Honest:
 *                  silence is never a divergence.
 */
export type PostureCoherenceKind = "aligned" | "divergent" | "single" | "unstated";

/** One document's rung on a single front (`unevaluable` = the document is silent on it). */
export type DocumentTier = {
  document: string;
  tier: NegotiationTier;
};

export type PostureCoherenceDimension = {
  dimension: string;
  /** Each document's rung on this front, in the caller's document order. */
  tiers: DocumentTier[];
  /**
   * The weakest *stated* rung across the bundle — the binding floor on this
   * front, since the weakest document usually governs exposure. `null` when no
   * document states the front (`unevaluable` is unranked, never a floor).
   */
  weakest_tier: NegotiationTier | null;
  /** The document(s) carrying the weakest stated rung, in the caller's order. */
  weakest_documents: string[];
  coherence: PostureCoherenceKind;
};

export type PostureCoherence = {
  dimensions: PostureCoherenceDimension[];
  counts: Record<PostureCoherenceKind, number>;
  /** SHA-256 over the canonical coherence — additive, apart from each `result_hash`. */
  coherence_hash: string;
};

/** One document's contribution to a bundle: its label and its posture. */
export type CoherenceInput = {
  document: string;
  posture: NegotiationPosture;
};

function emptyCounts(): Record<PostureCoherenceKind, number> {
  return { aligned: 0, divergent: 0, single: 0, unstated: 0 };
}

/**
 * Compute cross-document posture coherence over a bundle. Pure and
 * deterministic: dimensions are pinned by `localeCompare`, documents keep the
 * caller's order, and `coherence_hash` is over the canonical per-dimension set.
 *
 * Every posture must be classified against the **same** team positions (the
 * caller applies one active playbook to every document) — comparing rungs
 * computed from different ladders would be nonsense, the same way v6 refuses a
 * cross-family finding compare and v11 refuses a cross-ladder movement.
 */
export async function bundlePostureCoherence(
  documents: readonly CoherenceInput[],
): Promise<PostureCoherence> {
  // dimension -> (document -> tier). A dimension a document does not carry is
  // treated as `unevaluable` (unranked, not stated) — the honest, non-false-
  // divergence choice for the defensive case of mismatched ladders.
  const perDoc = documents.map((d) => {
    const byDim = new Map<string, NegotiationTier>();
    for (const p of d.posture.positions) byDim.set(p.dimension, p.tier);
    return { document: d.document, byDim };
  });

  const dimSet = new Set<string>();
  for (const d of perDoc) for (const dim of d.byDim.keys()) dimSet.add(dim);
  const labels = Array.from(dimSet).sort((a, b) => a.localeCompare(b, "en"));

  const counts = emptyCounts();
  const dimensions: PostureCoherenceDimension[] = labels.map((dimension) => {
    const tiers: DocumentTier[] = perDoc.map((d) => ({
      document: d.document,
      tier: d.byDim.get(dimension) ?? "unevaluable",
    }));

    // Stated = on the ladder (rank is non-null). `unevaluable` is excluded.
    const stated = tiers.filter((t) => TIER_RANK[t.tier] !== null);

    let coherence: PostureCoherenceKind;
    if (stated.length === 0) coherence = "unstated";
    else if (stated.length === 1) coherence = "single";
    else {
      const distinct = new Set(stated.map((t) => t.tier));
      coherence = distinct.size === 1 ? "aligned" : "divergent";
    }

    // The binding floor: the weakest stated rung, and who carries it.
    let weakest_tier: NegotiationTier | null = null;
    let weakest_documents: string[] = [];
    if (stated.length > 0) {
      let minRank = Infinity;
      for (const t of stated) {
        const rank = TIER_RANK[t.tier] as number;
        if (rank < minRank) minRank = rank;
      }
      const floor = stated.filter((t) => TIER_RANK[t.tier] === minRank);
      weakest_tier = floor[0]!.tier;
      weakest_documents = floor.map((t) => t.document);
    }

    counts[coherence] += 1;
    return { dimension, tiers, weakest_tier, weakest_documents, coherence };
  });

  const coherence_hash = await sha256Hex(
    stableStringify({
      dimensions: dimensions.map((d) => ({
        dimension: d.dimension,
        tiers: d.tiers.map((t) => ({ document: t.document, tier: t.tier })),
        weakest_tier: d.weakest_tier,
        weakest_documents: d.weakest_documents,
        coherence: d.coherence,
      })),
    }),
  );

  return { dimensions, counts, coherence_hash };
}

/**
 * Does the bundle disagree with itself on any front? The CI gate predicate
 * (mirrors v11's `postureRegressed`): true when any dimension is `divergent` —
 * two or more documents stating the same front on different rungs. `single` and
 * `unstated` never trip it (§3 honesty — silence is not a disagreement).
 */
export function hasDivergence(coherence: PostureCoherence): boolean {
  return coherence.counts.divergent > 0;
}
