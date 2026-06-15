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

  const coherence_hash = await coherenceHash(dimensions);

  return { dimensions, counts, coherence_hash };
}

/**
 * The canonical fingerprint of a coherence: SHA-256 over its dimension set, in
 * the pinned dimension/document order. Factored out so {@link bundlePostureCoherence}
 * computes it and {@link parsePostureCoherenceJson} re-derives it to verify a
 * saved artifact has not been tampered with or hand-edited (spec-v14).
 */
async function coherenceHash(dimensions: PostureCoherenceDimension[]): Promise<string> {
  return sha256Hex(
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

/**
 * The schema tags a saved coherence artifact may carry.
 *  - `v1` (spec-v14) — the unpinned artifact: rungs + integrity hash.
 *  - `v2` (spec-v15) — additionally carries a `ladder_hash` pinning the playbook
 *    ladder the rungs were computed against, so a consuming round can refuse a
 *    cross-ladder diff (comparing floors from different ladders is nonsense).
 *
 * The parser accepts both. The builder emits `v2` only when given a ladder hash,
 * so an emit without one is byte-identical to v14.
 */
export const COHERENCE_ARTIFACT_SCHEMA_V1 = "vaulytica.posture-coherence.v1";
export const COHERENCE_ARTIFACT_SCHEMA_V2 = "vaulytica.posture-coherence.v2";
/** Back-compat alias for the original (v1) schema tag. */
export const COHERENCE_ARTIFACT_SCHEMA = COHERENCE_ARTIFACT_SCHEMA_V1;
const VALID_SCHEMAS = new Set([COHERENCE_ARTIFACT_SCHEMA_V1, COHERENCE_ARTIFACT_SCHEMA_V2]);

/**
 * Serialize a {@link PostureCoherence} to a stable, pretty-printed JSON artifact
 * (spec-v14 Thrust A) — a portable baseline a later round can gate against
 * without re-checking-out the prior round's documents. The dimension and document
 * order is already pinned by {@link bundlePostureCoherence}, and the key order is
 * fixed here, so the same coherence always yields identical bytes; the embedded
 * `coherence_hash` is the canonical fingerprint, re-derivable from `dimensions`.
 *
 * When `ladderHash` is supplied (spec-v15) the artifact is tagged `v2` and
 * carries it, pinning the playbook ladder the rungs sit on so a consuming round
 * can refuse a cross-ladder diff. Omit it and the bytes are identical to v14's
 * `v1` artifact — the `ladder_hash` field is the only addition, and it is
 * independent of `coherence_hash` (which still covers `dimensions` only, so the
 * v1 and v2 artifacts of one coherence share the same integrity hash).
 */
export function buildPostureCoherenceJson(
  coherence: PostureCoherence,
  ladderHash?: string | null,
): string {
  const dimensions = coherence.dimensions.map((d) => ({
    dimension: d.dimension,
    tiers: d.tiers.map((t) => ({ document: t.document, tier: t.tier })),
    weakest_tier: d.weakest_tier,
    weakest_documents: d.weakest_documents,
    coherence: d.coherence,
  }));
  const body =
    ladderHash != null
      ? {
          schema: COHERENCE_ARTIFACT_SCHEMA_V2,
          coherence_hash: coherence.coherence_hash,
          ladder_hash: ladderHash,
          counts: coherence.counts,
          dimensions,
        }
      : {
          schema: COHERENCE_ARTIFACT_SCHEMA_V1,
          coherence_hash: coherence.coherence_hash,
          counts: coherence.counts,
          dimensions,
        };
  return JSON.stringify(body, null, 2);
}

const VALID_TIERS = new Set<NegotiationTier>(Object.keys(TIER_RANK) as NegotiationTier[]);
const VALID_KINDS = new Set<PostureCoherenceKind>(["aligned", "divergent", "single", "unstated"]);

export type ParsedCoherence =
  | {
      ok: true;
      coherence: PostureCoherence;
      /** The pinned ladder fingerprint (spec-v15 `v2` artifact), or `null` for an unpinned `v1` artifact. */
      ladderHash: string | null;
    }
  | { ok: false; errors: string[] };

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * Parse and **verify** a saved coherence artifact (spec-v14 Thrust A). Beyond a
 * structural check, this re-derives the `coherence_hash` from the artifact's own
 * `dimensions` and rejects the file when it does not match the embedded hash — so
 * a corrupted, truncated, or hand-edited baseline can never silently drive a CI
 * gate. The hash verifies the artifact's integrity; it cannot verify the two
 * rounds used the **same** playbook ladder (the §3 cross-ladder contract the
 * caller owns, exactly as v13's re-analyze path does).
 *
 * Returns a discriminated result mirroring `parseCustomPlaybookJson` — never
 * throws on bad input, so the CLI can surface every error at once.
 */
export async function parsePostureCoherenceJson(text: string): Promise<ParsedCoherence> {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (e) {
    return { ok: false, errors: [`not valid JSON: ${(e as Error).message}`] };
  }
  if (!isObject(raw)) return { ok: false, errors: ["top-level value must be an object"] };

  const errors: string[] = [];
  if (typeof raw.schema !== "string" || !VALID_SCHEMAS.has(raw.schema)) {
    errors.push(
      `schema must be one of ${[...VALID_SCHEMAS].map((s) => `"${s}"`).join(", ")} (got ${JSON.stringify(raw.schema)})`,
    );
  }
  if (typeof raw.coherence_hash !== "string") errors.push("coherence_hash must be a string");
  // A v2 artifact pins the ladder; a v1 artifact must not carry one (it would be
  // an unverifiable claim the parser cannot honor).
  const isV2 = raw.schema === COHERENCE_ARTIFACT_SCHEMA_V2;
  if (isV2 && typeof raw.ladder_hash !== "string") {
    errors.push(`ladder_hash must be a string for ${COHERENCE_ARTIFACT_SCHEMA_V2}`);
  }
  if (!isV2 && raw.ladder_hash !== undefined) {
    errors.push(`ladder_hash is only valid for ${COHERENCE_ARTIFACT_SCHEMA_V2}`);
  }
  if (!Array.isArray(raw.dimensions)) {
    errors.push("dimensions must be an array");
    return { ok: false, errors };
  }

  const dimensions: PostureCoherenceDimension[] = [];
  raw.dimensions.forEach((d: unknown, i: number) => {
    const at = `dimensions[${i}]`;
    if (!isObject(d)) {
      errors.push(`${at} must be an object`);
      return;
    }
    if (typeof d.dimension !== "string") errors.push(`${at}.dimension must be a string`);
    if (d.weakest_tier !== null && !VALID_TIERS.has(d.weakest_tier as NegotiationTier)) {
      errors.push(`${at}.weakest_tier must be a tier or null`);
    }
    if (!VALID_KINDS.has(d.coherence as PostureCoherenceKind)) {
      errors.push(`${at}.coherence must be one of ${[...VALID_KINDS].join(", ")}`);
    }
    if (
      !Array.isArray(d.weakest_documents) ||
      !d.weakest_documents.every((x) => typeof x === "string")
    ) {
      errors.push(`${at}.weakest_documents must be an array of strings`);
    }
    if (!Array.isArray(d.tiers)) {
      errors.push(`${at}.tiers must be an array`);
      return;
    }
    const tiers: DocumentTier[] = [];
    d.tiers.forEach((t: unknown, j: number) => {
      if (!isObject(t) || typeof t.document !== "string" || !VALID_TIERS.has(t.tier as NegotiationTier)) {
        errors.push(`${at}.tiers[${j}] must be { document: string, tier: <tier> }`);
        return;
      }
      tiers.push({ document: t.document, tier: t.tier as NegotiationTier });
    });
    dimensions.push({
      dimension: d.dimension as string,
      tiers,
      weakest_tier: (d.weakest_tier ?? null) as NegotiationTier | null,
      weakest_documents: (d.weakest_documents ?? []) as string[],
      coherence: d.coherence as PostureCoherenceKind,
    });
  });

  if (errors.length > 0) return { ok: false, errors };

  // Integrity: re-derive the fingerprint and reject any drift from the embedded
  // hash. This is what makes a saved baseline trustworthy as a CI gate input.
  const recomputed = await coherenceHash(dimensions);
  if (recomputed !== raw.coherence_hash) {
    return {
      ok: false,
      errors: [
        `coherence_hash mismatch — the artifact was modified or is corrupt (embedded ${String(
          raw.coherence_hash,
        ).slice(0, 12)}…, recomputed ${recomputed.slice(0, 12)}…)`,
      ],
    };
  }

  // Recompute counts from the verified dimensions rather than trusting the
  // artifact's `counts` field — the hash covers `dimensions` only, so a derived
  // tally is recomputed, never imported.
  const counts = emptyCounts();
  for (const d of dimensions) counts[d.coherence] += 1;
  return {
    ok: true,
    coherence: { dimensions, counts, coherence_hash: raw.coherence_hash as string },
    ladderHash: isV2 ? (raw.ladder_hash as string) : null,
  };
}
