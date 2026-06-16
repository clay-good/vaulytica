import { describe, expect, it } from "vitest";
import {
  computeCoherenceOpposition,
  exposureOpposed,
  buildCoherenceOppositionJson,
  renderCoherenceOppositionSummary,
} from "./coherence-opposition.js";
import { computeCoherenceConcurrency } from "./coherence-concurrency.js";
import { computeCoherenceAffinity } from "./coherence-affinity.js";
import { computeCoherenceRecoveryAffinity } from "./coherence-recovery-affinity.js";
import { bundlePostureCoherence, type CoherenceInput } from "./posture-coherence.js";
import type { NegotiationPosture, NegotiationTier } from "../playbooks/custom-interpreter.js";

function posture(map: Record<string, NegotiationTier>): NegotiationPosture {
  return {
    positions: Object.entries(map).map(([dimension, tier]) => ({ dimension, tier })),
    counts: { ideal: 0, acceptable: 0, below_acceptable: 0, unevaluable: 0 },
    posture_hash: "test",
  };
}

const bundle = (...docs: Array<[string, Record<string, NegotiationTier>]>): CoherenceInput[] =>
  docs.map(([document, map]) => ({ document, posture: posture(map) }));

/** A round built from two docs; each front's binding floor is the weaker of the two tiers. */
const mk = (a: Record<string, NegotiationTier>, b: Record<string, NegotiationTier>) =>
  bundlePostureCoherence(bundle(["msa.docx", a], ["order.docx", b]));

/** The expected opposed total = Σ over transitions of falling × recovering. */
function crossSum(perFalling: number[], perRecovering: number[]): number {
  return perFalling.reduce((sum, f, i) => sum + f * perRecovering[i]!, 0);
}

describe("computeCoherenceOpposition (spec-v34 — pairwise counter-move coupling)", () => {
  it("measures a see-saw — two fronts that move opposite ways for a strict majority of joint steps", async () => {
    // Cap starts below, Term starts above. They swap every step: Cap recovers as Term falls,
    // then Cap falls as Term recovers, repeatedly. Every joint crossing is opposed.
    const rounds = await Promise.all([
      mk({ Cap: "below-acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // Cap↑ Term↓
      mk({ Cap: "below-acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // Cap↓ Term↑
      mk({ Cap: "acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // Cap↑ Term↓
    ]);
    const opp = await computeCoherenceOpposition(rounds);
    expect(opp.pairs).toHaveLength(1);
    const pair = opp.pairs[0]!;
    expect(pair.dimension_a).toBe("Cap");
    expect(pair.dimension_b).toBe("Term");
    expect(pair.co_falls).toBe(0);
    expect(pair.co_recoveries).toBe(0);
    expect(pair.opposed_moves).toBe(3);
    expect(pair.joint_moves).toBe(3);
    expect(pair.affinity).toBe(1);
    expect(pair.class).toBe("opposed");
    expect(opp.opposed).toBe(true);
    expect(exposureOpposed(opp)).toBe(true);
    expect(opp.most_opposed_pair).toEqual(["Cap", "Term"]);
    expect(opp.max_affinity).toBe(1);
  });

  it("a counter-move requires one front to FALL while the other RECOVERS — co-falls and co-recoveries are not opposed", async () => {
    // Cap & Term fall together, then recover together — always aligned, never opposed.
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // both fall
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // both recover
    ]);
    const opp = await computeCoherenceOpposition(rounds);
    expect(opp.pairs).toHaveLength(0); // no counter-move edge
    expect(opp.max_affinity).toBeNull();
    expect(opp.most_opposed_pair).toBeNull();
    expect(opp.opposed).toBe(false);
    expect(opp.total_opposed_moves).toBe(0);
    // But the aligned total picks up the co-fall and co-recovery.
    expect(opp.total_aligned_moves).toBe(2);
  });

  it("an exact split is incidental, not opposed (opposed 1 of a 2-step joint set)", async () => {
    // r1→2: Cap falls, Term recovers (opposed). r3→4: both fall together (aligned co-fall). Joint
    // moves 2, opposed 1 → exact split → incidental.
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // r1
      mk({ Cap: "below-acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r2: Cap↓ Term↑ (opposed)
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r3: Cap↑, Term holds above — only Cap crosses → not joint
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // r4: both fall (aligned co-fall)
    ]);
    const opp = await computeCoherenceOpposition(rounds);
    const pair = opp.pairs[0]!;
    expect(pair.opposed_moves).toBe(1);
    expect(pair.co_falls).toBe(1);
    expect(pair.joint_moves).toBe(2);
    expect(pair.affinity).toBeCloseTo(0.5);
    expect(pair.class).toBe("incidental");
    expect(opp.opposed).toBe(false);
  });

  it("total_opposed_moves equals Σ falling×recovering and total_aligned_moves equals v32+v33 (join invariants)", async () => {
    const rounds = await Promise.all([
      mk(
        { Cap: "below-acceptable", Term: "below-acceptable", Fee: "acceptable" },
        { Cap: "ideal", Term: "ideal", Fee: "ideal" },
      ),
      // Cap & Term recover (aligned co-recovery), Fee falls — Fee opposes both Cap and Term.
      mk(
        { Cap: "acceptable", Term: "acceptable", Fee: "below-acceptable" },
        { Cap: "ideal", Term: "ideal", Fee: "ideal" },
      ),
      // Cap & Term fall together (aligned co-fall), Fee recovers — Fee opposes both again.
      mk(
        { Cap: "below-acceptable", Term: "below-acceptable", Fee: "acceptable" },
        { Cap: "ideal", Term: "ideal", Fee: "ideal" },
      ),
    ]);
    const opp = await computeCoherenceOpposition(rounds);
    const conc = await computeCoherenceConcurrency(rounds);
    const fall = await computeCoherenceAffinity(rounds);
    const rec = await computeCoherenceRecoveryAffinity(rounds);
    // Per-transition (falling, recovering): r1→2 = (1 Fee, 2 Cap&Term); r2→3 = (2 Cap&Term, 1 Fee).
    expect(conc.per_transition.map((t) => t.falling)).toEqual([1, 2]);
    expect(conc.per_transition.map((t) => t.recovering)).toEqual([2, 1]);
    // Σ falling×recovering = 1*2 + 2*1 = 4.
    expect(opp.total_opposed_moves).toBe(
      crossSum(
        conc.per_transition.map((t) => t.falling),
        conc.per_transition.map((t) => t.recovering),
      ),
    );
    expect(opp.total_opposed_moves).toBe(4);
    // Aligned = v32 co-falls (Cap&Term fell together once) + v33 co-recoveries (once) = 1 + 1 = 2.
    expect(opp.total_aligned_moves).toBe(fall.total_co_falls + rec.total_co_recoveries);
    expect(opp.total_aligned_moves).toBe(2);
  });

  it("picks the most-opposed pairing across pairs by exact integer ratio (ratio beats label order)", async () => {
    // Cap & Term move on steps 0–2 (oppose once, align once → 0.5); Fee & Risk move only on
    // step 3 (oppose once → 1.0). The movements are disjoint, so no cross-pair forms an edge. The
    // tighter Fee+Risk (1.0) wins even though it sorts *after* Cap+Term — the pick is by ratio.
    const all = (
      cap: NegotiationTier,
      term: NegotiationTier,
      fee: NegotiationTier,
      risk: NegotiationTier,
    ) =>
      mk(
        { Cap: cap, Term: term, Fee: fee, Risk: risk },
        { Cap: "ideal", Term: "ideal", Fee: "ideal", Risk: "ideal" },
      );
    const rounds = await Promise.all([
      all("below-acceptable", "acceptable", "below-acceptable", "acceptable"), // r1
      all("acceptable", "below-acceptable", "below-acceptable", "acceptable"), // r2: step0 Cap↑ Term↓ (opposed)
      all("below-acceptable", "below-acceptable", "below-acceptable", "acceptable"), // r3: step1 Cap↓ alone
      all("acceptable", "acceptable", "below-acceptable", "acceptable"), // r4: step2 Cap↑ Term↑ (co-recovery, aligned)
      all("acceptable", "acceptable", "acceptable", "below-acceptable"), // r5: step3 Fee↑ Risk↓ (opposed)
    ]);
    const opp = await computeCoherenceOpposition(rounds);
    const capTerm = opp.pairs.find((p) => p.dimension_a === "Cap" && p.dimension_b === "Term")!;
    const feeRisk = opp.pairs.find((p) => p.dimension_a === "Fee" && p.dimension_b === "Risk")!;
    expect(capTerm.affinity).toBeCloseTo(0.5);
    expect(capTerm.class).toBe("incidental");
    expect(feeRisk.affinity).toBe(1);
    expect(feeRisk.class).toBe("opposed");
    expect(opp.most_opposed_pair).toEqual(["Fee", "Risk"]);
    expect(opp.max_affinity).toBe(1);
  });

  it("breaks a most-opposed tie by earliest pair (localeCompare order)", async () => {
    // Four fronts; two-and-two swap once → all opposing pairs affinity 1.0; earliest pair wins.
    const rounds = await Promise.all([
      mk(
        {
          Aaa: "below-acceptable",
          Bbb: "acceptable",
          Yyy: "below-acceptable",
          Zzz: "acceptable",
        },
        { Aaa: "ideal", Bbb: "ideal", Yyy: "ideal", Zzz: "ideal" },
      ),
      // Aaa↑ Bbb↓; Yyy↑ Zzz↓.
      mk(
        { Aaa: "acceptable", Bbb: "below-acceptable", Yyy: "acceptable", Zzz: "below-acceptable" },
        { Aaa: "ideal", Bbb: "ideal", Yyy: "ideal", Zzz: "ideal" },
      ),
    ]);
    const opp = await computeCoherenceOpposition(rounds);
    expect(opp.max_affinity).toBe(1);
    expect(opp.most_opposed_pair).toEqual(["Aaa", "Bbb"]);
  });

  it("reports no most-opposed pairing when no two fronts ever counter-moved", async () => {
    // Cap falls r1→2; Term falls r2→3 — never opposite, never the same step.
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "below-acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
    ]);
    const opp = await computeCoherenceOpposition(rounds);
    expect(opp.pairs).toHaveLength(0);
    expect(opp.max_affinity).toBeNull();
    expect(opp.most_opposed_pair).toBeNull();
    expect(opp.opposed).toBe(false);
    expect(opp.total_opposed_moves).toBe(0);
  });

  it("treats silence as neither a fall nor a recovery (§3) — a counter-move across a silent gap is on the revealing step", async () => {
    // Cap below, Term above. Both go silent at r3, then reveal swapped standings at r4. The
    // counter-move is attributed to the revealing step (r3→4), not the silent step.
    const rounds = await Promise.all([
      mk({ Cap: "below-acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r1
      mk({ Cap: "below-acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r2: no change
      mk({ Cap: "unevaluable", Term: "unevaluable" }, { Cap: "unevaluable", Term: "unevaluable" }), // r3: silent
      mk({ Cap: "acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // r4: Cap↑ Term↓ revealed
    ]);
    const opp = await computeCoherenceOpposition(rounds);
    expect(opp.pairs).toHaveLength(1);
    const pair = opp.pairs[0]!;
    expect(pair.opposed_moves).toBe(1);
    expect(pair.joint_moves).toBe(1);
    expect(pair.class).toBe("opposed");
  });

  it("a pair that counter-moved once reads 100% / opposed (no minimum-joint count)", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "below-acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
    ]);
    const opp = await computeCoherenceOpposition(rounds);
    const pair = opp.pairs[0]!;
    expect(pair.opposed_moves).toBe(1);
    expect(pair.joint_moves).toBe(1);
    expect(pair.affinity).toBe(1);
    expect(pair.class).toBe("opposed");
    expect(opp.opposed).toBe(true);
  });

  it("diverges from v32/v33: a pair coupled on FALLS can be incidental (or edge-less) on OPPOSITION", async () => {
    // Cap & Term fall together twice (a v32 coupling) and never oppose → v32 coupled, v34 no edge.
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r1
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // r2: both fall
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r3: both recover
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // r4: both fall
    ]);
    const fall = await computeCoherenceAffinity(rounds);
    const opp = await computeCoherenceOpposition(rounds);
    const fallPair = fall.pairs.find((p) => p.dimension_a === "Cap" && p.dimension_b === "Term");
    expect(fallPair).toBeDefined();
    expect(fallPair!.class).toBe("coupled");
    expect(opp.pairs).toHaveLength(0); // never opposed
    expect(opp.opposed).toBe(false);
  });

  it("is deterministic: identical rounds in identical order → identical opposition_hash", async () => {
    const build = () =>
      Promise.all([
        mk({ Cap: "below-acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
        mk({ Cap: "acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
        mk({ Cap: "below-acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
      ]);
    const a = await computeCoherenceOpposition(await build());
    const c = await computeCoherenceOpposition(await build());
    expect(a.opposition_hash).toBe(c.opposition_hash);
    expect(a.opposition_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("throws on fewer than two rounds", async () => {
    const rounds = [await mk({ Cap: "ideal" }, { Cap: "ideal" })];
    await expect(computeCoherenceOpposition(rounds)).rejects.toThrow(/at least two rounds/);
  });

  it("renders the most-opposed verdict and stable JSON", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "below-acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
    ]);
    const opp = await computeCoherenceOpposition(rounds);
    const summary = renderCoherenceOppositionSummary(opp);
    expect(summary).toContain("Coherence exposure counter-move affinity across 2 rounds");
    expect(summary).toMatch(
      /most-opposed pairing: Cap \+ Term — counter-moved 100% of the steps both crossed/,
    );
    expect(summary).toMatch(/1 opposed/);
    expect(summary).toMatch(/opposition_hash: [0-9a-f]{64}/);

    const json = JSON.parse(buildCoherenceOppositionJson(opp));
    expect(json.schema).toBe("vaulytica.posture-opposition.v1");
    expect(json.opposition_hash).toBe(opp.opposition_hash);
    expect(json.rounds).toBe(2);
    expect(json.total_opposed_moves).toBe(1);
    expect(json.total_aligned_moves).toBe(0);
    expect(json.most_opposed_pair).toEqual(["Cap", "Term"]);
    expect(json.opposed).toBe(true);
    expect(json.pairs[0]).toMatchObject({
      dimension_a: "Cap",
      dimension_b: "Term",
      opposed_moves: 1,
      joint_moves: 1,
      class: "opposed",
    });
  });

  it("renders a none-paired verdict distinctly", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
    ]);
    const summary = renderCoherenceOppositionSummary(await computeCoherenceOpposition(rounds));
    expect(summary).toMatch(/most-opposed pairing: none/);
  });
});
