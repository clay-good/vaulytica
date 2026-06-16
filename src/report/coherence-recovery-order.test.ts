import { describe, expect, it } from "vitest";
import {
  computeCoherenceRecoveryOrder,
  exposureLags,
  buildCoherenceRecoveryOrderJson,
  renderCoherenceRecoveryOrderSummary,
} from "./coherence-recovery-order.js";
import { computeCoherenceRecoveryAffinity } from "./coherence-recovery-affinity.js";
import { computeCoherenceConcession } from "./coherence-concession.js";
import { computeCoherenceConcurrency } from "./coherence-concurrency.js";
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

describe("computeCoherenceRecoveryOrder (spec-v37 — recovery-precedence / who recovers first/last)", () => {
  it("measures a clear first-recoverer and laggard — one front consistently climbs back first", async () => {
    // Cap recovers at transitions {0,2}; Term recovers at {1,4}. Three of four comparisons have Cap
    // first (the fourth has Term first), no same-step ties → a strict-majority recovery lead, so Term
    // is the consistent laggard.
    const rounds = await Promise.all([
      mk({ Cap: "below-acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r0: Cap below
      mk({ Cap: "acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // r1: Cap↑ (t0), Term↓
      mk({ Cap: "below-acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r2: Cap↓, Term↑ (t1)
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r3: Cap↑ (t2)
      mk({ Cap: "acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // r4: Term↓
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r5: Term↑ (t4)
    ]);
    // Cap recovers {t0, t2}; Term recovers {t1, t4}. Comparisons: t0<t1 (Cap), t0<t4 (Cap), t2>t1
    // (Term), t2<t4 (Cap) → Cap 3, Term 1, no ties.
    const ro = await computeCoherenceRecoveryOrder(rounds);
    expect(ro.pairs).toHaveLength(1);
    const pair = ro.pairs[0]!;
    expect(pair.dimension_a).toBe("Cap");
    expect(pair.dimension_b).toBe("Term");
    expect(pair.a_recovers_first).toBe(3);
    expect(pair.b_recovers_first).toBe(1);
    expect(pair.co_recoveries).toBe(0);
    expect(pair.comparisons).toBe(4);
    expect(pair.first_recoverer).toBe("Cap");
    expect(pair.last_recoverer).toBe("Term");
    expect(pair.affinity).toBe(0.75);
    expect(pair.class).toBe("leading");
    expect(ro.lags).toBe(true);
    expect(exposureLags(ro)).toBe(true);
    expect(ro.most_ordered_pair).toEqual(["Cap", "Term"]);
    expect(ro.first_recovering_front).toBe("Cap");
    expect(ro.last_recovering_front).toBe("Term");
    expect(ro.max_affinity).toBe(0.75);
  });

  it("is distinct from v36 concession: a pair that leads on falls can interleave on recoveries", async () => {
    // Cap falls {0,2}, recovers {1,5}; Term falls {3}, recovers {4}. On *falls only* (v36): Cap leads.
    // On *recoveries only* (v37): Cap {1,5}, Term {4} → 1<4 Cap, 5>4 Term → split.
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r0
      mk({ Cap: "below-acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r1: Cap↓ (t0)
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r2: Cap↑ (t1)
      mk({ Cap: "below-acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r3: Cap↓ (t2)
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // r4: Term↓ (t3)
      mk({ Cap: "below-acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r5: Term↑ (t4)
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r6: Cap↑ (t5)
    ]);
    const ro = await computeCoherenceRecoveryOrder(rounds);
    const conc = await computeCoherenceConcession(rounds);
    // Recoveries only: Cap {1,5}, Term {4}. Comparisons: 1<4 Cap, 5>4 Term → Cap 1, Term 1, split.
    const rPair = ro.pairs[0]!;
    expect(rPair.a_recovers_first).toBe(1);
    expect(rPair.b_recovers_first).toBe(1);
    expect(rPair.first_recoverer).toBeNull();
    expect(rPair.last_recoverer).toBeNull();
    expect(rPair.class).toBe("interleaved");
    expect(ro.lags).toBe(false);
    // But v36 (falls only: Cap {0,2}, Term {3}) sees a leader.
    const cPair = conc.pairs[0]!;
    expect(cPair.first_conceder).toBe("Cap");
    expect(cPair.class).toBe("leading");
  });

  it("co_recoveries equals v33's per-pair co_recoveries, and summed equals Σ C(recovering,2)", async () => {
    const rounds = await Promise.all([
      mk(
        { Cap: "acceptable", Term: "acceptable", Fee: "acceptable" },
        { Cap: "ideal", Term: "ideal", Fee: "ideal" },
      ),
      // all fall at t0
      mk(
        { Cap: "below-acceptable", Term: "below-acceptable", Fee: "below-acceptable" },
        { Cap: "ideal", Term: "ideal", Fee: "ideal" },
      ),
      // all recover at t1
      mk(
        { Cap: "acceptable", Term: "acceptable", Fee: "acceptable" },
        { Cap: "ideal", Term: "ideal", Fee: "ideal" },
      ),
      // all fall again at t2
      mk(
        { Cap: "below-acceptable", Term: "below-acceptable", Fee: "below-acceptable" },
        { Cap: "ideal", Term: "ideal", Fee: "ideal" },
      ),
      // all recover again at t3
      mk(
        { Cap: "acceptable", Term: "acceptable", Fee: "acceptable" },
        { Cap: "ideal", Term: "ideal", Fee: "ideal" },
      ),
    ]);
    const ro = await computeCoherenceRecoveryOrder(rounds);
    const aff = await computeCoherenceRecoveryAffinity(rounds);
    const concur = await computeCoherenceConcurrency(rounds);

    // Every pair recovers together at t1 and t3 → co_recoveries 2 per pair, the same as v33's.
    for (const p of ro.pairs) {
      const affPair = aff.pairs.find(
        (a) => a.dimension_a === p.dimension_a && a.dimension_b === p.dimension_b,
      );
      if (affPair) expect(p.co_recoveries).toBe(affPair.co_recoveries);
    }

    // Σ_t C(recovering_t, 2): t1 = C(3,2) = 3, t3 = C(3,2) = 3 → 6. Equals v33's total_co_recoveries.
    expect(ro.total_co_recoveries).toBe(6);
    expect(ro.total_co_recoveries).toBe(aff.total_co_recoveries);
    expect(ro.total_co_recoveries).toBe(
      concur.per_transition.reduce((s, t) => s + (t.recovering * (t.recovering - 1)) / 2, 0),
    );
  });

  it("treats silence as neither a fall nor a recovery (§3) — a recovery across a silent gap is on the revealing step", async () => {
    // Cap recovers (t0), both go silent (r2), Term's recovery is revealed at r3 — Cap was already above,
    // so only Term newly recovers at t2; Cap does not re-recover.
    const rounds = await Promise.all([
      mk({ Cap: "below-acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r0: Cap below
      mk({ Cap: "acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // r1: Cap↑ (t0), Term↓
      mk({ Cap: "unevaluable", Term: "unevaluable" }, { Cap: "unevaluable", Term: "unevaluable" }), // r2: silent
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r3: Term↑ revealed (t2); Cap unchanged
    ]);
    const ro = await computeCoherenceRecoveryOrder(rounds);
    expect(ro.pairs).toHaveLength(1);
    const pair = ro.pairs[0]!;
    // Cap recovered at {0}; Term recovered at {2}. The one comparison has Cap first.
    expect(pair.a_recovers_first).toBe(1);
    expect(pair.b_recovers_first).toBe(0);
    expect(pair.co_recoveries).toBe(0);
    expect(pair.first_recoverer).toBe("Cap");
    expect(pair.last_recoverer).toBe("Term");
    expect(pair.class).toBe("leading");
  });

  it("picks the clearest recovery order across pairs by exact integer ratio (ratio beats label order)", async () => {
    // Aaa recovers {0,2,4}; Mmm recovers {3}; Zzz recovers {4}. (Aaa,Mmm) leads 2/3; (Mmm,Zzz) leads
    // 1/1 — the tighter (Mmm,Zzz) wins even though it sorts *after* (Aaa,Mmm). The pick is by ratio.
    const rounds = await Promise.all([
      mk(
        { Aaa: "below-acceptable", Mmm: "acceptable", Zzz: "acceptable" },
        { Aaa: "ideal", Mmm: "ideal", Zzz: "ideal" },
      ), // r0: Aaa below
      mk(
        { Aaa: "acceptable", Mmm: "acceptable", Zzz: "acceptable" },
        { Aaa: "ideal", Mmm: "ideal", Zzz: "ideal" },
      ), // r1: Aaa↑ (t0)
      mk(
        { Aaa: "below-acceptable", Mmm: "acceptable", Zzz: "acceptable" },
        { Aaa: "ideal", Mmm: "ideal", Zzz: "ideal" },
      ), // r2: Aaa↓
      mk(
        { Aaa: "acceptable", Mmm: "below-acceptable", Zzz: "acceptable" },
        { Aaa: "ideal", Mmm: "ideal", Zzz: "ideal" },
      ), // r3: Aaa↑ (t2), Mmm↓
      mk(
        { Aaa: "below-acceptable", Mmm: "acceptable", Zzz: "below-acceptable" },
        { Aaa: "ideal", Mmm: "ideal", Zzz: "ideal" },
      ), // r4: Aaa↓, Mmm↑ (t3), Zzz↓
      mk(
        { Aaa: "acceptable", Mmm: "acceptable", Zzz: "acceptable" },
        { Aaa: "ideal", Mmm: "ideal", Zzz: "ideal" },
      ), // r5: Aaa↑ (t4), Zzz↑ (t4)
    ]);
    // Aaa recovers {0,2,4}; Mmm recovers {3}; Zzz recovers {4}.
    const ro = await computeCoherenceRecoveryOrder(rounds);
    const aaaMmm = ro.pairs.find((p) => p.dimension_a === "Aaa" && p.dimension_b === "Mmm")!;
    const mmmZzz = ro.pairs.find((p) => p.dimension_a === "Mmm" && p.dimension_b === "Zzz")!;
    // Aaa {0,2,4} vs Mmm {3}: 0<3, 2<3, 4>3 → Aaa 2, Mmm 1 → 2/3.
    expect(aaaMmm.affinity).toBeCloseTo(2 / 3);
    expect(aaaMmm.class).toBe("leading");
    // Mmm {3} vs Zzz {4}: 3<4 → Mmm 1/1.
    expect(mmmZzz.affinity).toBe(1);
    expect(mmmZzz.class).toBe("leading");
    expect(ro.most_ordered_pair).toEqual(["Mmm", "Zzz"]);
    expect(ro.first_recovering_front).toBe("Mmm");
    expect(ro.last_recovering_front).toBe("Zzz");
    expect(ro.max_affinity).toBe(1);
  });

  it("breaks a clearest-order tie by earliest pair (localeCompare order)", async () => {
    // Four fronts recover one transition apart → every pair leads 1.0; the earliest pair wins.
    const rounds = await Promise.all([
      mk(
        { Aaa: "below-acceptable", Bbb: "below-acceptable", Yyy: "below-acceptable", Zzz: "below-acceptable" },
        { Aaa: "ideal", Bbb: "ideal", Yyy: "ideal", Zzz: "ideal" },
      ),
      mk(
        { Aaa: "acceptable", Bbb: "below-acceptable", Yyy: "below-acceptable", Zzz: "below-acceptable" },
        { Aaa: "ideal", Bbb: "ideal", Yyy: "ideal", Zzz: "ideal" },
      ), // Aaa↑ (t0)
      mk(
        { Aaa: "acceptable", Bbb: "acceptable", Yyy: "below-acceptable", Zzz: "below-acceptable" },
        { Aaa: "ideal", Bbb: "ideal", Yyy: "ideal", Zzz: "ideal" },
      ), // Bbb↑ (t1)
      mk(
        { Aaa: "acceptable", Bbb: "acceptable", Yyy: "acceptable", Zzz: "below-acceptable" },
        { Aaa: "ideal", Bbb: "ideal", Yyy: "ideal", Zzz: "ideal" },
      ), // Yyy↑ (t2)
      mk(
        { Aaa: "acceptable", Bbb: "acceptable", Yyy: "acceptable", Zzz: "acceptable" },
        { Aaa: "ideal", Bbb: "ideal", Yyy: "ideal", Zzz: "ideal" },
      ), // Zzz↑ (t3)
    ]);
    const ro = await computeCoherenceRecoveryOrder(rounds);
    expect(ro.max_affinity).toBe(1);
    expect(ro.most_ordered_pair).toEqual(["Aaa", "Bbb"]);
    expect(ro.first_recovering_front).toBe("Aaa");
    expect(ro.last_recovering_front).toBe("Bbb");
  });

  it("reports no recovery order when no pair has a consistent first-recoverer", async () => {
    // Cap & Term always recover the same steps → every comparison is a same-step tie or an even split.
    const rounds = await Promise.all([
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // both↑ (t0)
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // both↓
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // both↑ (t2)
    ]);
    const ro = await computeCoherenceRecoveryOrder(rounds);
    const pair = ro.pairs[0]!;
    // Cap {0,2}, Term {0,2}: 0=0 tie, 0<2 Cap, 2>0 Term, 2=2 tie → Cap 1, Term 1, ties 2.
    expect(pair.a_recovers_first).toBe(1);
    expect(pair.b_recovers_first).toBe(1);
    expect(pair.co_recoveries).toBe(2);
    expect(pair.first_recoverer).toBeNull();
    expect(pair.last_recoverer).toBeNull();
    expect(pair.class).toBe("interleaved");
    expect(ro.most_ordered_pair).toBeNull();
    expect(ro.first_recovering_front).toBeNull();
    expect(ro.last_recovering_front).toBeNull();
    expect(ro.max_affinity).toBeNull();
    expect(ro.lags).toBe(false);
  });

  it("omits a pair with no ordered comparison (the two only ever recovered in the same step)", async () => {
    // Cap & Term both recover at t0 and never recover again → only a same-step tie, no ordering.
    const rounds = await Promise.all([
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
    ]);
    const ro = await computeCoherenceRecoveryOrder(rounds);
    expect(ro.pairs).toHaveLength(0); // no recovery-order edge
    expect(ro.total_ordered_comparisons).toBe(0);
    expect(ro.total_co_recoveries).toBe(1); // but the same-step tie still counts toward the total
    expect(ro.most_ordered_pair).toBeNull();
    expect(ro.lags).toBe(false);
  });

  it("a pair with a single ordered comparison reads 100% / leading (no minimum-comparison count)", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // Cap↑ (t0)
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // Term↑ (t1)
    ]);
    const ro = await computeCoherenceRecoveryOrder(rounds);
    const pair = ro.pairs[0]!;
    expect(pair.a_recovers_first).toBe(1);
    expect(pair.b_recovers_first).toBe(0);
    expect(pair.co_recoveries).toBe(0);
    expect(pair.comparisons).toBe(1);
    expect(pair.affinity).toBe(1);
    expect(pair.first_recoverer).toBe("Cap");
    expect(pair.last_recoverer).toBe("Term");
    expect(pair.class).toBe("leading");
    expect(ro.lags).toBe(true);
  });

  it("is deterministic: identical rounds in identical order → identical recovery_order_hash", async () => {
    const build = () =>
      Promise.all([
        mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
        mk({ Cap: "acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
        mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
      ]);
    const a = await computeCoherenceRecoveryOrder(await build());
    const c = await computeCoherenceRecoveryOrder(await build());
    expect(a.recovery_order_hash).toBe(c.recovery_order_hash);
    expect(a.recovery_order_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("throws on fewer than two rounds", async () => {
    const rounds = [await mk({ Cap: "ideal" }, { Cap: "ideal" })];
    await expect(computeCoherenceRecoveryOrder(rounds)).rejects.toThrow(/at least two rounds/);
  });

  it("renders the clearest recovery order and stable JSON", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // Cap↑ (t0)
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // Term↑ (t1)
    ]);
    const ro = await computeCoherenceRecoveryOrder(rounds);
    const summary = renderCoherenceRecoveryOrderSummary(ro);
    expect(summary).toContain("Coherence exposure recovery order across 3 rounds");
    expect(summary).toMatch(
      /clearest recovery order: Cap recovers before Term — Term recovers last \(left exposed longest\), Cap first 100% of the comparisons/,
    );
    expect(summary).toMatch(/1 leading/);
    expect(summary).toMatch(/recovery_order_hash: [0-9a-f]{64}/);

    const json = JSON.parse(buildCoherenceRecoveryOrderJson(ro));
    expect(json.schema).toBe("vaulytica.posture-recovery-order.v1");
    expect(json.recovery_order_hash).toBe(ro.recovery_order_hash);
    expect(json.rounds).toBe(3);
    expect(json.total_ordered_comparisons).toBe(1);
    expect(json.total_co_recoveries).toBe(0);
    expect(json.most_ordered_pair).toEqual(["Cap", "Term"]);
    expect(json.first_recovering_front).toBe("Cap");
    expect(json.last_recovering_front).toBe("Term");
    expect(json.lags).toBe(true);
    expect(json.pairs[0]).toMatchObject({
      dimension_a: "Cap",
      dimension_b: "Term",
      a_recovers_first: 1,
      b_recovers_first: 0,
      comparisons: 1,
      first_recoverer: "Cap",
      last_recoverer: "Term",
      class: "leading",
    });
  });

  it("renders a none-ordered verdict distinctly", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // both↑ (t0)
    ]);
    const summary = renderCoherenceRecoveryOrderSummary(await computeCoherenceRecoveryOrder(rounds));
    expect(summary).toMatch(/clearest recovery order: none/);
  });
});
