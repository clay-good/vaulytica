import { describe, expect, it } from "vitest";
import {
  computeCoherenceConcession,
  exposureConcedes,
  buildCoherenceConcessionJson,
  renderCoherenceConcessionSummary,
} from "./coherence-concession.js";
import { computeCoherenceAffinity } from "./coherence-affinity.js";
import { computeCoherencePrecedence } from "./coherence-precedence.js";
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

describe("computeCoherenceConcession (spec-v36 — fall-precedence / who concedes first)", () => {
  it("measures a clear first-conceder — one front consistently falls below floor first", async () => {
    // Cap falls at transitions {0,2}; Term falls at {1,3}. Three of four comparisons have Cap
    // first (the fourth has Term first), no same-step ties → a strict-majority concession lead.
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r0
      mk({ Cap: "below-acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r1: Cap↓ (t0)
      mk({ Cap: "acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // r2: Cap↑, Term↓ (t1: Term falls)
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // r3: Cap↓ (t2)
      mk({ Cap: "below-acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r4: Term↑ (no fall)
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // r5: Term↓ (t4)
    ]);
    // Cap falls {t0, t2}; Term falls {t1, t4}. Comparisons: t0<t1 (Cap), t0<t4 (Cap), t2>t1 (Term),
    // t2<t4 (Cap) → Cap 3, Term 1, no ties.
    const conc = await computeCoherenceConcession(rounds);
    expect(conc.pairs).toHaveLength(1);
    const pair = conc.pairs[0]!;
    expect(pair.dimension_a).toBe("Cap");
    expect(pair.dimension_b).toBe("Term");
    expect(pair.a_concedes_first).toBe(3);
    expect(pair.b_concedes_first).toBe(1);
    expect(pair.co_falls).toBe(0);
    expect(pair.comparisons).toBe(4);
    expect(pair.first_conceder).toBe("Cap");
    expect(pair.affinity).toBe(0.75);
    expect(pair.class).toBe("leading");
    expect(conc.concedes).toBe(true);
    expect(exposureConcedes(conc)).toBe(true);
    expect(conc.most_conceding_pair).toEqual(["Cap", "Term"]);
    expect(conc.first_conceding_front).toBe("Cap");
    expect(conc.max_affinity).toBe(0.75);
  });

  it("is distinct from v35 precedence: a pair that leads on all crossings can interleave on falls", async () => {
    // Cap falls {t0}, recovers {t1}, falls {t2}; Term falls {t1}, recovers {t2}. Crossings (any
    // direction): Cap {0,1,2}, Term {1,2}. On *falls only*: Cap {0,2}, Term {1}.
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r0
      mk({ Cap: "below-acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r1: Cap↓ (t0)
      mk({ Cap: "acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // r2: Cap↑, Term↓ (t1)
      mk({ Cap: "below-acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r3: Cap↓, Term↑ (t2)
    ]);
    const conc = await computeCoherenceConcession(rounds);
    const prec = await computeCoherencePrecedence(rounds);
    // Falls only: Cap {0,2}, Term {1}. Comparisons: 0<1 Cap, 2>1 Term → Cap 1, Term 1, split.
    const cPair = conc.pairs[0]!;
    expect(cPair.a_concedes_first).toBe(1);
    expect(cPair.b_concedes_first).toBe(1);
    expect(cPair.first_conceder).toBeNull();
    expect(cPair.class).toBe("interleaved");
    expect(conc.concedes).toBe(false);
    // But v35 (all crossings: Cap {0,1,2}, Term {1,2}) sees a leader.
    const pPair = prec.pairs[0]!;
    expect(pPair.leader).not.toBeNull();
  });

  it("co_falls equals v32's per-pair co_falls, and summed equals Σ C(falling,2) (join invariant)", async () => {
    const rounds = await Promise.all([
      mk(
        { Cap: "acceptable", Term: "acceptable", Fee: "acceptable" },
        { Cap: "ideal", Term: "ideal", Fee: "ideal" },
      ),
      // Cap, Term, Fee all fall at t0.
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
    ]);
    const conc = await computeCoherenceConcession(rounds);
    const aff = await computeCoherenceAffinity(rounds);
    const concur = await computeCoherenceConcurrency(rounds);

    // Every pair falls together at t0 and t2 → co_falls 2 per pair, the same as v32's co_falls.
    for (const p of conc.pairs) {
      const affPair = aff.pairs.find(
        (a) => a.dimension_a === p.dimension_a && a.dimension_b === p.dimension_b,
      );
      if (affPair) expect(p.co_falls).toBe(affPair.co_falls);
    }

    // Σ_t C(falling_t, 2): t0 = C(3,2) = 3, t2 = C(3,2) = 3 → 6. Equals v32's total_co_falls.
    expect(conc.total_co_falls).toBe(6);
    expect(conc.total_co_falls).toBe(aff.total_co_falls);
    expect(conc.total_co_falls).toBe(
      concur.per_transition.reduce((s, t) => s + (t.falling * (t.falling - 1)) / 2, 0),
    );
  });

  it("treats silence as neither a fall nor a recovery (§3) — a fall across a silent gap is on the revealing step", async () => {
    // Cap falls (t0), both go silent (r2), Cap & Term both fall revealed at r3 — but Cap was already
    // below, so only Term newly falls at t2; Cap does not re-fall.
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r0
      mk({ Cap: "below-acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r1: Cap↓ (t0)
      mk({ Cap: "unevaluable", Term: "unevaluable" }, { Cap: "unevaluable", Term: "unevaluable" }), // r2: silent
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // r3: Term↓ revealed (t2); Cap unchanged
    ]);
    const conc = await computeCoherenceConcession(rounds);
    expect(conc.pairs).toHaveLength(1);
    const pair = conc.pairs[0]!;
    // Cap fell at {0}; Term fell at {2}. The one comparison has Cap first → Cap concedes first.
    expect(pair.a_concedes_first).toBe(1);
    expect(pair.b_concedes_first).toBe(0);
    expect(pair.co_falls).toBe(0);
    expect(pair.first_conceder).toBe("Cap");
    expect(pair.class).toBe("leading");
  });

  it("picks the most-conceding pairing across pairs by exact integer ratio (ratio beats label order)", async () => {
    // Aaa falls {0,1,3}; Mmm falls {2}; Zzz falls {3}. (Aaa,Mmm) leads 2/3; (Mmm,Zzz) leads 1/1 —
    // the tighter (Mmm,Zzz) wins even though it sorts *after* (Aaa,Mmm). The pick is by ratio.
    const rounds = await Promise.all([
      mk(
        { Aaa: "acceptable", Mmm: "acceptable", Zzz: "acceptable" },
        { Aaa: "ideal", Mmm: "ideal", Zzz: "ideal" },
      ), // r0
      mk(
        { Aaa: "below-acceptable", Mmm: "acceptable", Zzz: "acceptable" },
        { Aaa: "ideal", Mmm: "ideal", Zzz: "ideal" },
      ), // r1: Aaa↓ (t0)
      mk(
        { Aaa: "acceptable", Mmm: "acceptable", Zzz: "acceptable" },
        { Aaa: "ideal", Mmm: "ideal", Zzz: "ideal" },
      ), // r2: Aaa↑ (no fall)
      mk(
        { Aaa: "below-acceptable", Mmm: "acceptable", Zzz: "acceptable" },
        { Aaa: "ideal", Mmm: "ideal", Zzz: "ideal" },
      ), // r3: Aaa↓ (t2)
      mk(
        { Aaa: "acceptable", Mmm: "below-acceptable", Zzz: "acceptable" },
        { Aaa: "ideal", Mmm: "ideal", Zzz: "ideal" },
      ), // r4: Aaa↑ (no fall), Mmm↓ (t3)
      mk(
        { Aaa: "below-acceptable", Mmm: "below-acceptable", Zzz: "below-acceptable" },
        { Aaa: "ideal", Mmm: "ideal", Zzz: "ideal" },
      ), // r5: Aaa↓ (t4), Zzz↓ (t4)
    ]);
    // Aaa falls {0,2,4}; Mmm falls {3}; Zzz falls {4}.
    const conc = await computeCoherenceConcession(rounds);
    const aaaMmm = conc.pairs.find((p) => p.dimension_a === "Aaa" && p.dimension_b === "Mmm")!;
    const mmmZzz = conc.pairs.find((p) => p.dimension_a === "Mmm" && p.dimension_b === "Zzz")!;
    // Aaa {0,2,4} vs Mmm {3}: 0<3, 2<3, 4>3 → Aaa 2, Mmm 1 → 2/3.
    expect(aaaMmm.affinity).toBeCloseTo(2 / 3);
    expect(aaaMmm.class).toBe("leading");
    // Mmm {3} vs Zzz {4}: 3<4 → Mmm 1/1.
    expect(mmmZzz.affinity).toBe(1);
    expect(mmmZzz.class).toBe("leading");
    expect(conc.most_conceding_pair).toEqual(["Mmm", "Zzz"]);
    expect(conc.first_conceding_front).toBe("Mmm");
    expect(conc.max_affinity).toBe(1);
  });

  it("breaks a most-conceding tie by earliest pair (localeCompare order)", async () => {
    // Four fronts fall one transition apart → every pair leads 1.0; the earliest pair wins.
    const rounds = await Promise.all([
      mk(
        { Aaa: "acceptable", Bbb: "acceptable", Yyy: "acceptable", Zzz: "acceptable" },
        { Aaa: "ideal", Bbb: "ideal", Yyy: "ideal", Zzz: "ideal" },
      ),
      mk(
        { Aaa: "below-acceptable", Bbb: "acceptable", Yyy: "acceptable", Zzz: "acceptable" },
        { Aaa: "ideal", Bbb: "ideal", Yyy: "ideal", Zzz: "ideal" },
      ), // Aaa↓ (t0)
      mk(
        { Aaa: "below-acceptable", Bbb: "below-acceptable", Yyy: "acceptable", Zzz: "acceptable" },
        { Aaa: "ideal", Bbb: "ideal", Yyy: "ideal", Zzz: "ideal" },
      ), // Bbb↓ (t1)
      mk(
        {
          Aaa: "below-acceptable",
          Bbb: "below-acceptable",
          Yyy: "below-acceptable",
          Zzz: "acceptable",
        },
        { Aaa: "ideal", Bbb: "ideal", Yyy: "ideal", Zzz: "ideal" },
      ), // Yyy↓ (t2)
      mk(
        {
          Aaa: "below-acceptable",
          Bbb: "below-acceptable",
          Yyy: "below-acceptable",
          Zzz: "below-acceptable",
        },
        { Aaa: "ideal", Bbb: "ideal", Yyy: "ideal", Zzz: "ideal" },
      ), // Zzz↓ (t3)
    ]);
    const conc = await computeCoherenceConcession(rounds);
    expect(conc.max_affinity).toBe(1);
    expect(conc.most_conceding_pair).toEqual(["Aaa", "Bbb"]);
    expect(conc.first_conceding_front).toBe("Aaa");
  });

  it("reports no most-conceding pairing when no pair has a consistent first-conceder", async () => {
    // Cap & Term always fall the same steps → every comparison is a same-step tie or an even split.
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // both↓ (t0)
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // both↑ (no fall)
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // both↓ (t2)
    ]);
    const conc = await computeCoherenceConcession(rounds);
    const pair = conc.pairs[0]!;
    // Cap {0,2}, Term {0,2}: 0=0 tie, 0<2 Cap, 2>0 Term, 2=2 tie → Cap 1, Term 1, ties 2.
    expect(pair.a_concedes_first).toBe(1);
    expect(pair.b_concedes_first).toBe(1);
    expect(pair.co_falls).toBe(2);
    expect(pair.first_conceder).toBeNull();
    expect(pair.class).toBe("interleaved");
    expect(conc.most_conceding_pair).toBeNull();
    expect(conc.first_conceding_front).toBeNull();
    expect(conc.max_affinity).toBeNull();
    expect(conc.concedes).toBe(false);
  });

  it("omits a pair with no ordered comparison (the two only ever fell in the same step)", async () => {
    // Cap & Term both fall at t0 and never fall again → only a same-step tie, no ordering.
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
    ]);
    const conc = await computeCoherenceConcession(rounds);
    expect(conc.pairs).toHaveLength(0); // no concession-order edge
    expect(conc.total_ordered_comparisons).toBe(0);
    expect(conc.total_co_falls).toBe(1); // but the same-step tie still counts toward the total
    expect(conc.most_conceding_pair).toBeNull();
    expect(conc.concedes).toBe(false);
  });

  it("a pair with a single ordered comparison reads 100% / leading (no minimum-comparison count)", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "below-acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // Cap↓ (t0)
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // Term↓ (t1)
    ]);
    const conc = await computeCoherenceConcession(rounds);
    const pair = conc.pairs[0]!;
    expect(pair.a_concedes_first).toBe(1);
    expect(pair.b_concedes_first).toBe(0);
    expect(pair.co_falls).toBe(0);
    expect(pair.comparisons).toBe(1);
    expect(pair.affinity).toBe(1);
    expect(pair.first_conceder).toBe("Cap");
    expect(pair.class).toBe("leading");
    expect(conc.concedes).toBe(true);
  });

  it("is deterministic: identical rounds in identical order → identical concession_hash", async () => {
    const build = () =>
      Promise.all([
        mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
        mk({ Cap: "below-acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
        mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
      ]);
    const a = await computeCoherenceConcession(await build());
    const c = await computeCoherenceConcession(await build());
    expect(a.concession_hash).toBe(c.concession_hash);
    expect(a.concession_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("throws on fewer than two rounds", async () => {
    const rounds = [await mk({ Cap: "ideal" }, { Cap: "ideal" })];
    await expect(computeCoherenceConcession(rounds)).rejects.toThrow(/at least two rounds/);
  });

  it("renders the most-conceding verdict and stable JSON", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "below-acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // Cap↓ (t0)
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // Term↓ (t1)
    ]);
    const conc = await computeCoherenceConcession(rounds);
    const summary = renderCoherenceConcessionSummary(conc);
    expect(summary).toContain("Coherence exposure concession order across 3 rounds");
    expect(summary).toMatch(
      /most-conceding pairing: Cap concedes before Term — fell first 100% of the comparisons/,
    );
    expect(summary).toMatch(/1 leading/);
    expect(summary).toMatch(/concession_hash: [0-9a-f]{64}/);

    const json = JSON.parse(buildCoherenceConcessionJson(conc));
    expect(json.schema).toBe("vaulytica.posture-concession.v1");
    expect(json.concession_hash).toBe(conc.concession_hash);
    expect(json.rounds).toBe(3);
    expect(json.total_ordered_comparisons).toBe(1);
    expect(json.total_co_falls).toBe(0);
    expect(json.most_conceding_pair).toEqual(["Cap", "Term"]);
    expect(json.first_conceding_front).toBe("Cap");
    expect(json.concedes).toBe(true);
    expect(json.pairs[0]).toMatchObject({
      dimension_a: "Cap",
      dimension_b: "Term",
      a_concedes_first: 1,
      b_concedes_first: 0,
      comparisons: 1,
      first_conceder: "Cap",
      class: "leading",
    });
  });

  it("renders a none-conceding verdict distinctly", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // both↓ (t0)
    ]);
    const summary = renderCoherenceConcessionSummary(await computeCoherenceConcession(rounds));
    expect(summary).toMatch(/most-conceding pairing: none/);
  });
});
