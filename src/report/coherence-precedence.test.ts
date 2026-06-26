import { describe, expect, it } from "vitest";
import {
  computeCoherencePrecedence,
  exposureLeads,
  buildCoherencePrecedenceJson,
  renderCoherencePrecedenceSummary,
} from "./coherence-precedence.js";
import { computeCoherenceOpposition } from "./coherence-opposition.js";
import { computeCoherenceSynchrony } from "./coherence-synchrony.js";
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

describe("computeCoherencePrecedence (spec-v35 — pairwise lead-lag / who crosses first)", () => {
  it("measures a clear leader — one front consistently crosses the floor first", async () => {
    // Cap crosses at transitions {0,2}; Term crosses at {1,3}. Three of four comparisons have Cap
    // first (the fourth has Term first), no same-step ties → a strict-majority lead.
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r0
      mk({ Cap: "below-acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r1: Cap↓ (t0)
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // r2: Term↓ (t1)
      mk({ Cap: "acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // r3: Cap↑ (t2)
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r4: Term↑ (t3)
    ]);
    const prec = await computeCoherencePrecedence(rounds);
    expect(prec.pairs).toHaveLength(1);
    const pair = prec.pairs[0]!;
    expect(pair.dimension_a).toBe("Cap");
    expect(pair.dimension_b).toBe("Term");
    expect(pair.a_leads).toBe(3); // Cap crossed first in 3 comparisons
    expect(pair.b_leads).toBe(1);
    expect(pair.co_crossings).toBe(0); // never crossed in the same step — a pure ordering signal
    expect(pair.comparisons).toBe(4);
    expect(pair.leader).toBe("Cap");
    expect(pair.affinity).toBe(0.75);
    expect(pair.class).toBe("leading");
    expect(prec.leads).toBe(true);
    expect(exposureLeads(prec)).toBe(true);
    expect(prec.most_leading_pair).toEqual(["Cap", "Term"]);
    expect(prec.leading_front).toBe("Cap");
    expect(prec.max_affinity).toBe(0.75);
  });

  it("an interleaved pair (mixed order, no strict-majority first-mover) clears the gate", async () => {
    // Cap crosses {0,2}; Term crosses {0,1}. Comparisons: 1 tie, 1 Cap-first, 2 Term-first → no
    // strict majority of all comparisons (leaderLeads 2 of 4 is not > 4/2).
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r0
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // r1: both↓ (t0)
      mk({ Cap: "below-acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r2: Term↑ (t1)
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r3: Cap↑ (t2)
    ]);
    const prec = await computeCoherencePrecedence(rounds);
    const pair = prec.pairs[0]!;
    expect(pair.a_leads).toBe(1);
    expect(pair.b_leads).toBe(2);
    expect(pair.co_crossings).toBe(1);
    expect(pair.comparisons).toBe(4);
    expect(pair.leader).toBe("Term"); // a plurality, but not a strict majority
    expect(pair.affinity).toBe(0.5);
    expect(pair.class).toBe("interleaved");
    expect(prec.leads).toBe(false);
    // It still has a leader, so it headlines the most-leading pick.
    expect(prec.most_leading_pair).toEqual(["Cap", "Term"]);
    expect(prec.leading_front).toBe("Term");
    expect(prec.max_affinity).toBe(0.5);
  });

  it("co_crossings equals v34's joint_moves per pair, and summed equals v25's Σ C(crossing,2) (join invariant)", async () => {
    const rounds = await Promise.all([
      mk(
        { Cap: "below-acceptable", Term: "below-acceptable", Fee: "acceptable" },
        { Cap: "ideal", Term: "ideal", Fee: "ideal" },
      ),
      // Cap & Term recover, Fee falls — all three cross at t0.
      mk(
        { Cap: "acceptable", Term: "acceptable", Fee: "below-acceptable" },
        { Cap: "ideal", Term: "ideal", Fee: "ideal" },
      ),
      // Cap & Term fall, Fee recovers — all three cross at t1.
      mk(
        { Cap: "below-acceptable", Term: "below-acceptable", Fee: "acceptable" },
        { Cap: "ideal", Term: "ideal", Fee: "ideal" },
      ),
    ]);
    const prec = await computeCoherencePrecedence(rounds);
    const opp = await computeCoherenceOpposition(rounds);
    const sync = await computeCoherenceSynchrony(rounds);

    // Every front crosses at both t0 and t1 → each pair has co_crossings 2, the same as v34's
    // per-pair joint_moves.
    for (const p of prec.pairs) {
      const oppPair = opp.pairs.find(
        (o) => o.dimension_a === p.dimension_a && o.dimension_b === p.dimension_b,
      );
      if (oppPair) expect(p.co_crossings).toBe(oppPair.joint_moves);
    }

    // Σ_t C(crossing_t, 2): t0 = C(3,2) = 3, t1 = C(3,2) = 3 → 6. Equals v34's total joint moves
    // (opposed + aligned), and v25's per-step synchrony pairs.
    expect(prec.total_co_crossings).toBe(6);
    expect(prec.total_co_crossings).toBe(opp.total_opposed_moves + opp.total_aligned_moves);
    expect(prec.total_co_crossings).toBe(
      sync.per_transition.reduce(
        (s, t) => s + (t.crossing_fronts * (t.crossing_fronts - 1)) / 2,
        0,
      ),
    );
  });

  it("treats silence as neither a fall nor a recovery (§3) — a crossing across a silent gap is on the revealing step", async () => {
    // Cap falls (t0), both go silent (r2), Cap recovers & Term falls revealed at r3 (t2).
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r0
      mk({ Cap: "below-acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r1: Cap↓ (t0)
      mk({ Cap: "unevaluable", Term: "unevaluable" }, { Cap: "unevaluable", Term: "unevaluable" }), // r2: silent
      mk({ Cap: "acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // r3: Cap↑, Term↓ revealed (t2)
    ]);
    const prec = await computeCoherencePrecedence(rounds);
    expect(prec.pairs).toHaveLength(1);
    const pair = prec.pairs[0]!;
    // Cap crossed at {0, 2}; Term crossed at {2}. The Cap t0 crossing precedes Term's t2; the two
    // both cross at t2 (a tie) — the crossing across the silent gap is held at the revealing step.
    expect(pair.a_leads).toBe(1);
    expect(pair.b_leads).toBe(0);
    expect(pair.co_crossings).toBe(1);
    expect(pair.leader).toBe("Cap");
  });

  it("picks the most-leading pairing across pairs by exact integer ratio (ratio beats label order)", async () => {
    // Aaa crosses {0,1,3}; Mmm crosses {2}; Zzz crosses {3}. (Aaa,Mmm) leads 2/3; (Mmm,Zzz) leads
    // 1/1 — the tighter (Mmm,Zzz) wins even though it sorts *after* (Aaa,Mmm). The pick is by ratio.
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
      ), // r2: Aaa↑ (t1)
      mk(
        { Aaa: "acceptable", Mmm: "below-acceptable", Zzz: "acceptable" },
        { Aaa: "ideal", Mmm: "ideal", Zzz: "ideal" },
      ), // r3: Mmm↓ (t2)
      mk(
        { Aaa: "below-acceptable", Mmm: "below-acceptable", Zzz: "below-acceptable" },
        { Aaa: "ideal", Mmm: "ideal", Zzz: "ideal" },
      ), // r4: Aaa↓ (t3), Zzz↓ (t3)
    ]);
    const prec = await computeCoherencePrecedence(rounds);
    const aaaMmm = prec.pairs.find((p) => p.dimension_a === "Aaa" && p.dimension_b === "Mmm")!;
    const mmmZzz = prec.pairs.find((p) => p.dimension_a === "Mmm" && p.dimension_b === "Zzz")!;
    expect(aaaMmm.affinity).toBeCloseTo(2 / 3);
    expect(aaaMmm.class).toBe("leading");
    expect(mmmZzz.affinity).toBe(1);
    expect(mmmZzz.class).toBe("leading");
    expect(prec.most_leading_pair).toEqual(["Mmm", "Zzz"]);
    expect(prec.leading_front).toBe("Mmm");
    expect(prec.max_affinity).toBe(1);
  });

  it("breaks a most-leading tie by earliest pair (localeCompare order)", async () => {
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
    const prec = await computeCoherencePrecedence(rounds);
    expect(prec.max_affinity).toBe(1);
    expect(prec.most_leading_pair).toEqual(["Aaa", "Bbb"]);
    expect(prec.leading_front).toBe("Aaa");
  });

  it("reports no most-leading pairing when no pair has a consistent first-mover", async () => {
    // Cap & Term always cross the same steps → every comparison is a same-step tie or an even split;
    // no front leads.
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // both↓ (t0)
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // both↑ (t1)
    ]);
    const prec = await computeCoherencePrecedence(rounds);
    const pair = prec.pairs[0]!;
    expect(pair.a_leads).toBe(1);
    expect(pair.b_leads).toBe(1);
    expect(pair.co_crossings).toBe(2);
    expect(pair.leader).toBeNull();
    expect(pair.class).toBe("interleaved");
    expect(prec.most_leading_pair).toBeNull();
    expect(prec.leading_front).toBeNull();
    expect(prec.max_affinity).toBeNull();
    expect(prec.leads).toBe(false);
  });

  it("omits a pair with no ordered comparison (the two only ever crossed in the same step)", async () => {
    // Cap & Term both fall at t0 and never cross again → only a same-step tie, no ordering.
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
    ]);
    const prec = await computeCoherencePrecedence(rounds);
    expect(prec.pairs).toHaveLength(0); // no lead-lag edge
    expect(prec.total_ordered_comparisons).toBe(0);
    expect(prec.total_co_crossings).toBe(1); // but the same-step tie still counts toward the total
    expect(prec.most_leading_pair).toBeNull();
    expect(prec.leads).toBe(false);
  });

  it("a pair with a single ordered comparison reads 100% / leading (no minimum-comparison count)", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "below-acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // Cap↓ (t0)
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // Term↓ (t1)
    ]);
    const prec = await computeCoherencePrecedence(rounds);
    const pair = prec.pairs[0]!;
    expect(pair.a_leads).toBe(1);
    expect(pair.b_leads).toBe(0);
    expect(pair.co_crossings).toBe(0);
    expect(pair.comparisons).toBe(1);
    expect(pair.affinity).toBe(1);
    expect(pair.leader).toBe("Cap");
    expect(pair.class).toBe("leading");
    expect(prec.leads).toBe(true);
  });

  it("is deterministic: identical rounds in identical order → identical precedence_hash", async () => {
    const build = () =>
      Promise.all([
        mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
        mk({ Cap: "below-acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
        mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
      ]);
    const a = await computeCoherencePrecedence(await build());
    const c = await computeCoherencePrecedence(await build());
    expect(a.precedence_hash).toBe(c.precedence_hash);
    expect(a.precedence_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("throws on fewer than two rounds", async () => {
    const rounds = [await mk({ Cap: "ideal" }, { Cap: "ideal" })];
    await expect(computeCoherencePrecedence(rounds)).rejects.toThrow(/at least two rounds/);
  });

  it("renders the most-leading verdict and stable JSON", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "below-acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // Cap↓ (t0)
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // Term↓ (t1)
    ]);
    const prec = await computeCoherencePrecedence(rounds);
    const summary = renderCoherencePrecedenceSummary(prec);
    expect(summary).toContain("Coherence exposure precedence across 3 rounds");
    expect(summary).toMatch(
      /most-leading pairing: Cap leads Term — crossed first 100% of the comparisons/,
    );
    expect(summary).toMatch(/1 leading/);
    expect(summary).toMatch(/precedence_hash: [0-9a-f]{64}/);

    const json = JSON.parse(buildCoherencePrecedenceJson(prec));
    expect(json.schema).toBe("vaulytica.posture-precedence.v1");
    expect(json.precedence_hash).toBe(prec.precedence_hash);
    expect(json.rounds).toBe(3);
    expect(json.total_ordered_comparisons).toBe(1);
    expect(json.total_co_crossings).toBe(0);
    expect(json.most_leading_pair).toEqual(["Cap", "Term"]);
    expect(json.leading_front).toBe("Cap");
    expect(json.leads).toBe(true);
    expect(json.pairs[0]).toMatchObject({
      dimension_a: "Cap",
      dimension_b: "Term",
      a_leads: 1,
      b_leads: 0,
      comparisons: 1,
      leader: "Cap",
      class: "leading",
    });
  });

  it("renders a none-leading verdict distinctly", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // both↓ (t0)
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // both↑ (t1)
    ]);
    const summary = renderCoherencePrecedenceSummary(await computeCoherencePrecedence(rounds));
    expect(summary).toMatch(/most-leading pairing: none/);
  });
});
