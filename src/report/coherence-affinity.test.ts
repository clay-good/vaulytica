import { describe, expect, it } from "vitest";
import {
  computeCoherenceAffinity,
  exposureCoupled,
  buildCoherenceAffinityJson,
  renderCoherenceAffinitySummary,
} from "./coherence-affinity.js";
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

/** The expected co-fall total = Σ over transitions of C(falling, 2). */
function chooseTwoSum(perFalling: number[]): number {
  return perFalling.reduce((sum, k) => sum + (k * (k - 1)) / 2, 0);
}

describe("computeCoherenceAffinity (spec-v32 — pairwise co-fall coupling)", () => {
  it("measures a stable coupling — two fronts that fall together for a strict majority", async () => {
    // Cap and Term both start acceptable, then fall together at round 2 and again (after a
    // joint recovery) at round 4. Every time either fell, the other fell with it.
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
    ]);
    const aff = await computeCoherenceAffinity(rounds);
    expect(aff.pairs).toHaveLength(1);
    const pair = aff.pairs[0]!;
    expect(pair.dimension_a).toBe("Cap");
    expect(pair.dimension_b).toBe("Term");
    expect(pair.a_falls).toBe(2);
    expect(pair.b_falls).toBe(2);
    expect(pair.co_falls).toBe(2);
    expect(pair.union_falls).toBe(2);
    expect(pair.affinity).toBe(1);
    expect(pair.class).toBe("coupled");
    expect(aff.coupled).toBe(true);
    expect(exposureCoupled(aff)).toBe(true);
    expect(aff.tightest_pair).toEqual(["Cap", "Term"]);
    expect(aff.max_affinity).toBe(1);
  });

  it("separates a coupling from a coincidence — v29 trips on a concerted step, v32 does not", async () => {
    // Cap & Term co-fall ONCE (r1→2, a concerted step v29 catches), then Cap falls alone twice
    // more (r3→4, r5→6) and Term falls alone once (r6→7). They fell together 1 of the 4 steps
    // either fell → incidental. v29 reports one concerted fall (gate trips); v32 reports no
    // coupling (gate clears) — the divergence that motivates the axis.
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r1
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // r2: both fall (T0)
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r3: both recover
      mk({ Cap: "below-acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r4: Cap falls alone (T2)
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r5: Cap recovers
      mk({ Cap: "below-acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r6: Cap falls alone (T4)
      mk({ Cap: "acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // r7: Cap recovers, Term falls alone (T5)
    ]);
    const aff = await computeCoherenceAffinity(rounds);
    const conc = await computeCoherenceConcurrency(rounds);
    // v29: exactly one concerted fall (the r1→2 step where both fell), gate trips.
    expect(conc.concerted_fall_count).toBe(1);
    expect(conc.concerted).toBe(true);
    // v32: the single shared fall is a minority of the union → no coupling, gate clears.
    expect(aff.coupled).toBe(false);
    expect(exposureCoupled(aff)).toBe(false);
    const pair = aff.pairs.find((p) => p.dimension_a === "Cap" && p.dimension_b === "Term")!;
    expect(pair.a_falls).toBe(3); // Cap fell at T0, T2, T4
    expect(pair.b_falls).toBe(2); // Term fell at T0, T5
    expect(pair.co_falls).toBe(1); // together only at T0
    expect(pair.union_falls).toBe(4);
    expect(pair.class).toBe("incidental");
  });

  it("a co-fall requires BOTH fronts to fall the same step — one-fell-one-recovered is not a co-fall", async () => {
    // r1→2: Cap falls while Term recovers. They cross the floor the same step (a v25 synchrony
    // of two) but in OPPOSITE directions — not a co-fall.
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "below-acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
    ]);
    const aff = await computeCoherenceAffinity(rounds);
    expect(aff.pairs).toHaveLength(0); // no co-fall edge
    expect(aff.max_affinity).toBeNull();
    expect(aff.tightest_pair).toBeNull();
    expect(aff.coupled).toBe(false);
    expect(aff.total_co_falls).toBe(0);
  });

  it("an exact split is incidental, not coupled (together 1 of a 2-step union)", async () => {
    // Cap & Term co-fall once (r1→2). Then Cap recovers and Term holds below; Cap falls alone
    // again (r3→4) → union 2, together 1, exact split → incidental.
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
    ]);
    const aff = await computeCoherenceAffinity(rounds);
    const pair = aff.pairs[0]!;
    expect(pair.co_falls).toBe(1);
    expect(pair.union_falls).toBe(2);
    expect(pair.affinity).toBeCloseTo(0.5);
    expect(pair.class).toBe("incidental");
    expect(aff.coupled).toBe(false);
  });

  it("total_co_falls equals Σ C(falling, 2) and total_falls equals v29's total_falls (join invariants)", async () => {
    const rounds = await Promise.all([
      mk(
        { Cap: "acceptable", Term: "acceptable", Fee: "acceptable" },
        { Cap: "ideal", Term: "ideal", Fee: "ideal" },
      ),
      // all three fall together
      mk(
        { Cap: "below-acceptable", Term: "below-acceptable", Fee: "below-acceptable" },
        { Cap: "ideal", Term: "ideal", Fee: "ideal" },
      ),
      // all three recover
      mk(
        { Cap: "acceptable", Term: "acceptable", Fee: "acceptable" },
        { Cap: "ideal", Term: "ideal", Fee: "ideal" },
      ),
      // two fall together
      mk(
        { Cap: "below-acceptable", Term: "below-acceptable", Fee: "acceptable" },
        { Cap: "ideal", Term: "ideal", Fee: "ideal" },
      ),
    ]);
    const aff = await computeCoherenceAffinity(rounds);
    const conc = await computeCoherenceConcurrency(rounds);
    // Per-transition falling counts: [3, 0, 2] → C(3,2)+C(0,2)+C(2,2)=3+0+1=4.
    expect(conc.per_transition.map((t) => t.falling)).toEqual([3, 0, 2]);
    expect(aff.total_co_falls).toBe(chooseTwoSum(conc.per_transition.map((t) => t.falling)));
    expect(aff.total_co_falls).toBe(4);
    expect(aff.total_falls).toBe(conc.total_falls);
  });

  it("picks the tightest pairing across pairs by exact integer ratio (earliest pair on a tie)", async () => {
    // Build so Cap+Term have affinity 1/2 and Fee+Risk have affinity 1/1 (tighter).
    const rounds = await Promise.all([
      mk(
        { Cap: "acceptable", Term: "acceptable", Fee: "acceptable", Risk: "acceptable" },
        { Cap: "ideal", Term: "ideal", Fee: "ideal", Risk: "ideal" },
      ),
      // Cap & Term fall together; Fee & Risk fall together.
      mk(
        {
          Cap: "below-acceptable",
          Term: "below-acceptable",
          Fee: "below-acceptable",
          Risk: "below-acceptable",
        },
        { Cap: "ideal", Term: "ideal", Fee: "ideal", Risk: "ideal" },
      ),
      // Cap recovers; Term holds below; Fee & Risk recover.
      mk(
        {
          Cap: "acceptable",
          Term: "below-acceptable",
          Fee: "acceptable",
          Risk: "acceptable",
        },
        { Cap: "ideal", Term: "ideal", Fee: "ideal", Risk: "ideal" },
      ),
      // Cap falls alone → Cap fell twice, Term once, together once: union 2, affinity 1/2.
      mk(
        {
          Cap: "below-acceptable",
          Term: "below-acceptable",
          Fee: "acceptable",
          Risk: "acceptable",
        },
        { Cap: "ideal", Term: "ideal", Fee: "ideal", Risk: "ideal" },
      ),
    ]);
    const aff = await computeCoherenceAffinity(rounds);
    const capTerm = aff.pairs.find((p) => p.dimension_a === "Cap" && p.dimension_b === "Term")!;
    const feeRisk = aff.pairs.find((p) => p.dimension_a === "Fee" && p.dimension_b === "Risk")!;
    expect(capTerm.affinity).toBeCloseTo(0.5);
    expect(feeRisk.affinity).toBe(1);
    expect(aff.tightest_pair).toEqual(["Fee", "Risk"]);
    expect(aff.max_affinity).toBe(1);
  });

  it("breaks a tightest-pairing tie by earliest pair (localeCompare order)", async () => {
    // Two disjoint pairs each co-fall once and never fall apart → both affinity 1.0; the
    // earlier pair (Aaa+Bbb) wins.
    const rounds = await Promise.all([
      mk(
        { Aaa: "acceptable", Bbb: "acceptable", Yyy: "acceptable", Zzz: "acceptable" },
        { Aaa: "ideal", Bbb: "ideal", Yyy: "ideal", Zzz: "ideal" },
      ),
      mk(
        {
          Aaa: "below-acceptable",
          Bbb: "below-acceptable",
          Yyy: "below-acceptable",
          Zzz: "below-acceptable",
        },
        { Aaa: "ideal", Bbb: "ideal", Yyy: "ideal", Zzz: "ideal" },
      ),
    ]);
    const aff = await computeCoherenceAffinity(rounds);
    // C(4,2) = 6 pairs all co-fall once → all affinity 1.0; earliest pair wins.
    expect(aff.max_affinity).toBe(1);
    expect(aff.tightest_pair).toEqual(["Aaa", "Bbb"]);
  });

  it("reports no tightest pairing when no two fronts ever fell together", async () => {
    // Cap falls r1→2; Term falls r2→3 — never the same step.
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "below-acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
    ]);
    const aff = await computeCoherenceAffinity(rounds);
    expect(aff.pairs).toHaveLength(0);
    expect(aff.max_affinity).toBeNull();
    expect(aff.tightest_pair).toBeNull();
    expect(aff.coupled).toBe(false);
    expect(aff.total_co_falls).toBe(0);
    expect(aff.total_falls).toBe(2);
  });

  it("treats silence as neither a fall nor a recovery (§3) — a fall across a silent gap is on the revealing step", async () => {
    // Cap & Term fall together r1→2, recover at r3, both go SILENT at r4, then both below at r5.
    // The fall is attributed to the step that REVEALS the new standing (r4→5), not the silent
    // step — and no fall is invented across the gap. They still co-fall twice → coupled.
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r1
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // r2: both fall
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r3: both recover
      mk({ Cap: "unevaluable", Term: "unevaluable" }, { Cap: "unevaluable", Term: "unevaluable" }), // r4: silent
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // r5: both fall (revealed)
    ]);
    const aff = await computeCoherenceAffinity(rounds);
    const pair = aff.pairs[0]!;
    expect(pair.a_falls).toBe(2);
    expect(pair.b_falls).toBe(2);
    expect(pair.co_falls).toBe(2);
    expect(pair.class).toBe("coupled");
  });

  it("a pair that both-fell once reads 100% / coupled (no minimum-union count)", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
    ]);
    const aff = await computeCoherenceAffinity(rounds);
    const pair = aff.pairs[0]!;
    expect(pair.co_falls).toBe(1);
    expect(pair.union_falls).toBe(1);
    expect(pair.affinity).toBe(1);
    expect(pair.class).toBe("coupled");
    expect(aff.coupled).toBe(true);
  });

  it("is deterministic: identical rounds in identical order → identical affinity_hash", async () => {
    const build = () =>
      Promise.all([
        mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
        mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
        mk({ Cap: "acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
      ]);
    const a = await computeCoherenceAffinity(await build());
    const c = await computeCoherenceAffinity(await build());
    expect(a.affinity_hash).toBe(c.affinity_hash);
    expect(a.affinity_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("throws on fewer than two rounds", async () => {
    const rounds = [await mk({ Cap: "ideal" }, { Cap: "ideal" })];
    await expect(computeCoherenceAffinity(rounds)).rejects.toThrow(/at least two rounds/);
  });

  it("renders the tightest-pairing verdict and stable JSON", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
    ]);
    const aff = await computeCoherenceAffinity(rounds);
    const summary = renderCoherenceAffinitySummary(aff);
    expect(summary).toContain("Coherence exposure co-fall affinity across 2 rounds");
    expect(summary).toMatch(
      /tightest pairing: Cap \+ Term — fell together 100% of the steps either fell/,
    );
    expect(summary).toMatch(/1 coupled/);
    expect(summary).toMatch(/affinity_hash: [0-9a-f]{64}/);

    const json = JSON.parse(buildCoherenceAffinityJson(aff));
    expect(json.schema).toBe("vaulytica.posture-affinity.v1");
    expect(json.affinity_hash).toBe(aff.affinity_hash);
    expect(json.rounds).toBe(2);
    expect(json.total_co_falls).toBe(1);
    expect(json.total_falls).toBe(2);
    expect(json.tightest_pair).toEqual(["Cap", "Term"]);
    expect(json.coupled).toBe(true);
    expect(json.pairs[0]).toMatchObject({
      dimension_a: "Cap",
      dimension_b: "Term",
      co_falls: 1,
      union_falls: 1,
      class: "coupled",
    });
  });

  it("renders a none-paired verdict distinctly", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
    ]);
    const summary = renderCoherenceAffinitySummary(await computeCoherenceAffinity(rounds));
    expect(summary).toMatch(/tightest pairing: none/);
  });
});
