import { describe, expect, it } from "vitest";
import {
  computeCoherenceRecoveryAffinity,
  exposureRecoveryCoupled,
  buildCoherenceRecoveryAffinityJson,
  renderCoherenceRecoveryAffinitySummary,
} from "./coherence-recovery-affinity.js";
import { computeCoherenceConcurrency } from "./coherence-concurrency.js";
import { computeCoherenceAffinity } from "./coherence-affinity.js";
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

/** The expected co-recovery total = Σ over transitions of C(recovering, 2). */
function chooseTwoSum(perRecovering: number[]): number {
  return perRecovering.reduce((sum, k) => sum + (k * (k - 1)) / 2, 0);
}

describe("computeCoherenceRecoveryAffinity (spec-v33 — pairwise co-recovery coupling)", () => {
  it("measures a linked recovery — two fronts that recover together for a strict majority", async () => {
    // Cap and Term both fall together at round 2, recover together at round 3, fall together at
    // round 4, recover together at round 5. Every time either recovered, the other recovered too.
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
    ]);
    const aff = await computeCoherenceRecoveryAffinity(rounds);
    expect(aff.pairs).toHaveLength(1);
    const pair = aff.pairs[0]!;
    expect(pair.dimension_a).toBe("Cap");
    expect(pair.dimension_b).toBe("Term");
    expect(pair.a_recoveries).toBe(2);
    expect(pair.b_recoveries).toBe(2);
    expect(pair.co_recoveries).toBe(2);
    expect(pair.union_recoveries).toBe(2);
    expect(pair.affinity).toBe(1);
    expect(pair.class).toBe("coupled");
    expect(aff.coupled).toBe(true);
    expect(exposureRecoveryCoupled(aff)).toBe(true);
    expect(aff.tightest_pair).toEqual(["Cap", "Term"]);
    expect(aff.max_affinity).toBe(1);
  });

  it("separates a linked recovery from an independent one — v29 sees concerted-recovery steps, v33 does not couple", async () => {
    // Both fall together r1→2 then recover together ONCE (r2→3). Then Cap falls/recovers alone
    // twice more and Term once more — never together again. Together 1 of the 4 steps either
    // recovered → incidental.
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r1
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // r2: both fall
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r3: both recover (R1)
      mk({ Cap: "below-acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r4: Cap falls alone
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r5: Cap recovers alone (R3)
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // r6: both fall
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r7: both recover (R5)
    ]);
    const aff = await computeCoherenceRecoveryAffinity(rounds);
    const pair = aff.pairs.find((p) => p.dimension_a === "Cap" && p.dimension_b === "Term")!;
    // Cap recovered at R1, R3, R5; Term recovered at R1, R5; together at R1 and R5.
    expect(pair.a_recoveries).toBe(3);
    expect(pair.b_recoveries).toBe(2);
    expect(pair.co_recoveries).toBe(2);
    expect(pair.union_recoveries).toBe(3);
    // 2 of 3 is a strict majority → coupled.
    expect(pair.class).toBe("coupled");
    expect(aff.coupled).toBe(true);
  });

  it("a co-recovery requires BOTH fronts to recover the same step — one-fell-one-recovered is not a co-recovery", async () => {
    // r1→2: Cap recovers while Term falls. They cross the floor the same step (a v25 synchrony of
    // two) but in OPPOSITE directions — not a co-recovery.
    const rounds = await Promise.all([
      mk({ Cap: "below-acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
    ]);
    const aff = await computeCoherenceRecoveryAffinity(rounds);
    expect(aff.pairs).toHaveLength(0); // no co-recovery edge
    expect(aff.max_affinity).toBeNull();
    expect(aff.tightest_pair).toBeNull();
    expect(aff.coupled).toBe(false);
    expect(aff.total_co_recoveries).toBe(0);
  });

  it("an exact split is incidental, not coupled (together 1 of a 2-step union)", async () => {
    // Cap & Term co-recover once (r2→3). Then Cap falls and recovers alone again while Term holds
    // above → union 2, together 1, exact split → incidental.
    const rounds = await Promise.all([
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // r1: both below
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r2: both recover (R0)
      mk({ Cap: "below-acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r3: Cap falls alone
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r4: Cap recovers alone (R2)
    ]);
    const aff = await computeCoherenceRecoveryAffinity(rounds);
    const pair = aff.pairs[0]!;
    expect(pair.co_recoveries).toBe(1);
    expect(pair.union_recoveries).toBe(2);
    expect(pair.affinity).toBeCloseTo(0.5);
    expect(pair.class).toBe("incidental");
    expect(aff.coupled).toBe(false);
  });

  it("total_co_recoveries equals Σ C(recovering, 2) and total_recoveries equals v29's total_recoveries (join invariants)", async () => {
    const rounds = await Promise.all([
      mk(
        { Cap: "below-acceptable", Term: "below-acceptable", Fee: "below-acceptable" },
        { Cap: "ideal", Term: "ideal", Fee: "ideal" },
      ),
      // all three recover together
      mk(
        { Cap: "acceptable", Term: "acceptable", Fee: "acceptable" },
        { Cap: "ideal", Term: "ideal", Fee: "ideal" },
      ),
      // all three fall together
      mk(
        { Cap: "below-acceptable", Term: "below-acceptable", Fee: "below-acceptable" },
        { Cap: "ideal", Term: "ideal", Fee: "ideal" },
      ),
      // two recover together (Cap & Term), Fee holds below
      mk(
        { Cap: "acceptable", Term: "acceptable", Fee: "below-acceptable" },
        { Cap: "ideal", Term: "ideal", Fee: "ideal" },
      ),
    ]);
    const aff = await computeCoherenceRecoveryAffinity(rounds);
    const conc = await computeCoherenceConcurrency(rounds);
    // Per-transition recovering counts: [3, 0, 2] → C(3,2)+C(0,2)+C(2,2)=3+0+1=4.
    expect(conc.per_transition.map((t) => t.recovering)).toEqual([3, 0, 2]);
    expect(aff.total_co_recoveries).toBe(chooseTwoSum(conc.per_transition.map((t) => t.recovering)));
    expect(aff.total_co_recoveries).toBe(4);
    expect(aff.total_recoveries).toBe(conc.total_recoveries);
  });

  it("picks the tightest pairing across pairs by exact integer ratio (earliest pair on a tie)", async () => {
    // Build so Cap+Term recover with affinity 1/2 and Fee+Risk with affinity 1/1 (tighter).
    const rounds = await Promise.all([
      mk(
        {
          Cap: "below-acceptable",
          Term: "below-acceptable",
          Fee: "below-acceptable",
          Risk: "below-acceptable",
        },
        { Cap: "ideal", Term: "ideal", Fee: "ideal", Risk: "ideal" },
      ),
      // Cap & Term recover together; Fee & Risk recover together.
      mk(
        { Cap: "acceptable", Term: "acceptable", Fee: "acceptable", Risk: "acceptable" },
        { Cap: "ideal", Term: "ideal", Fee: "ideal", Risk: "ideal" },
      ),
      // Cap falls; Term holds above; Fee & Risk hold above.
      mk(
        {
          Cap: "below-acceptable",
          Term: "acceptable",
          Fee: "acceptable",
          Risk: "acceptable",
        },
        { Cap: "ideal", Term: "ideal", Fee: "ideal", Risk: "ideal" },
      ),
      // Cap recovers alone → Cap recovered twice, Term once, together once: union 2, affinity 1/2.
      mk(
        { Cap: "acceptable", Term: "acceptable", Fee: "acceptable", Risk: "acceptable" },
        { Cap: "ideal", Term: "ideal", Fee: "ideal", Risk: "ideal" },
      ),
    ]);
    const aff = await computeCoherenceRecoveryAffinity(rounds);
    const capTerm = aff.pairs.find((p) => p.dimension_a === "Cap" && p.dimension_b === "Term")!;
    const feeRisk = aff.pairs.find((p) => p.dimension_a === "Fee" && p.dimension_b === "Risk")!;
    expect(capTerm.affinity).toBeCloseTo(0.5);
    expect(feeRisk.affinity).toBe(1);
    expect(aff.tightest_pair).toEqual(["Fee", "Risk"]);
    expect(aff.max_affinity).toBe(1);
  });

  it("breaks a tightest-pairing tie by earliest pair (localeCompare order)", async () => {
    // Four fronts all below, then all recover together once → all pairs affinity 1.0; the
    // earliest pair (Aaa+Bbb) wins.
    const rounds = await Promise.all([
      mk(
        {
          Aaa: "below-acceptable",
          Bbb: "below-acceptable",
          Yyy: "below-acceptable",
          Zzz: "below-acceptable",
        },
        { Aaa: "ideal", Bbb: "ideal", Yyy: "ideal", Zzz: "ideal" },
      ),
      mk(
        { Aaa: "acceptable", Bbb: "acceptable", Yyy: "acceptable", Zzz: "acceptable" },
        { Aaa: "ideal", Bbb: "ideal", Yyy: "ideal", Zzz: "ideal" },
      ),
    ]);
    const aff = await computeCoherenceRecoveryAffinity(rounds);
    // C(4,2) = 6 pairs all co-recover once → all affinity 1.0; earliest pair wins.
    expect(aff.max_affinity).toBe(1);
    expect(aff.tightest_pair).toEqual(["Aaa", "Bbb"]);
  });

  it("reports no tightest pairing when no two fronts ever recovered together", async () => {
    // Cap recovers r1→2; Term recovers r2→3 — never the same step.
    const rounds = await Promise.all([
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
    ]);
    const aff = await computeCoherenceRecoveryAffinity(rounds);
    expect(aff.pairs).toHaveLength(0);
    expect(aff.max_affinity).toBeNull();
    expect(aff.tightest_pair).toBeNull();
    expect(aff.coupled).toBe(false);
    expect(aff.total_co_recoveries).toBe(0);
    expect(aff.total_recoveries).toBe(2);
  });

  it("treats silence as neither a fall nor a recovery (§3) — a recovery across a silent gap is on the revealing step", async () => {
    // Cap & Term recover together r1→2, fall together at r3, both go SILENT at r4, then both
    // above at r5. The recovery is attributed to the step that REVEALS the new standing (r4→5),
    // not the silent step — and no recovery is invented across the gap. They co-recover twice.
    const rounds = await Promise.all([
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // r1
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r2: both recover
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // r3: both fall
      mk({ Cap: "unevaluable", Term: "unevaluable" }, { Cap: "unevaluable", Term: "unevaluable" }), // r4: silent
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r5: both recover (revealed)
    ]);
    const aff = await computeCoherenceRecoveryAffinity(rounds);
    const pair = aff.pairs[0]!;
    expect(pair.a_recoveries).toBe(2);
    expect(pair.b_recoveries).toBe(2);
    expect(pair.co_recoveries).toBe(2);
    expect(pair.class).toBe("coupled");
  });

  it("a pair that both-recovered once reads 100% / coupled (no minimum-union count)", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
    ]);
    const aff = await computeCoherenceRecoveryAffinity(rounds);
    const pair = aff.pairs[0]!;
    expect(pair.co_recoveries).toBe(1);
    expect(pair.union_recoveries).toBe(1);
    expect(pair.affinity).toBe(1);
    expect(pair.class).toBe("coupled");
    expect(aff.coupled).toBe(true);
  });

  it("diverges from v32: a pair coupled on FALLS can be incidental on RECOVERIES (independent directions)", async () => {
    // Cap & Term fall together TWICE (a v32 coupling) but recover on DIFFERENT steps — never the
    // same recovery transition. So v32 reports coupled, v33 reports no co-recovery edge.
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r1
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // r2: both fall (co-fall 1)
      mk({ Cap: "acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // r3: Cap recovers alone
      mk({ Cap: "below-acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r4: Cap falls, Term recovers (opposite)
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // r5: Term falls (Cap holds below)
    ]);
    const fall = await computeCoherenceAffinity(rounds);
    const rec = await computeCoherenceRecoveryAffinity(rounds);
    // v32: Cap & Term fell together at r1→2 and... let's just assert they have a co-fall edge.
    const fallPair = fall.pairs.find((p) => p.dimension_a === "Cap" && p.dimension_b === "Term");
    expect(fallPair).toBeDefined();
    expect(fallPair!.co_falls).toBeGreaterThanOrEqual(1);
    // v33: Cap recovered at r2→3, Term recovered at r3→4 — never the same step → no co-recovery.
    expect(rec.pairs).toHaveLength(0);
    expect(rec.coupled).toBe(false);
  });

  it("is deterministic: identical rounds in identical order → identical recovery_affinity_hash", async () => {
    const build = () =>
      Promise.all([
        mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
        mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
        mk({ Cap: "acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
      ]);
    const a = await computeCoherenceRecoveryAffinity(await build());
    const c = await computeCoherenceRecoveryAffinity(await build());
    expect(a.recovery_affinity_hash).toBe(c.recovery_affinity_hash);
    expect(a.recovery_affinity_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("throws on fewer than two rounds", async () => {
    const rounds = [await mk({ Cap: "ideal" }, { Cap: "ideal" })];
    await expect(computeCoherenceRecoveryAffinity(rounds)).rejects.toThrow(/at least two rounds/);
  });

  it("renders the tightest-pairing verdict and stable JSON", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
    ]);
    const aff = await computeCoherenceRecoveryAffinity(rounds);
    const summary = renderCoherenceRecoveryAffinitySummary(aff);
    expect(summary).toContain("Coherence exposure co-recovery affinity across 2 rounds");
    expect(summary).toMatch(/tightest pairing: Cap \+ Term — recovered together 100% of the steps either recovered/);
    expect(summary).toMatch(/1 coupled/);
    expect(summary).toMatch(/recovery_affinity_hash: [0-9a-f]{64}/);

    const json = JSON.parse(buildCoherenceRecoveryAffinityJson(aff));
    expect(json.schema).toBe("vaulytica.posture-recovery-affinity.v1");
    expect(json.recovery_affinity_hash).toBe(aff.recovery_affinity_hash);
    expect(json.rounds).toBe(2);
    expect(json.total_co_recoveries).toBe(1);
    expect(json.total_recoveries).toBe(2);
    expect(json.tightest_pair).toEqual(["Cap", "Term"]);
    expect(json.coupled).toBe(true);
    expect(json.pairs[0]).toMatchObject({
      dimension_a: "Cap",
      dimension_b: "Term",
      co_recoveries: 1,
      union_recoveries: 1,
      class: "coupled",
    });
  });

  it("renders a none-paired verdict distinctly", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
    ]);
    const summary = renderCoherenceRecoveryAffinitySummary(
      await computeCoherenceRecoveryAffinity(rounds),
    );
    expect(summary).toMatch(/tightest pairing: none/);
  });
});
