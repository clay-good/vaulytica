import { describe, it, expect } from "vitest";
import {
  bundlePostureCoherence,
  type CoherenceInput,
} from "./posture-coherence.js";
import {
  compareCoherence,
  coherenceRegressed,
  type CoherenceFrontMovement,
} from "./coherence-movement.js";
import type { NegotiationPosture, NegotiationTier } from "../playbooks/custom-interpreter.js";

/** Build a minimal posture from a `{ dimension: tier }` map (only the fields the engine reads). */
function posture(map: Record<string, NegotiationTier>): NegotiationPosture {
  const positions = Object.entries(map).map(([dimension, tier]) => ({ dimension, tier }));
  return {
    positions,
    counts: { ideal: 0, acceptable: 0, below_acceptable: 0, unevaluable: 0 },
    posture_hash: "test",
  };
}

/** A bundle from a list of `[label, { dimension: tier }]` documents. */
function bundle(...docs: Array<[string, Record<string, NegotiationTier>]>): CoherenceInput[] {
  return docs.map(([document, map]) => ({ document, posture: posture(map) }));
}

/** Coherence of a one-front (`Cap`) bundle from a list of per-document tiers. */
async function coherenceOfCap(...tiers: NegotiationTier[]) {
  return bundlePostureCoherence(
    bundle(...tiers.map((t, i): [string, Record<string, NegotiationTier>] => [`doc${i}`, { Cap: t }])),
  );
}

/** The single `Cap` front of a movement between a base and revised set of per-doc tiers. */
async function capMovement(
  baseTiers: NegotiationTier[],
  revisedTiers: NegotiationTier[],
): Promise<CoherenceFrontMovement> {
  const m = await compareCoherence(
    await coherenceOfCap(...baseTiers),
    await coherenceOfCap(...revisedTiers),
  );
  return m.fronts.find((f) => f.dimension === "Cap")!;
}

describe("compareCoherence — binding-floor movement", () => {
  it("improves when the bundle's weakest stated rung rises", async () => {
    // base floor below-acceptable (Order), revised floor acceptable (Order).
    const f = await capMovement(["ideal", "below-acceptable"], ["ideal", "acceptable"]);
    expect(f.base_floor).toBe("below-acceptable");
    expect(f.revised_floor).toBe("acceptable");
    expect(f.floor_movement).toBe("improved");
  });

  it("regresses when the bundle's weakest stated rung falls", async () => {
    const f = await capMovement(["ideal", "acceptable"], ["ideal", "below-acceptable"]);
    expect(f.floor_movement).toBe("regressed");
  });

  it("is unchanged when the floor holds, even if a non-floor document moved", async () => {
    // weakest stays below-acceptable on both sides; the ideal doc dropping to
    // acceptable does not change the binding floor.
    const f = await capMovement(["ideal", "below-acceptable"], ["acceptable", "below-acceptable"]);
    expect(f.floor_movement).toBe("unchanged");
  });

  it("is newly-stated when a front goes from no stated floor to a stated one", async () => {
    const f = await capMovement(["unevaluable", "unevaluable"], ["ideal", "acceptable"]);
    expect(f.base_floor).toBeNull();
    expect(f.revised_floor).toBe("acceptable");
    expect(f.floor_movement).toBe("newly-stated");
  });

  it("is now-unstated when a stated front drops off the ladder entirely", async () => {
    const f = await capMovement(["ideal", "acceptable"], ["unevaluable", "unevaluable"]);
    expect(f.floor_movement).toBe("now-unstated");
  });

  it("never ranks an unstated→unstated front (stays unchanged)", async () => {
    const f = await capMovement(["unevaluable", "unevaluable"], ["unevaluable", "unevaluable"]);
    expect(f.floor_movement).toBe("unchanged");
    expect(f.base_floor).toBeNull();
    expect(f.revised_floor).toBeNull();
  });
});

describe("compareCoherence — coherence-kind shift", () => {
  it("fractures when a non-divergent front becomes divergent", async () => {
    const f = await capMovement(["ideal", "ideal"], ["ideal", "below-acceptable"]);
    expect(f.base_coherence).toBe("aligned");
    expect(f.revised_coherence).toBe("divergent");
    expect(f.coherence_shift).toBe("fractured");
  });

  it("reconciles when a divergent front stops diverging", async () => {
    const f = await capMovement(["ideal", "below-acceptable"], ["ideal", "ideal"]);
    expect(f.base_coherence).toBe("divergent");
    expect(f.revised_coherence).toBe("aligned");
    expect(f.coherence_shift).toBe("reconciled");
  });

  it("realigns when the stating set changes without crossing divergence (single → aligned)", async () => {
    const f = await capMovement(["ideal", "unevaluable"], ["ideal", "ideal"]);
    expect(f.base_coherence).toBe("single");
    expect(f.revised_coherence).toBe("aligned");
    expect(f.coherence_shift).toBe("realigned");
  });

  it("is unchanged when the coherence kind holds", async () => {
    const f = await capMovement(["ideal", "below-acceptable"], ["acceptable", "below-acceptable"]);
    expect(f.base_coherence).toBe("divergent");
    expect(f.revised_coherence).toBe("divergent");
    expect(f.coherence_shift).toBe("unchanged");
  });
});

describe("compareCoherence — structure, counts & determinism", () => {
  it("matches fronts by dimension across renamed/added documents, sorts by label, tallies counts", async () => {
    // Round 1: two documents. Round 2: three documents with different names —
    // matching is by dimension (the front), never by document label.
    const base = await bundlePostureCoherence(
      bundle(
        ["msa-v1", { Liability: "ideal", Governing: "ideal" }],
        ["order-v1", { Liability: "below-acceptable", Governing: "ideal" }],
      ),
    );
    const revised = await bundlePostureCoherence(
      bundle(
        ["msa-v2", { Liability: "acceptable", Governing: "ideal" }],
        ["order-v2", { Liability: "acceptable", Governing: "ideal" }],
        ["dpa-v2", { Liability: "acceptable", Governing: "ideal" }],
      ),
    );
    const m = await compareCoherence(base, revised);
    expect(m.fronts.map((f) => f.dimension)).toEqual(["Governing", "Liability"]);
    const liability = m.fronts.find((f) => f.dimension === "Liability")!;
    expect(liability.floor_movement).toBe("improved"); // below-acceptable → acceptable
    expect(liability.coherence_shift).toBe("reconciled"); // divergent → aligned
    const governing = m.fronts.find((f) => f.dimension === "Governing")!;
    expect(governing.floor_movement).toBe("unchanged");
    expect(m.floor_counts.improved).toBe(1);
    expect(m.floor_counts.unchanged).toBe(1);
    expect(m.shift_counts.reconciled).toBe(1);
    expect(m.shift_counts.unchanged).toBe(1);
  });

  it("is deterministic — same two coherences → identical movement_hash", async () => {
    const base = await coherenceOfCap("ideal", "below-acceptable");
    const revised = await coherenceOfCap("ideal", "acceptable");
    const a = await compareCoherence(base, revised);
    const b = await compareCoherence(base, revised);
    expect(a.movement_hash).toBe(b.movement_hash);
    expect(a.movement_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("is direction-sensitive — swapping base and revised yields a different artifact", async () => {
    const x = await coherenceOfCap("ideal", "below-acceptable");
    const y = await coherenceOfCap("ideal", "acceptable");
    const forward = await compareCoherence(x, y);
    const backward = await compareCoherence(y, x);
    expect(forward.movement_hash).not.toBe(backward.movement_hash);
    expect(forward.fronts[0]!.floor_movement).toBe("improved");
    expect(backward.fronts[0]!.floor_movement).toBe("regressed");
  });
});

describe("coherenceRegressed — the CI gate predicate", () => {
  it("trips when any front's binding floor moved to a strictly worse rung", async () => {
    const m = await compareCoherence(
      await coherenceOfCap("ideal", "acceptable"),
      await coherenceOfCap("ideal", "below-acceptable"),
    );
    expect(coherenceRegressed(m)).toBe(true);
  });

  it("does not trip on an improvement, a hold, or a dropped (now-unstated) front", async () => {
    const improved = await compareCoherence(
      await coherenceOfCap("ideal", "below-acceptable"),
      await coherenceOfCap("ideal", "acceptable"),
    );
    expect(coherenceRegressed(improved)).toBe(false);

    const dropped = await compareCoherence(
      await coherenceOfCap("ideal", "acceptable"),
      await coherenceOfCap("unevaluable", "unevaluable"),
    );
    // a front that fell off the ladder is `now-unstated`, never a rung regression.
    expect(dropped.fronts[0]!.floor_movement).toBe("now-unstated");
    expect(coherenceRegressed(dropped)).toBe(false);
  });
});
