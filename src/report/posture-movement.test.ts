import { describe, it, expect } from "vitest";
import { comparePosture, type PostureMovementKind } from "./posture-movement.js";
import type {
  NegotiationPosture,
  NegotiationTier,
} from "../playbooks/custom-interpreter.js";

/** Build a minimal posture from a `{ dimension: tier }` map (only the fields comparePosture reads). */
function posture(map: Record<string, NegotiationTier>): NegotiationPosture {
  const positions = Object.entries(map).map(([dimension, tier]) => ({ dimension, tier }));
  return {
    positions,
    counts: { ideal: 0, acceptable: 0, below_acceptable: 0, unevaluable: 0 },
    posture_hash: "test",
  };
}

async function movementOf(
  base: NegotiationTier,
  revised: NegotiationTier,
): Promise<PostureMovementKind> {
  const pm = await comparePosture(posture({ Cap: base }), posture({ Cap: revised }));
  return pm.dimensions[0]!.movement;
}

describe("comparePosture — movement classification", () => {
  it("classifies a strictly-better rung as improved", async () => {
    expect(await movementOf("acceptable", "ideal")).toBe("improved");
    expect(await movementOf("below-acceptable", "acceptable")).toBe("improved");
    expect(await movementOf("below-acceptable", "ideal")).toBe("improved");
  });

  it("classifies a strictly-worse rung as regressed", async () => {
    expect(await movementOf("ideal", "acceptable")).toBe("regressed");
    expect(await movementOf("acceptable", "below-acceptable")).toBe("regressed");
    expect(await movementOf("ideal", "below-acceptable")).toBe("regressed");
  });

  it("classifies an identical rung as unchanged (including both unstated)", async () => {
    expect(await movementOf("ideal", "ideal")).toBe("unchanged");
    expect(await movementOf("below-acceptable", "below-acceptable")).toBe("unchanged");
    expect(await movementOf("unevaluable", "unevaluable")).toBe("unchanged");
  });

  it("does not rank unstated against a stated rung — it labels the transition honestly", async () => {
    // unevaluable → on the ladder: newly stated (NOT a false 'improved').
    expect(await movementOf("unevaluable", "below-acceptable")).toBe("newly-stated");
    expect(await movementOf("unevaluable", "ideal")).toBe("newly-stated");
    // on the ladder → unevaluable: no longer stated (NOT a false 'regressed').
    expect(await movementOf("ideal", "unevaluable")).toBe("now-unstated");
    expect(await movementOf("below-acceptable", "unevaluable")).toBe("now-unstated");
  });

  it("labels a dimension present in only one posture (defensive, different position sets)", async () => {
    const pm = await comparePosture(
      posture({ Cap: "ideal", Law: "acceptable" }),
      posture({ Cap: "ideal", Indemnity: "below-acceptable" }),
    );
    const byDim = Object.fromEntries(pm.dimensions.map((d) => [d.dimension, d.movement]));
    expect(byDim["Law"]).toBe("disappeared"); // base only
    expect(byDim["Indemnity"]).toBe("appeared"); // revised only
    expect(byDim["Cap"]).toBe("unchanged");
  });
});

describe("comparePosture — structure & determinism", () => {
  it("sorts dimensions by label and tallies counts", async () => {
    const pm = await comparePosture(
      posture({ Liability: "acceptable", Governing: "ideal", Indemnity: "unevaluable" }),
      posture({ Liability: "ideal", Governing: "acceptable", Indemnity: "below-acceptable" }),
    );
    expect(pm.dimensions.map((d) => d.dimension)).toEqual([
      "Governing",
      "Indemnity",
      "Liability",
    ]);
    expect(pm.counts.improved).toBe(1); // Liability
    expect(pm.counts.regressed).toBe(1); // Governing
    expect(pm.counts["newly-stated"]).toBe(1); // Indemnity
    expect(pm.counts.unchanged).toBe(0);
  });

  it("carries each transition's base and revised tier", async () => {
    const pm = await comparePosture(
      posture({ Cap: "acceptable" }),
      posture({ Cap: "ideal" }),
    );
    expect(pm.dimensions[0]).toMatchObject({
      dimension: "Cap",
      base_tier: "acceptable",
      revised_tier: "ideal",
      movement: "improved",
    });
  });

  it("is deterministic — same postures yield the same movement_hash, regardless of position order", async () => {
    const a = await comparePosture(
      posture({ Cap: "acceptable", Law: "ideal" }),
      posture({ Cap: "ideal", Law: "ideal" }),
    );
    const b = await comparePosture(
      posture({ Law: "ideal", Cap: "acceptable" }),
      posture({ Law: "ideal", Cap: "ideal" }),
    );
    expect(a.movement_hash).toBe(b.movement_hash);
    expect(a.movement_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("a different movement set yields a different hash", async () => {
    const a = await comparePosture(posture({ Cap: "acceptable" }), posture({ Cap: "ideal" }));
    const b = await comparePosture(posture({ Cap: "ideal" }), posture({ Cap: "acceptable" }));
    expect(a.movement_hash).not.toBe(b.movement_hash);
  });

  it("an empty pair of postures yields no movements and a stable hash", async () => {
    const pm = await comparePosture(posture({}), posture({}));
    expect(pm.dimensions).toEqual([]);
    expect(pm.movement_hash).toMatch(/^[0-9a-f]{64}$/);
  });
});
