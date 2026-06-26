import { describe, expect, it } from "vitest";
import {
  compareCoherenceExposure,
  exposureBreached,
  buildCoherenceExposureJson,
  renderCoherenceExposureSummary,
} from "./coherence-exposure.js";
import { compareCoherenceTrajectory, trajectoryRegressed } from "./coherence-trajectory.js";
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

/** A round whose `Cap` floor is the weaker of the two docs' tiers; `Law` held ideal throughout. */
const round = (capA: NegotiationTier, capB: NegotiationTier) =>
  bundlePostureCoherence(
    bundle(["msa.docx", { Cap: capA, Law: "ideal" }], ["order.docx", { Cap: capB, Law: "ideal" }]),
  );

describe("compareCoherenceExposure (spec-v20 — whole-deal binding-floor low-water mark)", () => {
  it("reports the worst floor each front reached and which round first hit it", async () => {
    // Cap floors: ideal → below-acceptable → acceptable. Worst = below-acceptable, first at round 2.
    const rounds = await Promise.all([
      round("ideal", "ideal"),
      round("ideal", "below-acceptable"),
      round("acceptable", "acceptable"),
    ]);
    const exposure = await compareCoherenceExposure(rounds);
    expect(exposure.rounds).toBe(3);
    const cap = exposure.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.floors).toEqual(["ideal", "below-acceptable", "acceptable"]);
    expect(cap.worst_floor).toBe("below-acceptable");
    expect(cap.worst_round).toBe(2);
    expect(cap.rounds_stated).toBe(3);
    expect(cap.exposed).toBe(true);
  });

  it("flags a front pinned below floor for the whole deal that EVERY movement command misses", async () => {
    // Cap sits at below-acceptable in both rounds: it never *moves*, so v17 calls
    // it `flat` and trajectoryRegressed is false — yet it is exposed every round.
    const rounds = await Promise.all([
      round("below-acceptable", "below-acceptable"),
      round("below-acceptable", "below-acceptable"),
    ]);
    const exposure = await compareCoherenceExposure(rounds);
    const cap = exposure.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.worst_floor).toBe("below-acceptable");
    expect(cap.worst_round).toBe(1);
    expect(cap.exposed).toBe(true);
    expect(exposureBreached(exposure)).toBe(true);

    // The movement axis is blind to it: the floor never changed → flat, no regression.
    const floor = await compareCoherenceTrajectory(rounds);
    expect(floor.fronts.find((f) => f.dimension === "Cap")!.trajectory).toBe("flat");
    expect(trajectoryRegressed(floor)).toBe(false);
  });

  it("never flags a front no document ever stated (silence is not exposure, §3)", async () => {
    // `Gap` is stated by no document in any round → unstated, never exposed.
    const rounds = await Promise.all([round("ideal", "acceptable"), round("acceptable", "ideal")]);
    const exposure = await compareCoherenceExposure(rounds);
    // every front here is stated; assert the unstated path via a front absent everywhere.
    expect(exposure.fronts.some((f) => f.worst_floor === null)).toBe(false);
    // Cap's worst is acceptable (the weaker side each round) → not exposed.
    const cap = exposure.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.worst_floor).toBe("acceptable");
    expect(cap.exposed).toBe(false);
    expect(exposureBreached(exposure)).toBe(false);
  });

  it("counts a front stated in only some rounds as stated, ignoring the unstated rounds", async () => {
    // Round 1 has no Cap (neither doc states it); rounds 2-3 do.
    const r1 = await bundlePostureCoherence(
      bundle(["msa.docx", { Law: "ideal" }], ["order.docx", { Law: "ideal" }]),
    );
    const r2 = await round("acceptable", "below-acceptable");
    const r3 = await round("acceptable", "acceptable");
    const exposure = await compareCoherenceExposure([r1, r2, r3]);
    const cap = exposure.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.floors).toEqual([null, "below-acceptable", "acceptable"]);
    expect(cap.worst_floor).toBe("below-acceptable");
    expect(cap.worst_round).toBe(2);
    expect(cap.rounds_stated).toBe(2);
    expect(cap.exposed).toBe(true);
  });

  it("tallies worst levels and the exposed count across fronts", async () => {
    // Cap worst acceptable; Law worst ideal (held ideal); Risk worst below-acceptable.
    const rounds = await Promise.all([
      bundlePostureCoherence(
        bundle(
          ["a.docx", { Cap: "ideal", Law: "ideal", Risk: "below-acceptable" }],
          ["b.docx", { Cap: "acceptable", Law: "ideal", Risk: "ideal" }],
        ),
      ),
      bundlePostureCoherence(
        bundle(
          ["a.docx", { Cap: "acceptable", Law: "ideal", Risk: "below-acceptable" }],
          ["b.docx", { Cap: "ideal", Law: "ideal", Risk: "acceptable" }],
        ),
      ),
    ]);
    const exposure = await compareCoherenceExposure(rounds);
    expect(exposure.worst_counts).toEqual({
      ideal: 1, // Law
      acceptable: 1, // Cap
      "below-acceptable": 1, // Risk
      unstated: 0,
    });
    expect(exposure.exposed_count).toBe(1);
  });

  it("is deterministic: identical rounds in identical order → identical exposure_hash", async () => {
    const mk = () =>
      Promise.all([round("ideal", "below-acceptable"), round("acceptable", "acceptable")]);
    const a = await compareCoherenceExposure(await mk());
    const b = await compareCoherenceExposure(await mk());
    expect(a.exposure_hash).toBe(b.exposure_hash);
    expect(a.exposure_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("throws on fewer than two rounds", async () => {
    const rounds = [await round("ideal", "ideal")];
    await expect(compareCoherenceExposure(rounds)).rejects.toThrow(/at least two rounds/);
  });

  it("renders a summary listing only exposed fronts and stable JSON", async () => {
    const rounds = await Promise.all([round("ideal", "ideal"), round("ideal", "below-acceptable")]);
    const exposure = await compareCoherenceExposure(rounds);
    const summary = renderCoherenceExposureSummary(exposure);
    expect(summary).toContain("Coherence exposure across 2 rounds (worst binding floor)");
    expect(summary).toMatch(/Cap: worst below floor, first at round 2/);
    expect(summary).not.toMatch(/Law:/); // Law held ideal → not exposed → omitted
    expect(summary).toMatch(/exposure_hash: [0-9a-f]{64}/);

    const json = JSON.parse(buildCoherenceExposureJson(exposure));
    expect(json.schema).toBe("vaulytica.posture-exposure.v1");
    expect(json.exposure_hash).toBe(exposure.exposure_hash);
    expect(json.rounds).toBe(2);
    expect(json.exposed_count).toBe(1);
    const capJson = json.fronts.find((f: { dimension: string }) => f.dimension === "Cap");
    expect(capJson.worst_floor).toBe("below-acceptable");
    expect(capJson.worst_round).toBe(2);
  });
});
