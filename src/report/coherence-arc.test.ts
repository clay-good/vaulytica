import { describe, expect, it } from "vitest";
import {
  compareCoherenceArc,
  arcRegressedOrFractured,
  buildCoherenceArcJson,
  renderCoherenceArcSummary,
} from "./coherence-arc.js";
import { compareCoherenceTrajectory, trajectoryRegressed } from "./coherence-trajectory.js";
import {
  compareCoherenceShiftTrajectory,
  shiftTrajectoryFractured,
} from "./coherence-shift-trajectory.js";
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

/**
 * A round whose `Cap` floor is the weaker of the two docs' tiers, and whose `Cap`
 * coherence is `aligned` when both agree and `divergent` when they disagree.
 * `Law` is held aligned at ideal throughout (stable on both axes, never reported).
 */
const round = (capA: NegotiationTier, capB: NegotiationTier) =>
  bundlePostureCoherence(
    bundle(["msa.docx", { Cap: capA, Law: "ideal" }], ["order.docx", { Cap: capB, Law: "ideal" }]),
  );

const aligned = () => round("ideal", "ideal"); // floor ideal, aligned
const divergent = () => round("ideal", "acceptable"); // floor acceptable, divergent

describe("compareCoherenceArc (spec-v19 — document-free combined posture arc)", () => {
  it("joins the v17 floor trajectory and the v18 shift trajectory front-for-front", async () => {
    // Cap: aligned(ideal) → divergent(acceptable) → aligned(ideal). On the floor
    // axis this whipsaws (ideal → acceptable → ideal); on the shift axis it
    // oscillates (aligned → divergent → aligned).
    const rounds = await Promise.all([aligned(), divergent(), aligned()]);
    const arc = await compareCoherenceArc(rounds);

    const floor = await compareCoherenceTrajectory(rounds);
    const shift = await compareCoherenceShiftTrajectory(rounds);

    expect(arc.rounds).toBe(3);
    const cap = arc.fronts.find((f) => f.dimension === "Cap")!;
    // floor axis carried verbatim from v17
    expect(cap.floors).toEqual(floor.fronts.find((f) => f.dimension === "Cap")!.floors);
    expect(cap.trajectory).toBe("whipsaw");
    // shift axis carried verbatim from v18
    expect(cap.shifts).toEqual(shift.fronts.find((f) => f.dimension === "Cap")!.shifts);
    expect(cap.shift_trajectory).toBe("oscillating");
    // the shared coherence sequence appears once
    expect(cap.coherences).toEqual(["aligned", "divergent", "aligned"]);
    // component fingerprints carried verbatim; arc_hash is its own namespace
    expect(arc.trajectory_hash).toBe(floor.trajectory_hash);
    expect(arc.shift_trajectory_hash).toBe(shift.shift_trajectory_hash);
    expect(arc.arc_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(arc.arc_hash).not.toBe(arc.trajectory_hash);
    expect(arc.arc_hash).not.toBe(arc.shift_trajectory_hash);
  });

  it("the combined gate equals trajectoryRegressed OR shiftTrajectoryFractured", async () => {
    const rounds = await Promise.all([aligned(), divergent(), aligned()]);
    const arc = await compareCoherenceArc(rounds);
    const floor = await compareCoherenceTrajectory(rounds);
    const shift = await compareCoherenceShiftTrajectory(rounds);
    expect(arcRegressedOrFractured(arc)).toBe(
      trajectoryRegressed(floor) || shiftTrajectoryFractured(shift),
    );
    // a whipsaw floor and an oscillating shift both trip → gate is true
    expect(arcRegressedOrFractured(arc)).toBe(true);
  });

  it("trips on a floor regression even when the coherence never fractures", async () => {
    // Both docs erode together: floor ideal → acceptable, but they stay aligned
    // every round (same tier on both sides). Floor regresses; coherence stable.
    const r1 = await round("ideal", "ideal");
    const r2 = await round("acceptable", "acceptable");
    const arc = await compareCoherenceArc([r1, r2]);
    const cap = arc.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.trajectory).toBe("steady-regression");
    expect(cap.shift_trajectory).toBe("stable"); // aligned → aligned, never split
    expect(arcRegressedOrFractured(arc)).toBe(true); // floor axis alone trips it
  });

  it("trips on a fracture even when the binding floor holds steady", async () => {
    // Floor held at acceptable both rounds (the weaker doc never moves), but the
    // package fractures: round 1 both at acceptable (aligned), round 2 one at
    // ideal one at acceptable (still floor acceptable, now divergent).
    const r1 = await round("acceptable", "acceptable");
    const r2 = await round("ideal", "acceptable");
    const arc = await compareCoherenceArc([r1, r2]);
    const cap = arc.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.floors).toEqual(["acceptable", "acceptable"]);
    expect(cap.trajectory).toBe("flat"); // floor never moved
    expect(cap.shift_trajectory).toBe("steady-fracture");
    expect(arcRegressedOrFractured(arc)).toBe(true); // shift axis alone trips it
  });

  it("does not trip when both axes are quiet (steady improvement, steady reconcile)", async () => {
    // Cap: divergent(acceptable) → aligned(ideal). Floor improves; package reconciles.
    const r1 = await divergent();
    const r2 = await aligned();
    const arc = await compareCoherenceArc([r1, r2]);
    const cap = arc.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.trajectory).toBe("steady-improvement");
    expect(cap.shift_trajectory).toBe("steady-reconcile");
    expect(arcRegressedOrFractured(arc)).toBe(false);
  });

  it("is deterministic: identical rounds in identical order → identical arc_hash", async () => {
    const mk = () => Promise.all([aligned(), divergent(), aligned()]);
    const a = await compareCoherenceArc(await mk());
    const b = await compareCoherenceArc(await mk());
    expect(a.arc_hash).toBe(b.arc_hash);
  });

  it("throws on fewer than two rounds (delegated to the component functions)", async () => {
    const rounds = [await aligned()];
    await expect(compareCoherenceArc(rounds)).rejects.toThrow(/at least two rounds/);
  });

  it("renders a human-readable summary and stable JSON carrying all three hashes", async () => {
    const rounds = await Promise.all([aligned(), divergent(), aligned()]);
    const arc = await compareCoherenceArc(rounds);
    const summary = renderCoherenceArcSummary(arc);
    expect(summary).toContain("Coherence arc across 3 rounds (floor + shift)");
    expect(summary).toMatch(/Cap: floor whipsaw .*coherence oscillating/);
    expect(summary).toMatch(/arc_hash: [0-9a-f]{64}/);
    expect(summary).toMatch(/trajectory_hash: [0-9a-f]{64}/);
    expect(summary).toMatch(/shift_trajectory_hash: [0-9a-f]{64}/);

    const json = JSON.parse(buildCoherenceArcJson(arc));
    expect(json.schema).toBe("vaulytica.posture-arc.v1");
    expect(json.arc_hash).toBe(arc.arc_hash);
    expect(json.trajectory_hash).toBe(arc.trajectory_hash);
    expect(json.shift_trajectory_hash).toBe(arc.shift_trajectory_hash);
    expect(json.rounds).toBe(3);
    const capJson = json.fronts.find((f: { dimension: string }) => f.dimension === "Cap");
    expect(capJson.trajectory).toBe("whipsaw");
    expect(capJson.shift_trajectory).toBe("oscillating");
  });

  it("omits a front that is flat on the floor and stable on the shift from the summary", async () => {
    const rounds = await Promise.all([aligned(), divergent(), aligned()]);
    const arc = await compareCoherenceArc(rounds);
    const summary = renderCoherenceArcSummary(arc);
    // Law held aligned at ideal throughout → flat + stable → not listed
    expect(summary).not.toMatch(/Law:/);
  });
});
