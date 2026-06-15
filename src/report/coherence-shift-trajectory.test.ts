import { describe, expect, it } from "vitest";
import {
  compareCoherenceShiftTrajectory,
  shiftTrajectoryFractured,
  buildCoherenceShiftTrajectoryJson,
  renderCoherenceShiftTrajectorySummary,
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
 * A round whose `Cap` coherence is set by whether the two docs agree:
 * `(ideal, ideal)` → aligned; `(ideal, acceptable)` → divergent. `Law` is held
 * aligned at ideal throughout, so it is `stable` and never reported.
 */
const round = (capA: NegotiationTier, capB: NegotiationTier) =>
  bundlePostureCoherence(bundle(["msa.docx", { Cap: capA, Law: "ideal" }], ["order.docx", { Cap: capB, Law: "ideal" }]));

const aligned = () => round("ideal", "ideal");
const divergent = () => round("ideal", "acceptable");

describe("compareCoherenceShiftTrajectory (spec-v18 — document-free coherence-shift trajectory)", () => {
  it("classifies an oscillation: package splits mid-deal then re-merges", async () => {
    // Cap coherence: aligned → divergent → aligned → aligned.
    const rounds = await Promise.all([aligned(), divergent(), aligned(), aligned()]);
    const t = await compareCoherenceShiftTrajectory(rounds);
    expect(t.rounds).toBe(4);
    const cap = t.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.coherences).toEqual(["aligned", "divergent", "aligned", "aligned"]);
    expect(cap.shifts).toEqual(["fractured", "reconciled", "unchanged"]);
    expect(cap.shift_trajectory).toBe("oscillating");
    // Net (first → last) reads as unchanged and hides the mid-deal fracture…
    expect(cap.net_shift).toBe("unchanged");
    // …but the fracture gate still trips, because the package fractured at a step.
    expect(shiftTrajectoryFractured(t)).toBe(true);
    // Law held aligned throughout.
    expect(t.fronts.find((f) => f.dimension === "Law")!.shift_trajectory).toBe("stable");
  });

  it("classifies a steady fracture (no step reconciled) and trips the gate", async () => {
    const rounds = await Promise.all([aligned(), divergent(), divergent()]);
    const t = await compareCoherenceShiftTrajectory(rounds);
    const cap = t.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.shifts).toEqual(["fractured", "unchanged"]);
    expect(cap.shift_trajectory).toBe("steady-fracture");
    expect(cap.net_shift).toBe("fractured");
    expect(shiftTrajectoryFractured(t)).toBe(true);
  });

  it("classifies a steady reconcile and does not trip the gate", async () => {
    const rounds = await Promise.all([divergent(), aligned(), aligned()]);
    const t = await compareCoherenceShiftTrajectory(rounds);
    const cap = t.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.shift_trajectory).toBe("steady-reconcile");
    expect(cap.net_shift).toBe("reconciled");
    expect(shiftTrajectoryFractured(t)).toBe(false);
  });

  it("treats a realign-only front as stable, never an oscillation (§3 honesty)", async () => {
    // `Term`: stated by one doc (single) → both docs same tier (aligned) → one
    // doc (single). The stating set changed but never crossed the divergence
    // line, so every step is `realigned` and the trajectory is stable.
    const r1 = await bundlePostureCoherence(bundle(["a.docx", { Term: "acceptable" }], ["b.docx", { Cap: "ideal" }]));
    const r2 = await bundlePostureCoherence(bundle(["a.docx", { Term: "acceptable" }], ["b.docx", { Term: "acceptable" }]));
    const r3 = await bundlePostureCoherence(bundle(["a.docx", { Term: "acceptable" }], ["b.docx", { Cap: "ideal" }]));
    const t = await compareCoherenceShiftTrajectory([r1, r2, r3]);
    const term = t.fronts.find((f) => f.dimension === "Term")!;
    expect(term.coherences).toEqual(["single", "aligned", "single"]);
    expect(term.shifts).toEqual(["realigned", "realigned"]);
    expect(term.shift_trajectory).toBe("stable");
    expect(shiftTrajectoryFractured(t)).toBe(false);
  });

  it("treats an appear-only front as stable (an absent side carries no shift)", async () => {
    const r1 = await bundlePostureCoherence(bundle(["a.docx", { Cap: "ideal" }], ["b.docx", { Cap: "ideal" }]));
    const r2 = await bundlePostureCoherence(
      bundle(["a.docx", { Cap: "ideal", Term: "acceptable" }], ["b.docx", { Cap: "ideal", Term: "acceptable" }]),
    );
    const t = await compareCoherenceShiftTrajectory([r1, r2]);
    const term = t.fronts.find((f) => f.dimension === "Term")!;
    expect(term.coherences).toEqual([null, "aligned"]);
    expect(term.shifts).toEqual(["unchanged"]);
    expect(term.shift_trajectory).toBe("stable");
  });

  it("is deterministic: identical rounds in identical order → identical shift_trajectory_hash", async () => {
    const mk = () => Promise.all([aligned(), divergent(), aligned()]);
    const a = await compareCoherenceShiftTrajectory(await mk());
    const b = await compareCoherenceShiftTrajectory(await mk());
    expect(a.shift_trajectory_hash).toBe(b.shift_trajectory_hash);
    expect(a.shift_trajectory_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("throws on fewer than two rounds", async () => {
    const rounds = [await aligned()];
    await expect(compareCoherenceShiftTrajectory(rounds)).rejects.toThrow(/at least two rounds/);
  });

  it("renders a human-readable summary and stable JSON", async () => {
    const rounds = await Promise.all([aligned(), divergent(), aligned()]);
    const t = await compareCoherenceShiftTrajectory(rounds);
    const summary = renderCoherenceShiftTrajectorySummary(t);
    expect(summary).toContain("Coherence-shift trajectory across 3 rounds");
    expect(summary).toMatch(/Cap: oscillating \(aligned → divergent → aligned\)/);
    expect(summary).toMatch(/shift_trajectory_hash: [0-9a-f]{64}/);
    const json = JSON.parse(buildCoherenceShiftTrajectoryJson(t));
    expect(json.schema).toBe("vaulytica.posture-shift-trajectory.v1");
    expect(json.shift_trajectory_hash).toBe(t.shift_trajectory_hash);
    expect(json.rounds).toBe(3);
  });
});
