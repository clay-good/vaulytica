import { describe, expect, it } from "vitest";
import {
  compareCoherenceTrajectory,
  trajectoryRegressed,
  buildCoherenceTrajectoryJson,
  renderCoherenceTrajectorySummary,
} from "./coherence-trajectory.js";
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

/** A bundle whose binding floor on `Cap` is the weakest of two docs; `Law` held at ideal. */
const round = (cap: NegotiationTier) =>
  bundlePostureCoherence(
    bundle(
      ["msa.docx", { Cap: "ideal", Law: "ideal" }],
      ["order.docx", { Cap: cap, Law: "ideal" }],
    ),
  );

describe("compareCoherenceTrajectory (spec-v17 — document-free coherence trajectory)", () => {
  it("classifies a whipsaw: dip below floor mid-deal that recovers", async () => {
    // Cap floor: acceptable → below-acceptable → acceptable → ideal.
    const rounds = await Promise.all([
      round("acceptable"),
      round("below-acceptable"),
      round("acceptable"),
      round("ideal"),
    ]);
    const t = await compareCoherenceTrajectory(rounds);
    expect(t.rounds).toBe(4);
    const cap = t.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.floors).toEqual(["acceptable", "below-acceptable", "acceptable", "ideal"]);
    expect(cap.steps).toEqual(["regressed", "improved", "improved"]);
    expect(cap.trajectory).toBe("whipsaw");
    // Net (first → last) reads as an improvement and hides the mid-deal dip…
    expect(cap.net_floor_movement).toBe("improved");
    // …but the trajectory gate still trips, because the floor regressed at a step.
    expect(trajectoryRegressed(t)).toBe(true);
    // Law never moved.
    expect(t.fronts.find((f) => f.dimension === "Law")!.trajectory).toBe("flat");
  });

  it("classifies steady improvement (no step regressed) and does not trip the gate", async () => {
    const rounds = await Promise.all([
      round("below-acceptable"),
      round("acceptable"),
      round("ideal"),
    ]);
    const t = await compareCoherenceTrajectory(rounds);
    const cap = t.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.trajectory).toBe("steady-improvement");
    expect(cap.net_floor_movement).toBe("improved");
    expect(trajectoryRegressed(t)).toBe(false);
  });

  it("classifies steady regression and trips the gate", async () => {
    const rounds = await Promise.all([
      round("ideal"),
      round("acceptable"),
      round("below-acceptable"),
    ]);
    const t = await compareCoherenceTrajectory(rounds);
    const cap = t.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.trajectory).toBe("steady-regression");
    expect(cap.net_floor_movement).toBe("regressed");
    expect(trajectoryRegressed(t)).toBe(true);
  });

  it("treats an appear-only front as flat, never a whipsaw (§3 honesty)", async () => {
    // `Term` is unstated in round 1, stated in rounds 2 and 3 — newly-stated then
    // unchanged are not ranked movements, so the trajectory is flat.
    const r1 = await bundlePostureCoherence(bundle(["a.docx", { Cap: "ideal" }]));
    const r2 = await bundlePostureCoherence(
      bundle(["a.docx", { Cap: "ideal", Term: "acceptable" }]),
    );
    const r3 = await bundlePostureCoherence(
      bundle(["a.docx", { Cap: "ideal", Term: "acceptable" }]),
    );
    const t = await compareCoherenceTrajectory([r1, r2, r3]);
    const term = t.fronts.find((f) => f.dimension === "Term")!;
    expect(term.floors).toEqual([null, "acceptable", "acceptable"]);
    expect(term.steps).toEqual(["newly-stated", "unchanged"]);
    expect(term.trajectory).toBe("flat");
    expect(trajectoryRegressed(t)).toBe(false);
  });

  it("is deterministic: identical rounds in identical order → identical trajectory_hash", async () => {
    const mk = () => Promise.all([round("acceptable"), round("below-acceptable"), round("ideal")]);
    const a = await compareCoherenceTrajectory(await mk());
    const b = await compareCoherenceTrajectory(await mk());
    expect(a.trajectory_hash).toBe(b.trajectory_hash);
    expect(a.trajectory_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("throws on fewer than two rounds", async () => {
    const rounds = [await round("ideal")];
    await expect(compareCoherenceTrajectory(rounds)).rejects.toThrow(/at least two rounds/);
  });

  it("renders a human-readable summary and stable JSON", async () => {
    const rounds = await Promise.all([
      round("acceptable"),
      round("below-acceptable"),
      round("ideal"),
    ]);
    const t = await compareCoherenceTrajectory(rounds);
    const summary = renderCoherenceTrajectorySummary(t);
    expect(summary).toContain("Coherence trajectory across 3 rounds");
    expect(summary).toMatch(/Cap: whipsaw \(acceptable → below-acceptable → ideal\)/);
    expect(summary).toMatch(/trajectory_hash: [0-9a-f]{64}/);
    const json = JSON.parse(buildCoherenceTrajectoryJson(t));
    expect(json.schema).toBe("vaulytica.posture-trajectory.v1");
    expect(json.trajectory_hash).toBe(t.trajectory_hash);
    expect(json.rounds).toBe(3);
  });
});
