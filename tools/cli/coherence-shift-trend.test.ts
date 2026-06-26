import { describe, expect, it } from "vitest";
import { compareCoherenceShiftTrendArtifacts } from "./coherence-shift-trend.js";
import {
  bundlePostureCoherence,
  buildPostureCoherenceJson,
  type CoherenceInput,
} from "../../src/report/posture-coherence.js";
import {
  compareCoherenceShiftTrajectory,
  shiftTrajectoryFractured,
  buildCoherenceShiftTrajectoryJson,
} from "../../src/report/coherence-shift-trajectory.js";
import type {
  NegotiationPosture,
  NegotiationTier,
} from "../../src/playbooks/custom-interpreter.js";

function posture(map: Record<string, NegotiationTier>): NegotiationPosture {
  return {
    positions: Object.entries(map).map(([dimension, tier]) => ({ dimension, tier })),
    counts: { ideal: 0, acceptable: 0, below_acceptable: 0, unevaluable: 0 },
    posture_hash: "test",
  };
}

const bundle = (...docs: Array<[string, Record<string, NegotiationTier>]>): CoherenceInput[] =>
  docs.map(([document, map]) => ({ document, posture: posture(map) }));

const LADDER_A = "a".repeat(64);
const LADDER_B = "b".repeat(64);

/** `Cap` is aligned when both docs agree, divergent when they disagree; `Law` aligned throughout. */
const round = (capA: NegotiationTier, capB: NegotiationTier) =>
  bundlePostureCoherence(
    bundle(["msa.docx", { Cap: capA, Law: "ideal" }], ["order.docx", { Cap: capB, Law: "ideal" }]),
  );

const aligned = () => round("ideal", "ideal");
const divergent = () => round("ideal", "acceptable");

describe("compareCoherenceShiftTrendArtifacts (spec-v18 — document-free coherence-shift trajectory)", () => {
  it("walks N artifacts and matches the in-memory compareCoherenceShiftTrajectory byte-for-byte", async () => {
    const c1 = await aligned();
    const c2 = await divergent();
    const c3 = await aligned();
    const outcome = await compareCoherenceShiftTrendArtifacts(
      [c1, c2, c3].map((c) => buildPostureCoherenceJson(c, LADDER_A)),
      "json",
    );
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    const inMemory = buildCoherenceShiftTrajectoryJson(
      await compareCoherenceShiftTrajectory([c1, c2, c3]),
    );
    expect(outcome.output).toBe(inMemory);
    expect(outcome.fractured).toBe(true); // a mid-deal fracture in round 2
    expect(outcome.ladderNote).toBeNull(); // all pinned + equal → verified
  });

  it("renders a human-readable summary by default", async () => {
    const outcome = await compareCoherenceShiftTrendArtifacts([
      buildPostureCoherenceJson(await aligned(), LADDER_A),
      buildPostureCoherenceJson(await divergent(), LADDER_A),
      buildPostureCoherenceJson(await aligned(), LADDER_A),
    ]);
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.output).toContain("Coherence-shift trajectory across 3 rounds");
    expect(outcome.output).toMatch(/Cap: oscillating/);
    expect(outcome.output).toMatch(/shift_trajectory_hash: [0-9a-f]{64}/);
  });

  it("reports no fracture when the package only ever reconciles", async () => {
    const outcome = await compareCoherenceShiftTrendArtifacts([
      buildPostureCoherenceJson(await divergent(), LADDER_A),
      buildPostureCoherenceJson(await aligned(), LADDER_A),
      buildPostureCoherenceJson(await aligned(), LADDER_A),
    ]);
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.fractured).toBe(false);
  });

  it("requires at least two artifacts", async () => {
    const outcome = await compareCoherenceShiftTrendArtifacts([
      buildPostureCoherenceJson(await aligned(), LADDER_A),
    ]);
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.errors.join(" ")).toMatch(/at least two/);
  });

  it("refuses the sequence when any two rounds are pinned to different ladders (naming both)", async () => {
    const outcome = await compareCoherenceShiftTrendArtifacts([
      buildPostureCoherenceJson(await aligned(), LADDER_A),
      buildPostureCoherenceJson(await aligned(), LADDER_A),
      buildPostureCoherenceJson(await divergent(), LADDER_B), // round 3 on a different ladder
    ]);
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.errors.join(" ")).toMatch(/ladder mismatch/);
    expect(outcome.errors.join(" ")).toMatch(/round 1 and round 3/);
  });

  it("proceeds with a note when any artifact is unpinned (v1)", async () => {
    const outcome = await compareCoherenceShiftTrendArtifacts([
      buildPostureCoherenceJson(await aligned()), // v1, no ladder pin
      buildPostureCoherenceJson(await divergent(), LADDER_A),
    ]);
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.ladderNote).toMatch(/cross-ladder verification unavailable/);
  });

  it("rejects a tampered artifact, prefixing the offending round (1-indexed)", async () => {
    const c2 = await aligned();
    const json = JSON.parse(buildPostureCoherenceJson(c2, LADDER_A));
    json.dimensions[0].tiers[0].tier = "below-acceptable"; // mutate without recomputing coherence_hash
    const outcome = await compareCoherenceShiftTrendArtifacts([
      buildPostureCoherenceJson(await divergent(), LADDER_A),
      JSON.stringify(json),
    ]);
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.errors.some((e) => e.startsWith("round 2:"))).toBe(true);
    expect(outcome.errors.join(" ")).toMatch(/coherence_hash mismatch/);
  });

  it("the fracture verdict matches shiftTrajectoryFractured on the same trajectory", async () => {
    const c1 = await aligned();
    const c2 = await divergent();
    const c3 = await aligned();
    const outcome = await compareCoherenceShiftTrendArtifacts(
      [c1, c2, c3].map((c) => buildPostureCoherenceJson(c, LADDER_A)),
      "json",
    );
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.fractured).toBe(
      shiftTrajectoryFractured(await compareCoherenceShiftTrajectory([c1, c2, c3])),
    );
  });
});
