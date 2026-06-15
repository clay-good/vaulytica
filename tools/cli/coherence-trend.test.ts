import { describe, expect, it } from "vitest";
import { compareCoherenceTrendArtifacts } from "./coherence-trend.js";
import {
  bundlePostureCoherence,
  buildPostureCoherenceJson,
  type CoherenceInput,
} from "../../src/report/posture-coherence.js";
import {
  compareCoherenceTrajectory,
  trajectoryRegressed,
  buildCoherenceTrajectoryJson,
} from "../../src/report/coherence-trajectory.js";
import type { NegotiationPosture, NegotiationTier } from "../../src/playbooks/custom-interpreter.js";

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

/** A round whose `Cap` binding floor is `cap`; `Law` held at ideal throughout. */
const round = (cap: NegotiationTier) =>
  bundlePostureCoherence(bundle(["msa.docx", { Cap: "ideal", Law: "ideal" }], ["order.docx", { Cap: cap, Law: "ideal" }]));

describe("compareCoherenceTrendArtifacts (spec-v17 — document-free coherence trajectory)", () => {
  it("walks N artifacts and matches the in-memory compareCoherenceTrajectory byte-for-byte", async () => {
    const c1 = await round("acceptable");
    const c2 = await round("below-acceptable");
    const c3 = await round("ideal");
    const outcome = await compareCoherenceTrendArtifacts(
      [c1, c2, c3].map((c) => buildPostureCoherenceJson(c, LADDER_A)),
      "json",
    );
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    const inMemory = buildCoherenceTrajectoryJson(await compareCoherenceTrajectory([c1, c2, c3]));
    expect(outcome.output).toBe(inMemory);
    expect(outcome.regressed).toBe(true); // a below-floor dip in round 2
    expect(outcome.ladderNote).toBeNull(); // all pinned + equal → verified
  });

  it("renders a human-readable summary by default", async () => {
    const outcome = await compareCoherenceTrendArtifacts([
      buildPostureCoherenceJson(await round("acceptable"), LADDER_A),
      buildPostureCoherenceJson(await round("below-acceptable"), LADDER_A),
      buildPostureCoherenceJson(await round("ideal"), LADDER_A),
    ]);
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.output).toContain("Coherence trajectory across 3 rounds");
    expect(outcome.output).toMatch(/Cap: whipsaw/);
    expect(outcome.output).toMatch(/trajectory_hash: [0-9a-f]{64}/);
  });

  it("reports no regression when the floor only ever improves", async () => {
    const outcome = await compareCoherenceTrendArtifacts([
      buildPostureCoherenceJson(await round("below-acceptable"), LADDER_A),
      buildPostureCoherenceJson(await round("acceptable"), LADDER_A),
      buildPostureCoherenceJson(await round("ideal"), LADDER_A),
    ]);
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.regressed).toBe(false);
  });

  it("requires at least two artifacts", async () => {
    const outcome = await compareCoherenceTrendArtifacts([
      buildPostureCoherenceJson(await round("ideal"), LADDER_A),
    ]);
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.errors.join(" ")).toMatch(/at least two/);
  });

  it("refuses the sequence when any two rounds are pinned to different ladders (naming both)", async () => {
    const outcome = await compareCoherenceTrendArtifacts([
      buildPostureCoherenceJson(await round("acceptable"), LADDER_A),
      buildPostureCoherenceJson(await round("acceptable"), LADDER_A),
      buildPostureCoherenceJson(await round("ideal"), LADDER_B), // round 3 on a different ladder
    ]);
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.errors.join(" ")).toMatch(/ladder mismatch/);
    expect(outcome.errors.join(" ")).toMatch(/round 1 and round 3/);
  });

  it("proceeds with a note when any artifact is unpinned (v1)", async () => {
    const outcome = await compareCoherenceTrendArtifacts([
      buildPostureCoherenceJson(await round("acceptable")), // v1, no ladder pin
      buildPostureCoherenceJson(await round("ideal"), LADDER_A),
    ]);
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.ladderNote).toMatch(/cross-ladder verification unavailable/);
  });

  it("rejects a tampered artifact, prefixing the offending round (1-indexed)", async () => {
    const c2 = await round("acceptable");
    const json = JSON.parse(buildPostureCoherenceJson(c2, LADDER_A));
    json.dimensions[0].tiers[0].tier = "below-acceptable"; // mutate without recomputing coherence_hash
    const outcome = await compareCoherenceTrendArtifacts([
      buildPostureCoherenceJson(await round("ideal"), LADDER_A),
      JSON.stringify(json),
    ]);
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.errors.some((e) => e.startsWith("round 2:"))).toBe(true);
    expect(outcome.errors.join(" ")).toMatch(/coherence_hash mismatch/);
  });

  it("the regression verdict matches trajectoryRegressed on the same trajectory", async () => {
    const c1 = await round("acceptable");
    const c2 = await round("below-acceptable");
    const c3 = await round("ideal");
    const outcome = await compareCoherenceTrendArtifacts(
      [c1, c2, c3].map((c) => buildPostureCoherenceJson(c, LADDER_A)),
      "json",
    );
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.regressed).toBe(trajectoryRegressed(await compareCoherenceTrajectory([c1, c2, c3])));
  });
});
