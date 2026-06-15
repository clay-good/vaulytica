import { describe, expect, it } from "vitest";
import { compareCoherenceArcArtifacts } from "./coherence-arc.js";
import {
  bundlePostureCoherence,
  buildPostureCoherenceJson,
  type CoherenceInput,
} from "../../src/report/posture-coherence.js";
import {
  compareCoherenceArc,
  arcRegressedOrFractured,
  buildCoherenceArcJson,
} from "../../src/report/coherence-arc.js";
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

const round = (capA: NegotiationTier, capB: NegotiationTier) =>
  bundlePostureCoherence(bundle(["msa.docx", { Cap: capA, Law: "ideal" }], ["order.docx", { Cap: capB, Law: "ideal" }]));

const aligned = () => round("ideal", "ideal");
const divergent = () => round("ideal", "acceptable");

describe("compareCoherenceArcArtifacts (spec-v19 — document-free combined posture arc)", () => {
  it("walks N artifacts and matches the in-memory compareCoherenceArc byte-for-byte", async () => {
    const c1 = await aligned();
    const c2 = await divergent();
    const c3 = await aligned();
    const outcome = await compareCoherenceArcArtifacts(
      [c1, c2, c3].map((c) => buildPostureCoherenceJson(c, LADDER_A)),
      "json",
    );
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    const inMemory = buildCoherenceArcJson(await compareCoherenceArc([c1, c2, c3]));
    expect(outcome.output).toBe(inMemory);
    expect(outcome.regressedOrFractured).toBe(true); // whipsaw floor + oscillating shift
    expect(outcome.ladderNote).toBeNull(); // all pinned + equal → verified
  });

  it("renders a human-readable summary by default with both axes", async () => {
    const outcome = await compareCoherenceArcArtifacts([
      buildPostureCoherenceJson(await aligned(), LADDER_A),
      buildPostureCoherenceJson(await divergent(), LADDER_A),
      buildPostureCoherenceJson(await aligned(), LADDER_A),
    ]);
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.output).toContain("Coherence arc across 3 rounds (floor + shift)");
    expect(outcome.output).toMatch(/Cap: floor whipsaw .*coherence oscillating/);
    expect(outcome.output).toMatch(/arc_hash: [0-9a-f]{64}/);
  });

  it("does not trip the combined gate when both axes are quiet", async () => {
    const outcome = await compareCoherenceArcArtifacts([
      buildPostureCoherenceJson(await divergent(), LADDER_A),
      buildPostureCoherenceJson(await aligned(), LADDER_A),
      buildPostureCoherenceJson(await aligned(), LADDER_A),
    ]);
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.regressedOrFractured).toBe(false); // steady improvement + steady reconcile
  });

  it("requires at least two artifacts", async () => {
    const outcome = await compareCoherenceArcArtifacts([
      buildPostureCoherenceJson(await aligned(), LADDER_A),
    ]);
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.errors.join(" ")).toMatch(/at least two/);
  });

  it("refuses the sequence when any two rounds are pinned to different ladders (naming both)", async () => {
    const outcome = await compareCoherenceArcArtifacts([
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
    const outcome = await compareCoherenceArcArtifacts([
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
    const outcome = await compareCoherenceArcArtifacts([
      buildPostureCoherenceJson(await divergent(), LADDER_A),
      JSON.stringify(json),
    ]);
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.errors.some((e) => e.startsWith("round 2:"))).toBe(true);
    expect(outcome.errors.join(" ")).toMatch(/coherence_hash mismatch/);
  });

  it("the combined verdict matches arcRegressedOrFractured on the same arc", async () => {
    const c1 = await aligned();
    const c2 = await divergent();
    const c3 = await aligned();
    const outcome = await compareCoherenceArcArtifacts(
      [c1, c2, c3].map((c) => buildPostureCoherenceJson(c, LADDER_A)),
      "json",
    );
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.regressedOrFractured).toBe(
      arcRegressedOrFractured(await compareCoherenceArc([c1, c2, c3])),
    );
  });
});
