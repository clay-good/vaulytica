import { describe, expect, it } from "vitest";
import { compareCoherenceExposureArtifacts } from "./coherence-exposure.js";
import {
  bundlePostureCoherence,
  buildPostureCoherenceJson,
  type CoherenceInput,
} from "../../src/report/posture-coherence.js";
import {
  compareCoherenceExposure,
  exposureBreached,
  buildCoherenceExposureJson,
} from "../../src/report/coherence-exposure.js";
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

describe("compareCoherenceExposureArtifacts (spec-v20 — document-free posture exposure)", () => {
  it("walks N artifacts and matches the in-memory compareCoherenceExposure byte-for-byte", async () => {
    const c1 = await round("ideal", "ideal");
    const c2 = await round("ideal", "below-acceptable");
    const c3 = await round("acceptable", "acceptable");
    const outcome = await compareCoherenceExposureArtifacts(
      [c1, c2, c3].map((c) => buildPostureCoherenceJson(c, LADDER_A)),
      "json",
    );
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    const inMemory = buildCoherenceExposureJson(await compareCoherenceExposure([c1, c2, c3]));
    expect(outcome.output).toBe(inMemory);
    expect(outcome.breached).toBe(true); // Cap hit below-acceptable in round 2
    expect(outcome.ladderNote).toBeNull(); // all pinned + equal → verified
  });

  it("renders a human-readable summary by default", async () => {
    const outcome = await compareCoherenceExposureArtifacts([
      buildPostureCoherenceJson(await round("ideal", "ideal"), LADDER_A),
      buildPostureCoherenceJson(await round("ideal", "below-acceptable"), LADDER_A),
    ]);
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.output).toContain("Coherence exposure across 2 rounds (worst binding floor)");
    expect(outcome.output).toMatch(/Cap: worst below floor, first at round 2/);
    expect(outcome.output).toMatch(/exposure_hash: [0-9a-f]{64}/);
  });

  it("does not breach when no front ever falls below the acceptable floor", async () => {
    const outcome = await compareCoherenceExposureArtifacts([
      buildPostureCoherenceJson(await round("ideal", "acceptable"), LADDER_A),
      buildPostureCoherenceJson(await round("acceptable", "ideal"), LADDER_A),
    ]);
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.breached).toBe(false); // Cap worst is acceptable; Law ideal
  });

  it("breaches on a front pinned below floor for the whole deal (a movement command's blind spot)", async () => {
    const outcome = await compareCoherenceExposureArtifacts([
      buildPostureCoherenceJson(await round("below-acceptable", "below-acceptable"), LADDER_A),
      buildPostureCoherenceJson(await round("below-acceptable", "below-acceptable"), LADDER_A),
    ]);
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.breached).toBe(true);
  });

  it("requires at least two artifacts", async () => {
    const outcome = await compareCoherenceExposureArtifacts([
      buildPostureCoherenceJson(await round("ideal", "ideal"), LADDER_A),
    ]);
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.errors.join(" ")).toMatch(/at least two/);
  });

  it("refuses the sequence when any two rounds are pinned to different ladders (naming both)", async () => {
    const outcome = await compareCoherenceExposureArtifacts([
      buildPostureCoherenceJson(await round("ideal", "ideal"), LADDER_A),
      buildPostureCoherenceJson(await round("ideal", "ideal"), LADDER_A),
      buildPostureCoherenceJson(await round("ideal", "below-acceptable"), LADDER_B),
    ]);
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.errors.join(" ")).toMatch(/ladder mismatch/);
    expect(outcome.errors.join(" ")).toMatch(/round 1 and round 3/);
  });

  it("proceeds with a note when any artifact is unpinned (v1)", async () => {
    const outcome = await compareCoherenceExposureArtifacts([
      buildPostureCoherenceJson(await round("ideal", "ideal")), // v1, no ladder pin
      buildPostureCoherenceJson(await round("ideal", "below-acceptable"), LADDER_A),
    ]);
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.ladderNote).toMatch(/cross-ladder verification unavailable/);
  });

  it("rejects a tampered artifact, prefixing the offending round (1-indexed)", async () => {
    const c2 = await round("ideal", "ideal");
    const json = JSON.parse(buildPostureCoherenceJson(c2, LADDER_A));
    json.dimensions[0].tiers[0].tier = "below-acceptable"; // mutate without recomputing coherence_hash
    const outcome = await compareCoherenceExposureArtifacts([
      buildPostureCoherenceJson(await round("ideal", "below-acceptable"), LADDER_A),
      JSON.stringify(json),
    ]);
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.errors.some((e) => e.startsWith("round 2:"))).toBe(true);
    expect(outcome.errors.join(" ")).toMatch(/coherence_hash mismatch/);
  });

  it("the breach verdict matches exposureBreached on the same exposure", async () => {
    const c1 = await round("ideal", "ideal");
    const c2 = await round("ideal", "below-acceptable");
    const outcome = await compareCoherenceExposureArtifacts(
      [c1, c2].map((c) => buildPostureCoherenceJson(c, LADDER_A)),
      "json",
    );
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.breached).toBe(exposureBreached(await compareCoherenceExposure([c1, c2])));
  });
});
