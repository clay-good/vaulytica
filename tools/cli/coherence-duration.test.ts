import { describe, expect, it } from "vitest";
import { computeCoherenceDurationArtifacts } from "./coherence-duration.js";
import {
  bundlePostureCoherence,
  buildPostureCoherenceJson,
  type CoherenceInput,
} from "../../src/report/posture-coherence.js";
import {
  computeCoherenceDuration,
  exposureLingers,
  buildCoherenceDurationJson,
} from "../../src/report/coherence-duration.js";
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

const mk = (a: Record<string, NegotiationTier>, b: Record<string, NegotiationTier>) =>
  bundlePostureCoherence(bundle(["msa.docx", a], ["order.docx", b]));

/** Rounds in which Cap falls and stays below for three rounds before recovering → mean 3, lingering. */
const lingeringRounds = () =>
  Promise.all([
    mk({ Cap: "acceptable" }, { Cap: "ideal" }),
    mk({ Cap: "below-acceptable" }, { Cap: "ideal" }), // fall
    mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
    mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
    mk({ Cap: "acceptable" }, { Cap: "ideal" }), // recover (lat 3)
  ]);

describe("computeCoherenceDurationArtifacts (spec-v40 — document-free exposure duration)", () => {
  it("walks N artifacts and matches the in-memory computeCoherenceDuration byte-for-byte", async () => {
    const cs = await lingeringRounds();
    const outcome = await computeCoherenceDurationArtifacts(
      cs.map((c) => buildPostureCoherenceJson(c, LADDER_A)),
      "json",
    );
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    const inMemory = buildCoherenceDurationJson(await computeCoherenceDuration(cs));
    expect(outcome.output).toBe(inMemory);
    expect(outcome.lingering).toBe(true);
    expect(outcome.ladderNote).toBeNull();
  });

  it("renders a human-readable summary by default", async () => {
    const outcome = await computeCoherenceDurationArtifacts(
      (await lingeringRounds()).map((c) => buildPostureCoherenceJson(c, LADDER_A)),
    );
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.output).toContain("Coherence exposure duration across 5 rounds");
    expect(outcome.output).toMatch(/chronic lingerer: Cap/);
    expect(outcome.output).toMatch(/duration_hash: [0-9a-f]{64}/);
  });

  it("trips the gate when a front's recovered exposures average at least two rounds", async () => {
    const outcome = await computeCoherenceDurationArtifacts(
      (await lingeringRounds()).map((c) => buildPostureCoherenceJson(c, LADDER_A)),
    );
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.lingering).toBe(true);
    expect(outcome.output).toMatch(/lingering/);
  });

  it("clears the gate when a front always recovers within a round (mean < 2)", async () => {
    const outcome = await computeCoherenceDurationArtifacts([
      buildPostureCoherenceJson(await mk({ Cap: "acceptable" }, { Cap: "ideal" }), LADDER_A),
      buildPostureCoherenceJson(await mk({ Cap: "below-acceptable" }, { Cap: "ideal" }), LADDER_A), // fall
      buildPostureCoherenceJson(await mk({ Cap: "acceptable" }, { Cap: "ideal" }), LADDER_A), // recover (lat 1)
    ]);
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.lingering).toBe(false); // one-round recovery → brief
  });

  it("requires at least two artifacts", async () => {
    const outcome = await computeCoherenceDurationArtifacts([
      buildPostureCoherenceJson(await mk({ Cap: "ideal" }, { Cap: "ideal" }), LADDER_A),
    ]);
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.errors.join(" ")).toMatch(/at least two/);
  });

  it("refuses the sequence when any two rounds are pinned to different ladders (naming both)", async () => {
    const outcome = await computeCoherenceDurationArtifacts([
      buildPostureCoherenceJson(await mk({ Cap: "acceptable" }, { Cap: "ideal" }), LADDER_A),
      buildPostureCoherenceJson(await mk({ Cap: "below-acceptable" }, { Cap: "ideal" }), LADDER_A),
      buildPostureCoherenceJson(await mk({ Cap: "acceptable" }, { Cap: "ideal" }), LADDER_B),
    ]);
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.errors.join(" ")).toMatch(/ladder mismatch/);
    expect(outcome.errors.join(" ")).toMatch(/round 1 and round 3/);
  });

  it("proceeds with a note when any artifact is unpinned (v1)", async () => {
    const outcome = await computeCoherenceDurationArtifacts([
      buildPostureCoherenceJson(await mk({ Cap: "acceptable" }, { Cap: "ideal" })), // v1, no ladder pin
      buildPostureCoherenceJson(await mk({ Cap: "below-acceptable" }, { Cap: "ideal" }), LADDER_A),
    ]);
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.ladderNote).toMatch(/cross-ladder verification unavailable/);
  });

  it("rejects a tampered artifact, prefixing the offending round (1-indexed)", async () => {
    const c2 = await mk({ Cap: "ideal" }, { Cap: "ideal" });
    const json = JSON.parse(buildPostureCoherenceJson(c2, LADDER_A));
    json.dimensions[0].tiers[0].tier = "below-acceptable"; // mutate without recomputing coherence_hash
    const outcome = await computeCoherenceDurationArtifacts([
      buildPostureCoherenceJson(await mk({ Cap: "acceptable" }, { Cap: "ideal" }), LADDER_A),
      JSON.stringify(json),
    ]);
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.errors.some((e) => e.startsWith("round 2:"))).toBe(true);
    expect(outcome.errors.join(" ")).toMatch(/coherence_hash mismatch/);
  });

  it("the lingering verdict matches exposureLingers on the same report", async () => {
    const cs = await lingeringRounds();
    const outcome = await computeCoherenceDurationArtifacts(
      cs.map((c) => buildPostureCoherenceJson(c, LADDER_A)),
      "json",
    );
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.lingering).toBe(exposureLingers(await computeCoherenceDuration(cs)));
  });
});
