import { describe, expect, it } from "vitest";
import { computeCoherencePersistenceArtifacts } from "./coherence-persistence.js";
import {
  bundlePostureCoherence,
  buildPostureCoherenceJson,
  type CoherenceInput,
} from "../../src/report/posture-coherence.js";
import {
  computeCoherencePersistence,
  exposureOpen,
  buildCoherencePersistenceJson,
} from "../../src/report/coherence-persistence.js";
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

const round = (capA: NegotiationTier, capB: NegotiationTier) =>
  bundlePostureCoherence(
    bundle(["msa.docx", { Cap: capA, Law: "ideal" }], ["order.docx", { Cap: capB, Law: "ideal" }]),
  );

describe("computeCoherencePersistenceArtifacts (spec-v21 — document-free exposure persistence)", () => {
  it("walks N artifacts and matches the in-memory computeCoherencePersistence byte-for-byte", async () => {
    const c1 = await round("ideal", "ideal");
    const c2 = await round("ideal", "below-acceptable");
    const c3 = await round("ideal", "below-acceptable");
    const outcome = await computeCoherencePersistenceArtifacts(
      [c1, c2, c3].map((c) => buildPostureCoherenceJson(c, LADDER_A)),
      "json",
    );
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    const inMemory = buildCoherencePersistenceJson(await computeCoherencePersistence([c1, c2, c3]));
    expect(outcome.output).toBe(inMemory);
    expect(outcome.open).toBe(true); // Cap still below floor in the last round
    expect(outcome.ladderNote).toBeNull();
  });

  it("renders a human-readable summary by default", async () => {
    const outcome = await computeCoherencePersistenceArtifacts([
      buildPostureCoherenceJson(await round("ideal", "ideal"), LADDER_A),
      buildPostureCoherenceJson(await round("ideal", "below-acceptable"), LADDER_A),
    ]);
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.output).toContain("Coherence exposure persistence across 2 rounds");
    expect(outcome.output).toMatch(/⚠ Cap: open/);
    expect(outcome.output).toMatch(/persistence_hash: [0-9a-f]{64}/);
  });

  it("does NOT report open when a front dipped below floor then recovered (the gate clears)", async () => {
    const outcome = await computeCoherencePersistenceArtifacts([
      buildPostureCoherenceJson(await round("ideal", "ideal"), LADDER_A),
      buildPostureCoherenceJson(await round("ideal", "below-acceptable"), LADDER_A),
      buildPostureCoherenceJson(await round("acceptable", "acceptable"), LADDER_A),
    ]);
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.open).toBe(false); // Cap recovered → resolved, not open
    expect(outcome.output).toMatch(/✓ Cap: resolved/);
  });

  it("reports open for a front still below floor at the latest round", async () => {
    const outcome = await computeCoherencePersistenceArtifacts([
      buildPostureCoherenceJson(await round("below-acceptable", "below-acceptable"), LADDER_A),
      buildPostureCoherenceJson(await round("below-acceptable", "below-acceptable"), LADDER_A),
    ]);
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.open).toBe(true);
  });

  it("requires at least two artifacts", async () => {
    const outcome = await computeCoherencePersistenceArtifacts([
      buildPostureCoherenceJson(await round("ideal", "ideal"), LADDER_A),
    ]);
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.errors.join(" ")).toMatch(/at least two/);
  });

  it("refuses the sequence when any two rounds are pinned to different ladders (naming both)", async () => {
    const outcome = await computeCoherencePersistenceArtifacts([
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
    const outcome = await computeCoherencePersistenceArtifacts([
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
    const outcome = await computeCoherencePersistenceArtifacts([
      buildPostureCoherenceJson(await round("ideal", "below-acceptable"), LADDER_A),
      JSON.stringify(json),
    ]);
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.errors.some((e) => e.startsWith("round 2:"))).toBe(true);
    expect(outcome.errors.join(" ")).toMatch(/coherence_hash mismatch/);
  });

  it("the open verdict matches exposureOpen on the same persistence", async () => {
    const c1 = await round("ideal", "ideal");
    const c2 = await round("ideal", "below-acceptable");
    const outcome = await computeCoherencePersistenceArtifacts(
      [c1, c2].map((c) => buildPostureCoherenceJson(c, LADDER_A)),
      "json",
    );
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.open).toBe(exposureOpen(await computeCoherencePersistence([c1, c2])));
  });
});
