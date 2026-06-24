import { describe, expect, it } from "vitest";
import { computeCoherenceDurabilityArtifacts } from "./coherence-durability.js";
import {
  bundlePostureCoherence,
  buildPostureCoherenceJson,
  type CoherenceInput,
} from "../../src/report/posture-coherence.js";
import {
  computeCoherenceDurability,
  recoveryFragile,
  buildCoherenceDurabilityJson,
} from "../../src/report/coherence-durability.js";
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

/** Rounds in which Cap recovers and relapses the very next round twice → mean 1, fragile. */
const fragileRounds = () =>
  Promise.all([
    mk({ Cap: "below-acceptable" }, { Cap: "ideal" }), // r1: below
    mk({ Cap: "acceptable" }, { Cap: "ideal" }), // r2: recover (rec 2)
    mk({ Cap: "below-acceptable" }, { Cap: "ideal" }), // r3: relapse (clean 1)
    mk({ Cap: "acceptable" }, { Cap: "ideal" }), // r4: recover (rec 4)
    mk({ Cap: "below-acceptable" }, { Cap: "ideal" }), // r5: relapse (clean 1)
  ]);

describe("computeCoherenceDurabilityArtifacts (spec-v41 — document-free recovery durability)", () => {
  it("walks N artifacts and matches the in-memory computeCoherenceDurability byte-for-byte", async () => {
    const cs = await fragileRounds();
    const outcome = await computeCoherenceDurabilityArtifacts(
      cs.map((c) => buildPostureCoherenceJson(c, LADDER_A)),
      "json",
    );
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    const inMemory = buildCoherenceDurabilityJson(await computeCoherenceDurability(cs));
    expect(outcome.output).toBe(inMemory);
    expect(outcome.fragile).toBe(true);
    expect(outcome.ladderNote).toBeNull();
  });

  it("renders a human-readable summary by default", async () => {
    const outcome = await computeCoherenceDurabilityArtifacts(
      (await fragileRounds()).map((c) => buildPostureCoherenceJson(c, LADDER_A)),
    );
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.output).toContain("Coherence recovery durability across 5 rounds");
    expect(outcome.output).toMatch(/most fragile recovery: Cap/);
    expect(outcome.output).toMatch(/durability_hash: [0-9a-f]{64}/);
  });

  it("trips the gate when a front's relapsed recoveries average fewer than two rounds", async () => {
    const outcome = await computeCoherenceDurabilityArtifacts(
      (await fragileRounds()).map((c) => buildPostureCoherenceJson(c, LADDER_A)),
    );
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.fragile).toBe(true);
    expect(outcome.output).toMatch(/fragile/);
  });

  it("clears the gate when a front's fix holds for two or more rounds before relapsing", async () => {
    const outcome = await computeCoherenceDurabilityArtifacts([
      buildPostureCoherenceJson(await mk({ Cap: "below-acceptable" }, { Cap: "ideal" }), LADDER_A), // below
      buildPostureCoherenceJson(await mk({ Cap: "acceptable" }, { Cap: "ideal" }), LADDER_A), // recover (rec 2)
      buildPostureCoherenceJson(await mk({ Cap: "acceptable" }, { Cap: "ideal" }), LADDER_A), // hold
      buildPostureCoherenceJson(await mk({ Cap: "below-acceptable" }, { Cap: "ideal" }), LADDER_A), // relapse (clean 2)
    ]);
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.fragile).toBe(false); // mean 2 → durable
  });

  it("requires at least two artifacts", async () => {
    const outcome = await computeCoherenceDurabilityArtifacts([
      buildPostureCoherenceJson(await mk({ Cap: "ideal" }, { Cap: "ideal" }), LADDER_A),
    ]);
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.errors.join(" ")).toMatch(/at least two/);
  });

  it("refuses the sequence when any two rounds are pinned to different ladders (naming both)", async () => {
    const outcome = await computeCoherenceDurabilityArtifacts([
      buildPostureCoherenceJson(await mk({ Cap: "below-acceptable" }, { Cap: "ideal" }), LADDER_A),
      buildPostureCoherenceJson(await mk({ Cap: "acceptable" }, { Cap: "ideal" }), LADDER_A),
      buildPostureCoherenceJson(await mk({ Cap: "below-acceptable" }, { Cap: "ideal" }), LADDER_B),
    ]);
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.errors.join(" ")).toMatch(/ladder mismatch/);
    expect(outcome.errors.join(" ")).toMatch(/round 1 and round 3/);
  });

  it("proceeds with a note when any artifact is unpinned (v1)", async () => {
    const outcome = await computeCoherenceDurabilityArtifacts([
      buildPostureCoherenceJson(await mk({ Cap: "below-acceptable" }, { Cap: "ideal" })), // v1, no ladder pin
      buildPostureCoherenceJson(await mk({ Cap: "acceptable" }, { Cap: "ideal" }), LADDER_A),
    ]);
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.ladderNote).toMatch(/cross-ladder verification unavailable/);
  });

  it("rejects a tampered artifact, prefixing the offending round (1-indexed)", async () => {
    const c2 = await mk({ Cap: "ideal" }, { Cap: "ideal" });
    const json = JSON.parse(buildPostureCoherenceJson(c2, LADDER_A));
    json.dimensions[0].tiers[0].tier = "below-acceptable"; // mutate without recomputing coherence_hash
    const outcome = await computeCoherenceDurabilityArtifacts([
      buildPostureCoherenceJson(await mk({ Cap: "acceptable" }, { Cap: "ideal" }), LADDER_A),
      JSON.stringify(json),
    ]);
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.errors.some((e) => e.startsWith("round 2:"))).toBe(true);
    expect(outcome.errors.join(" ")).toMatch(/coherence_hash mismatch/);
  });

  it("the fragile verdict matches recoveryFragile on the same report", async () => {
    const cs = await fragileRounds();
    const outcome = await computeCoherenceDurabilityArtifacts(
      cs.map((c) => buildPostureCoherenceJson(c, LADDER_A)),
      "json",
    );
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.fragile).toBe(recoveryFragile(await computeCoherenceDurability(cs)));
  });
});
