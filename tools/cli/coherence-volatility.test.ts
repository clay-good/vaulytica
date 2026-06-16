import { describe, expect, it } from "vitest";
import { computeCoherenceVolatilityArtifacts } from "./coherence-volatility.js";
import {
  bundlePostureCoherence,
  buildPostureCoherenceJson,
  type CoherenceInput,
} from "../../src/report/posture-coherence.js";
import {
  computeCoherenceVolatility,
  exposureVolatile,
  buildCoherenceVolatilityJson,
} from "../../src/report/coherence-volatility.js";
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

const mk = (a: Record<string, NegotiationTier>, b: Record<string, NegotiationTier>) =>
  bundlePostureCoherence(bundle(["msa.docx", a], ["order.docx", b]));

describe("computeCoherenceVolatilityArtifacts (spec-v24 — document-free exposure volatility)", () => {
  it("walks N artifacts and matches the in-memory computeCoherenceVolatility byte-for-byte", async () => {
    const c1 = await mk({ Cap: "below-acceptable" }, { Cap: "ideal" });
    const c2 = await mk({ Cap: "acceptable" }, { Cap: "ideal" });
    const c3 = await mk({ Cap: "below-acceptable" }, { Cap: "ideal" });
    const outcome = await computeCoherenceVolatilityArtifacts(
      [c1, c2, c3].map((c) => buildPostureCoherenceJson(c, LADDER_A)),
      "json",
    );
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    const inMemory = buildCoherenceVolatilityJson(await computeCoherenceVolatility([c1, c2, c3]));
    expect(outcome.output).toBe(inMemory);
    expect(outcome.volatile).toBe(true); // crossed the floor twice
    expect(outcome.ladderNote).toBeNull();
  });

  it("renders a human-readable summary by default", async () => {
    const outcome = await computeCoherenceVolatilityArtifacts([
      buildPostureCoherenceJson(await mk({ Cap: "below-acceptable" }, { Cap: "ideal" }), LADDER_A),
      buildPostureCoherenceJson(await mk({ Cap: "acceptable" }, { Cap: "ideal" }), LADDER_A),
      buildPostureCoherenceJson(await mk({ Cap: "below-acceptable" }, { Cap: "ideal" }), LADDER_A),
    ]);
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.output).toContain("Coherence exposure volatility across 3 rounds");
    expect(outcome.output).toMatch(/volatile/);
    expect(outcome.output).toMatch(/volatility_hash: [0-9a-f]{64}/);
  });

  it("does NOT report volatile for a stuck front (the gate clears)", async () => {
    const outcome = await computeCoherenceVolatilityArtifacts([
      buildPostureCoherenceJson(await mk({ Cap: "below-acceptable" }, { Cap: "ideal" }), LADDER_A),
      buildPostureCoherenceJson(await mk({ Cap: "below-acceptable" }, { Cap: "ideal" }), LADDER_A),
      buildPostureCoherenceJson(await mk({ Cap: "below-acceptable" }, { Cap: "ideal" }), LADDER_A),
    ]);
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.volatile).toBe(false); // never crossed the floor
    expect(outcome.output).toMatch(/stable \(never crossed\)/);
  });

  it("requires at least two artifacts", async () => {
    const outcome = await computeCoherenceVolatilityArtifacts([
      buildPostureCoherenceJson(await mk({ Cap: "ideal" }, { Cap: "ideal" }), LADDER_A),
    ]);
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.errors.join(" ")).toMatch(/at least two/);
  });

  it("refuses the sequence when any two rounds are pinned to different ladders (naming both)", async () => {
    const outcome = await computeCoherenceVolatilityArtifacts([
      buildPostureCoherenceJson(await mk({ Cap: "ideal" }, { Cap: "ideal" }), LADDER_A),
      buildPostureCoherenceJson(await mk({ Cap: "ideal" }, { Cap: "ideal" }), LADDER_A),
      buildPostureCoherenceJson(await mk({ Cap: "below-acceptable" }, { Cap: "ideal" }), LADDER_B),
    ]);
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.errors.join(" ")).toMatch(/ladder mismatch/);
    expect(outcome.errors.join(" ")).toMatch(/round 1 and round 3/);
  });

  it("proceeds with a note when any artifact is unpinned (v1)", async () => {
    const outcome = await computeCoherenceVolatilityArtifacts([
      buildPostureCoherenceJson(await mk({ Cap: "ideal" }, { Cap: "ideal" })), // v1, no ladder pin
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
    const outcome = await computeCoherenceVolatilityArtifacts([
      buildPostureCoherenceJson(await mk({ Cap: "below-acceptable" }, { Cap: "ideal" }), LADDER_A),
      JSON.stringify(json),
    ]);
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.errors.some((e) => e.startsWith("round 2:"))).toBe(true);
    expect(outcome.errors.join(" ")).toMatch(/coherence_hash mismatch/);
  });

  it("the volatile verdict matches exposureVolatile on the same volatility", async () => {
    const c1 = await mk({ Cap: "acceptable" }, { Cap: "ideal" });
    const c2 = await mk({ Cap: "below-acceptable" }, { Cap: "ideal" });
    const c3 = await mk({ Cap: "acceptable" }, { Cap: "ideal" });
    const outcome = await computeCoherenceVolatilityArtifacts(
      [c1, c2, c3].map((c) => buildPostureCoherenceJson(c, LADDER_A)),
      "json",
    );
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.volatile).toBe(exposureVolatile(await computeCoherenceVolatility([c1, c2, c3])));
  });
});
