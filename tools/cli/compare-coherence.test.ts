import { describe, expect, it } from "vitest";
import { compareCoherenceArtifacts } from "./compare-coherence.js";
import {
  bundlePostureCoherence,
  buildPostureCoherenceJson,
  type CoherenceInput,
} from "../../src/report/posture-coherence.js";
import {
  compareCoherence,
  coherenceRegressed,
  buildCoherenceMovementJson,
} from "../../src/report/coherence-movement.js";
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

/** Round one: cap acceptable, law ideal (both docs agree). */
const round1 = () =>
  bundlePostureCoherence(bundle(["msa.docx", { Cap: "acceptable", Law: "ideal" }], ["order.docx", { Cap: "acceptable", Law: "ideal" }]));
/** Round two: MSA ideal cap, order form below-floor cap → binding floor regressed + fractured. */
const round2 = () =>
  bundlePostureCoherence(bundle(["msa.docx", { Cap: "ideal", Law: "ideal" }], ["order.docx", { Cap: "below-acceptable", Law: "ideal" }]));

describe("compareCoherenceArtifacts (spec-v16 — document-free coherence-to-coherence movement)", () => {
  it("diffs two saved artifacts and matches the in-memory compareCoherence", async () => {
    const base = await round1();
    const revised = await round2();
    const outcome = await compareCoherenceArtifacts(
      buildPostureCoherenceJson(base, LADDER_A),
      buildPostureCoherenceJson(revised, LADDER_A),
      "json",
    );
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    // The movement from disk artifacts is byte-identical to the in-memory diff.
    const inMemory = buildCoherenceMovementJson(await compareCoherence(base, revised));
    expect(outcome.output).toBe(inMemory);
    expect(outcome.regressed).toBe(true); // Cap floor acceptable → below-acceptable
    expect(outcome.ladderNote).toBeNull(); // both pinned + equal → verified, no note
  });

  it("renders a human-readable summary by default", async () => {
    const outcome = await compareCoherenceArtifacts(
      buildPostureCoherenceJson(await round1(), LADDER_A),
      buildPostureCoherenceJson(await round2(), LADDER_A),
    );
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.output).toContain("Cross-document posture movement");
    expect(outcome.output).toMatch(/binding floor ↓ regressed/);
    expect(outcome.output).toMatch(/movement_hash: [0-9a-f]{64}/);
  });

  it("reports no regression when the floor holds or improves", async () => {
    // Reverse direction: round2 → round1 is an improvement.
    const outcome = await compareCoherenceArtifacts(
      buildPostureCoherenceJson(await round2(), LADDER_A),
      buildPostureCoherenceJson(await round1(), LADDER_A),
      "json",
    );
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.regressed).toBe(false);
  });

  it("refuses two artifacts pinned to different ladders (cross-ladder guard, exit 1)", async () => {
    const outcome = await compareCoherenceArtifacts(
      buildPostureCoherenceJson(await round1(), LADDER_A),
      buildPostureCoherenceJson(await round2(), LADDER_B),
    );
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.errors.join(" ")).toMatch(/ladder mismatch/);
  });

  it("proceeds with a note when either artifact is unpinned (v1)", async () => {
    const outcome = await compareCoherenceArtifacts(
      buildPostureCoherenceJson(await round1()), // v1, no ladder pin
      buildPostureCoherenceJson(await round2(), LADDER_A),
    );
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.ladderNote).toMatch(/cross-ladder verification unavailable/);
  });

  it("rejects a tampered artifact whose hash no longer matches its dimensions", async () => {
    const base = await round1();
    const json = JSON.parse(buildPostureCoherenceJson(base, LADDER_A));
    json.dimensions[0].tiers[0].tier = "ideal"; // mutate without recomputing coherence_hash
    const outcome = await compareCoherenceArtifacts(
      JSON.stringify(json),
      buildPostureCoherenceJson(await round2(), LADDER_A),
    );
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.errors.join(" ")).toMatch(/base: coherence_hash mismatch/);
  });

  it("rejects malformed JSON, prefixing the offending side", async () => {
    const outcome = await compareCoherenceArtifacts("{not json", buildPostureCoherenceJson(await round2(), LADDER_A));
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.errors.some((e) => e.startsWith("base:"))).toBe(true);
  });

  it("the regression verdict matches coherenceRegressed on the same movement", async () => {
    const base = await round1();
    const revised = await round2();
    const outcome = await compareCoherenceArtifacts(
      buildPostureCoherenceJson(base, LADDER_A),
      buildPostureCoherenceJson(revised, LADDER_A),
      "json",
    );
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.regressed).toBe(coherenceRegressed(await compareCoherence(base, revised)));
  });
});
