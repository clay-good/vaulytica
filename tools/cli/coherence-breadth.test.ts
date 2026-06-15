import { describe, expect, it } from "vitest";
import { computeCoherenceBreadthArtifacts } from "./coherence-breadth.js";
import {
  bundlePostureCoherence,
  buildPostureCoherenceJson,
  type CoherenceInput,
} from "../../src/report/posture-coherence.js";
import {
  computeCoherenceBreadth,
  exposureWidened,
  buildCoherenceBreadthJson,
} from "../../src/report/coherence-breadth.js";
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

describe("computeCoherenceBreadthArtifacts (spec-v22 — document-free exposure breadth)", () => {
  it("walks N artifacts and matches the in-memory computeCoherenceBreadth byte-for-byte", async () => {
    const c1 = await mk({ Cap: "below-acceptable", Risk: "ideal" }, { Cap: "ideal", Risk: "ideal" });
    const c2 = await mk(
      { Cap: "below-acceptable", Risk: "below-acceptable" },
      { Cap: "ideal", Risk: "ideal" },
    );
    const outcome = await computeCoherenceBreadthArtifacts(
      [c1, c2].map((c) => buildPostureCoherenceJson(c, LADDER_A)),
      "json",
    );
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    const inMemory = buildCoherenceBreadthJson(await computeCoherenceBreadth([c1, c2]));
    expect(outcome.output).toBe(inMemory);
    expect(outcome.widened).toBe(true); // 1 → 2 fronts below floor
    expect(outcome.ladderNote).toBeNull();
  });

  it("renders a human-readable summary by default", async () => {
    const outcome = await computeCoherenceBreadthArtifacts([
      buildPostureCoherenceJson(
        await mk({ Cap: "below-acceptable", Risk: "ideal" }, { Cap: "ideal", Risk: "ideal" }),
        LADDER_A,
      ),
      buildPostureCoherenceJson(
        await mk(
          { Cap: "below-acceptable", Risk: "below-acceptable" },
          { Cap: "ideal", Risk: "ideal" },
        ),
        LADDER_A,
      ),
    ]);
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.output).toContain("Coherence exposure breadth across 2 rounds");
    expect(outcome.output).toMatch(/exposure widened/);
    expect(outcome.output).toMatch(/breadth_hash: [0-9a-f]{64}/);
  });

  it("does NOT report widened when the deal narrowed (the gate clears)", async () => {
    const outcome = await computeCoherenceBreadthArtifacts([
      buildPostureCoherenceJson(
        await mk(
          { Cap: "below-acceptable", Risk: "below-acceptable" },
          { Cap: "ideal", Risk: "ideal" },
        ),
        LADDER_A,
      ),
      buildPostureCoherenceJson(
        await mk({ Cap: "below-acceptable", Risk: "acceptable" }, { Cap: "ideal", Risk: "ideal" }),
        LADDER_A,
      ),
    ]);
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.widened).toBe(false); // 2 → 1 narrowed
    expect(outcome.output).toMatch(/exposure narrowed/);
  });

  it("requires at least two artifacts", async () => {
    const outcome = await computeCoherenceBreadthArtifacts([
      buildPostureCoherenceJson(await mk({ Cap: "ideal" }, { Cap: "ideal" }), LADDER_A),
    ]);
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.errors.join(" ")).toMatch(/at least two/);
  });

  it("refuses the sequence when any two rounds are pinned to different ladders (naming both)", async () => {
    const outcome = await computeCoherenceBreadthArtifacts([
      buildPostureCoherenceJson(await mk({ Cap: "ideal" }, { Cap: "ideal" }), LADDER_A),
      buildPostureCoherenceJson(await mk({ Cap: "ideal" }, { Cap: "ideal" }), LADDER_A),
      buildPostureCoherenceJson(
        await mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
        LADDER_B,
      ),
    ]);
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.errors.join(" ")).toMatch(/ladder mismatch/);
    expect(outcome.errors.join(" ")).toMatch(/round 1 and round 3/);
  });

  it("proceeds with a note when any artifact is unpinned (v1)", async () => {
    const outcome = await computeCoherenceBreadthArtifacts([
      buildPostureCoherenceJson(await mk({ Cap: "ideal" }, { Cap: "ideal" })), // v1, no ladder pin
      buildPostureCoherenceJson(
        await mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
        LADDER_A,
      ),
    ]);
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.ladderNote).toMatch(/cross-ladder verification unavailable/);
  });

  it("rejects a tampered artifact, prefixing the offending round (1-indexed)", async () => {
    const c2 = await mk({ Cap: "ideal" }, { Cap: "ideal" });
    const json = JSON.parse(buildPostureCoherenceJson(c2, LADDER_A));
    json.dimensions[0].tiers[0].tier = "below-acceptable"; // mutate without recomputing coherence_hash
    const outcome = await computeCoherenceBreadthArtifacts([
      buildPostureCoherenceJson(await mk({ Cap: "below-acceptable" }, { Cap: "ideal" }), LADDER_A),
      JSON.stringify(json),
    ]);
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.errors.some((e) => e.startsWith("round 2:"))).toBe(true);
    expect(outcome.errors.join(" ")).toMatch(/coherence_hash mismatch/);
  });

  it("the widened verdict matches exposureWidened on the same breadth", async () => {
    const c1 = await mk({ Cap: "below-acceptable", Risk: "ideal" }, { Cap: "ideal", Risk: "ideal" });
    const c2 = await mk(
      { Cap: "below-acceptable", Risk: "below-acceptable" },
      { Cap: "ideal", Risk: "ideal" },
    );
    const outcome = await computeCoherenceBreadthArtifacts(
      [c1, c2].map((c) => buildPostureCoherenceJson(c, LADDER_A)),
      "json",
    );
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.widened).toBe(exposureWidened(await computeCoherenceBreadth([c1, c2])));
  });
});
