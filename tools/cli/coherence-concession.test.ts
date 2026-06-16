import { describe, expect, it } from "vitest";
import { computeCoherenceConcessionArtifacts } from "./coherence-concession.js";
import {
  bundlePostureCoherence,
  buildPostureCoherenceJson,
  type CoherenceInput,
} from "../../src/report/posture-coherence.js";
import {
  computeCoherenceConcession,
  exposureConcedes,
  buildCoherenceConcessionJson,
} from "../../src/report/coherence-concession.js";
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

/** Rounds in which Cap consistently falls below the floor before Term (a strict-majority lead). */
const concedingRounds = () =>
  Promise.all([
    mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
    mk({ Cap: "below-acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // Cap↓ (t0)
    mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // Cap↑
    mk({ Cap: "below-acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // Cap↓ (t2)
    mk({ Cap: "acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // Cap↑, Term↓ (t3)
  ]);

describe("computeCoherenceConcessionArtifacts (spec-v36 — document-free exposure concession order)", () => {
  it("walks N artifacts and matches the in-memory computeCoherenceConcession byte-for-byte", async () => {
    const cs = await concedingRounds();
    const outcome = await computeCoherenceConcessionArtifacts(
      cs.map((c) => buildPostureCoherenceJson(c, LADDER_A)),
      "json",
    );
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    const inMemory = buildCoherenceConcessionJson(await computeCoherenceConcession(cs));
    expect(outcome.output).toBe(inMemory);
    expect(outcome.concedes).toBe(true); // Cap conceded before Term for a strict majority
    expect(outcome.ladderNote).toBeNull();
  });

  it("renders a human-readable summary by default", async () => {
    const outcome = await computeCoherenceConcessionArtifacts(
      (await concedingRounds()).map((c) => buildPostureCoherenceJson(c, LADDER_A)),
    );
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.output).toContain("Coherence exposure concession order across 5 rounds");
    expect(outcome.output).toMatch(/most-conceding pairing/);
    expect(outcome.output).toMatch(/concession_hash: [0-9a-f]{64}/);
  });

  it("trips the gate when one front concedes first for a strict majority of the comparisons", async () => {
    const outcome = await computeCoherenceConcessionArtifacts(
      (await concedingRounds()).map((c) => buildPostureCoherenceJson(c, LADDER_A)),
    );
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.concedes).toBe(true);
    expect(outcome.output).toMatch(/leading/);
  });

  it("clears the gate when no front consistently concedes first (always together)", async () => {
    // Cap & Term fall the same steps each transition → no consistent first-conceder.
    const outcome = await computeCoherenceConcessionArtifacts([
      buildPostureCoherenceJson(
        await mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
        LADDER_A,
      ),
      buildPostureCoherenceJson(
        await mk(
          { Cap: "below-acceptable", Term: "below-acceptable" },
          { Cap: "ideal", Term: "ideal" },
        ),
        LADDER_A,
      ),
      buildPostureCoherenceJson(
        await mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
        LADDER_A,
      ),
      buildPostureCoherenceJson(
        await mk(
          { Cap: "below-acceptable", Term: "below-acceptable" },
          { Cap: "ideal", Term: "ideal" },
        ),
        LADDER_A,
      ),
    ]);
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.concedes).toBe(false);
  });

  it("requires at least two artifacts", async () => {
    const outcome = await computeCoherenceConcessionArtifacts([
      buildPostureCoherenceJson(await mk({ Cap: "ideal" }, { Cap: "ideal" }), LADDER_A),
    ]);
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.errors.join(" ")).toMatch(/at least two/);
  });

  it("refuses the sequence when any two rounds are pinned to different ladders (naming both)", async () => {
    const outcome = await computeCoherenceConcessionArtifacts([
      buildPostureCoherenceJson(
        await mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
        LADDER_A,
      ),
      buildPostureCoherenceJson(
        await mk({ Cap: "below-acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
        LADDER_A,
      ),
      buildPostureCoherenceJson(
        await mk(
          { Cap: "below-acceptable", Term: "below-acceptable" },
          { Cap: "ideal", Term: "ideal" },
        ),
        LADDER_B,
      ),
    ]);
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.errors.join(" ")).toMatch(/ladder mismatch/);
    expect(outcome.errors.join(" ")).toMatch(/round 1 and round 3/);
  });

  it("proceeds with a note when any artifact is unpinned (v1)", async () => {
    const outcome = await computeCoherenceConcessionArtifacts([
      buildPostureCoherenceJson(
        await mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
      ), // v1, no ladder pin
      buildPostureCoherenceJson(
        await mk({ Cap: "below-acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
        LADDER_A,
      ),
    ]);
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.ladderNote).toMatch(/cross-ladder verification unavailable/);
  });

  it("rejects a tampered artifact, prefixing the offending round (1-indexed)", async () => {
    const c2 = await mk({ Cap: "ideal", Term: "ideal" }, { Cap: "ideal", Term: "ideal" });
    const json = JSON.parse(buildPostureCoherenceJson(c2, LADDER_A));
    json.dimensions[0].tiers[0].tier = "below-acceptable"; // mutate without recomputing coherence_hash
    const outcome = await computeCoherenceConcessionArtifacts([
      buildPostureCoherenceJson(
        await mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
        LADDER_A,
      ),
      JSON.stringify(json),
    ]);
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.errors.some((e) => e.startsWith("round 2:"))).toBe(true);
    expect(outcome.errors.join(" ")).toMatch(/coherence_hash mismatch/);
  });

  it("the concedes verdict matches exposureConcedes on the same report", async () => {
    const cs = await concedingRounds();
    const outcome = await computeCoherenceConcessionArtifacts(
      cs.map((c) => buildPostureCoherenceJson(c, LADDER_A)),
      "json",
    );
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.concedes).toBe(exposureConcedes(await computeCoherenceConcession(cs)));
  });
});
