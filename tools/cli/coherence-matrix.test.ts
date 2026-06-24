import { describe, expect, it } from "vitest";
import { computeCoherenceMatrixArtifacts } from "./coherence-matrix.js";
import {
  bundlePostureCoherence,
  buildPostureCoherenceJson,
  type CoherenceInput,
} from "../../src/report/posture-coherence.js";
import {
  computeCoherenceMatrix,
  exposureBlackout,
  buildCoherenceMatrixJson,
} from "../../src/report/coherence-matrix.js";
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
const B: NegotiationTier = "below-acceptable";
const A: NegotiationTier = "acceptable";

const mk = (a: Record<string, NegotiationTier>, b: Record<string, NegotiationTier>) =>
  bundlePostureCoherence(bundle(["msa.docx", a], ["order.docx", b]));

function rounds(paths: Record<string, NegotiationTier[]>) {
  const names = Object.keys(paths);
  const n = paths[names[0]!]!.length;
  return Promise.all(
    Array.from({ length: n }, (_, i) => {
      const doc1: Record<string, NegotiationTier> = {};
      const doc2: Record<string, NegotiationTier> = {};
      for (const name of names) {
        doc1[name] = paths[name]![i]!;
        doc2[name] = "ideal";
      }
      return mk(doc1, doc2);
    }),
  );
}

/** A grid that blacks out in round 2 (both fronts below at once). */
const blackoutRounds = () => rounds({ Cap: [A, B, A], Term: [A, B, A] });
/** A grid where one front always holds the line — no full column. */
const cleanRounds = () => rounds({ Cap: [B, B, B], Term: [A, A, A] });

describe("computeCoherenceMatrixArtifacts (spec-v44 — document-free per-front × per-round grid)", () => {
  it("walks N artifacts and matches the in-memory computeCoherenceMatrix byte-for-byte", async () => {
    const cs = await blackoutRounds();
    const outcome = await computeCoherenceMatrixArtifacts(
      cs.map((c) => buildPostureCoherenceJson(c, LADDER_A)),
      "json",
    );
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    const inMemory = buildCoherenceMatrixJson(await computeCoherenceMatrix(cs));
    expect(outcome.output).toBe(inMemory);
    expect(outcome.blackout).toBe(true);
    expect(outcome.ladderNote).toBeNull();
  });

  it("renders a human-readable heatmap by default", async () => {
    const outcome = await computeCoherenceMatrixArtifacts(
      (await blackoutRounds()).map((c) => buildPostureCoherenceJson(c, LADDER_A)),
    );
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.output).toContain("Coherence exposure matrix across 3 rounds");
    expect(outcome.output).toMatch(/legend: ▓ below floor/);
    expect(outcome.output).toMatch(/matrix_hash: [0-9a-f]{64}/);
  });

  it("trips the gate on a blackout round", async () => {
    const outcome = await computeCoherenceMatrixArtifacts(
      (await blackoutRounds()).map((c) => buildPostureCoherenceJson(c, LADDER_A)),
    );
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.blackout).toBe(true);
    expect(outcome.output).toMatch(/blackout \(every stated front below floor\): round 2\./);
  });

  it("clears the gate when one front always holds the line", async () => {
    const outcome = await computeCoherenceMatrixArtifacts(
      (await cleanRounds()).map((c) => buildPostureCoherenceJson(c, LADDER_A)),
    );
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.blackout).toBe(false);
    expect(outcome.output).toMatch(/blackout: none/);
  });

  it("requires at least two artifacts", async () => {
    const outcome = await computeCoherenceMatrixArtifacts([
      buildPostureCoherenceJson(await mk({ Cap: "ideal" }, { Cap: "ideal" }), LADDER_A),
    ]);
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.errors.join(" ")).toMatch(/at least two/);
  });

  it("refuses the sequence when any two rounds are pinned to different ladders (naming both)", async () => {
    const outcome = await computeCoherenceMatrixArtifacts([
      buildPostureCoherenceJson(await mk({ Cap: B }, { Cap: "ideal" }), LADDER_A),
      buildPostureCoherenceJson(await mk({ Cap: A }, { Cap: "ideal" }), LADDER_A),
      buildPostureCoherenceJson(await mk({ Cap: B }, { Cap: "ideal" }), LADDER_B),
    ]);
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.errors.join(" ")).toMatch(/ladder mismatch/);
    expect(outcome.errors.join(" ")).toMatch(/round 1 and round 3/);
  });

  it("proceeds with a note when any artifact is unpinned (v1)", async () => {
    const outcome = await computeCoherenceMatrixArtifacts([
      buildPostureCoherenceJson(await mk({ Cap: B }, { Cap: "ideal" })), // v1, no ladder pin
      buildPostureCoherenceJson(await mk({ Cap: A }, { Cap: "ideal" }), LADDER_A),
    ]);
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.ladderNote).toMatch(/cross-ladder verification unavailable/);
  });

  it("rejects a tampered artifact, prefixing the offending round (1-indexed)", async () => {
    const c2 = await mk({ Cap: "ideal" }, { Cap: "ideal" });
    const json = JSON.parse(buildPostureCoherenceJson(c2, LADDER_A));
    json.dimensions[0].tiers[0].tier = "below-acceptable"; // mutate without recomputing coherence_hash
    const outcome = await computeCoherenceMatrixArtifacts([
      buildPostureCoherenceJson(await mk({ Cap: A }, { Cap: "ideal" }), LADDER_A),
      JSON.stringify(json),
    ]);
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.errors.some((e) => e.startsWith("round 2:"))).toBe(true);
    expect(outcome.errors.join(" ")).toMatch(/coherence_hash mismatch/);
  });

  it("the blackout verdict matches exposureBlackout on the same report", async () => {
    const cs = await blackoutRounds();
    const outcome = await computeCoherenceMatrixArtifacts(
      cs.map((c) => buildPostureCoherenceJson(c, LADDER_A)),
      "json",
    );
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.blackout).toBe(exposureBlackout(await computeCoherenceMatrix(cs)));
  });
});
