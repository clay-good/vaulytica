import { describe, expect, it } from "vitest";
import { computeCoherenceChainArtifacts } from "./coherence-chain.js";
import {
  bundlePostureCoherence,
  buildPostureCoherenceJson,
  type CoherenceInput,
} from "../../src/report/posture-coherence.js";
import {
  computeCoherenceChain,
  exposureCyclic,
  buildCoherenceChainJson,
} from "../../src/report/coherence-chain.js";
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

function path(steps: number[], n: number, start: NegotiationTier = A): NegotiationTier[] {
  const set = new Set(steps);
  const out: NegotiationTier[] = [];
  let cur = start;
  for (let i = 0; i < n; i++) {
    out.push(cur);
    if (set.has(i)) cur = cur === B ? A : B;
  }
  return out;
}

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

/** A clean acyclic pipeline Cap → Term → Ind (no cycle). */
const acyclicRounds = () => rounds({ Cap: path([0], 4), Term: path([1], 4), Ind: path([2], 4) });
/** The non-transitive (Condorcet) triple — a directed lead-lag cycle. */
const cyclicRounds = () =>
  rounds({ Aaa: path([1, 3, 8], 10), Bbb: path([0, 5, 7], 10), Ccc: path([2, 4, 6], 10) });

describe("computeCoherenceChainArtifacts (spec-v42 — document-free transitive lead chain)", () => {
  it("walks N artifacts and matches the in-memory computeCoherenceChain byte-for-byte", async () => {
    const cs = await acyclicRounds();
    const outcome = await computeCoherenceChainArtifacts(
      cs.map((c) => buildPostureCoherenceJson(c, LADDER_A)),
      "json",
    );
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    const inMemory = buildCoherenceChainJson(await computeCoherenceChain(cs));
    expect(outcome.output).toBe(inMemory);
    expect(outcome.cyclic).toBe(false);
    expect(outcome.ladderNote).toBeNull();
  });

  it("renders a human-readable summary by default", async () => {
    const outcome = await computeCoherenceChainArtifacts(
      (await acyclicRounds()).map((c) => buildPostureCoherenceJson(c, LADDER_A)),
    );
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.output).toContain("Coherence exposure lead chain across 4 rounds");
    expect(outcome.output).toMatch(/headwater: Cap/);
    expect(outcome.output).toMatch(/chain_hash: [0-9a-f]{64}/);
  });

  it("trips the gate on a directed lead-lag cycle", async () => {
    const outcome = await computeCoherenceChainArtifacts(
      (await cyclicRounds()).map((c) => buildPostureCoherenceJson(c, LADDER_A)),
    );
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.cyclic).toBe(true);
    expect(outcome.output).toMatch(/ordering: intransitive/);
  });

  it("clears the gate on an acyclic pipeline", async () => {
    const outcome = await computeCoherenceChainArtifacts(
      (await acyclicRounds()).map((c) => buildPostureCoherenceJson(c, LADDER_A)),
    );
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.cyclic).toBe(false);
  });

  it("requires at least two artifacts", async () => {
    const outcome = await computeCoherenceChainArtifacts([
      buildPostureCoherenceJson(await mk({ Cap: "ideal" }, { Cap: "ideal" }), LADDER_A),
    ]);
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.errors.join(" ")).toMatch(/at least two/);
  });

  it("refuses the sequence when any two rounds are pinned to different ladders (naming both)", async () => {
    const outcome = await computeCoherenceChainArtifacts([
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
    const outcome = await computeCoherenceChainArtifacts([
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
    const outcome = await computeCoherenceChainArtifacts([
      buildPostureCoherenceJson(await mk({ Cap: A }, { Cap: "ideal" }), LADDER_A),
      JSON.stringify(json),
    ]);
    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.errors.some((e) => e.startsWith("round 2:"))).toBe(true);
    expect(outcome.errors.join(" ")).toMatch(/coherence_hash mismatch/);
  });

  it("the cyclic verdict matches exposureCyclic on the same report", async () => {
    const cs = await cyclicRounds();
    const outcome = await computeCoherenceChainArtifacts(
      cs.map((c) => buildPostureCoherenceJson(c, LADDER_A)),
      "json",
    );
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.cyclic).toBe(exposureCyclic(await computeCoherenceChain(cs)));
  });
});
