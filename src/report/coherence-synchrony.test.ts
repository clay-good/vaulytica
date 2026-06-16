import { describe, expect, it } from "vitest";
import {
  computeCoherenceSynchrony,
  exposureSynchronized,
  buildCoherenceSynchronyJson,
  renderCoherenceSynchronySummary,
} from "./coherence-synchrony.js";
import { computeCoherenceVolatility } from "./coherence-volatility.js";
import { bundlePostureCoherence, type CoherenceInput } from "./posture-coherence.js";
import type { NegotiationPosture, NegotiationTier } from "../playbooks/custom-interpreter.js";

function posture(map: Record<string, NegotiationTier>): NegotiationPosture {
  return {
    positions: Object.entries(map).map(([dimension, tier]) => ({ dimension, tier })),
    counts: { ideal: 0, acceptable: 0, below_acceptable: 0, unevaluable: 0 },
    posture_hash: "test",
  };
}

const bundle = (...docs: Array<[string, Record<string, NegotiationTier>]>): CoherenceInput[] =>
  docs.map(([document, map]) => ({ document, posture: posture(map) }));

/** A round built from two docs; each front's binding floor is the weaker of the two tiers. */
const mk = (a: Record<string, NegotiationTier>, b: Record<string, NegotiationTier>) =>
  bundlePostureCoherence(bundle(["msa.docx", a], ["order.docx", b]));

describe("computeCoherenceSynchrony (spec-v25 — per-round-transition floor crossings)", () => {
  it("flags a synchronized step — two fronts crossing the floor together in one round", async () => {
    // Round 1→2: both Cap and Term fall below floor in the SAME step (a coordinated lurch).
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
    ]);
    const r = await computeCoherenceSynchrony(rounds);
    expect(r.per_transition).toHaveLength(1);
    const step = r.per_transition[0]!;
    expect(step.from_round).toBe(1);
    expect(step.to_round).toBe(2);
    expect(step.crossing_fronts).toBe(2);
    expect(step.crossed_dimensions).toEqual(["Cap", "Term"]);
    expect(step.synchrony).toBe("synchronized");
    expect(r.peak_transition).toBe(1);
    expect(r.peak_count).toBe(2);
    expect(r.synchronized_count).toBe(1);
    expect(exposureSynchronized(r)).toBe(true);
  });

  it("does NOT flag two fronts crossing in DIFFERENT steps — each is an isolated crossing (gate clears)", async () => {
    // Cap crosses on step 1→2, Term crosses on step 2→3 — no single step has two crossings,
    // even though BOTH fronts are volatile to v24. Synchrony is per-step, not per-front.
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "below-acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
    ]);
    const r = await computeCoherenceSynchrony(rounds);
    expect(r.per_transition.map((t) => t.crossing_fronts)).toEqual([1, 1]);
    expect(r.per_transition.every((t) => t.synchrony === "isolated")).toBe(true);
    expect(r.synchronized_count).toBe(0);
    expect(r.peak_count).toBe(1);
    expect(exposureSynchronized(r)).toBe(false);
  });

  it("is the transpose of v24 — total_crossings equals the sum of every front's v24 crossings", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Term: "below-acceptable", Fee: "ideal" }, { Cap: "ideal", Term: "ideal", Fee: "ideal" }),
      mk({ Cap: "below-acceptable", Term: "acceptable", Fee: "ideal" }, { Cap: "ideal", Term: "ideal", Fee: "ideal" }),
      mk({ Cap: "acceptable", Term: "below-acceptable", Fee: "below-acceptable" }, { Cap: "ideal", Term: "ideal", Fee: "ideal" }),
    ]);
    const sync = await computeCoherenceSynchrony(rounds);
    const vol = await computeCoherenceVolatility(rounds);
    const perFrontTotal = vol.fronts.reduce((sum, f) => sum + f.crossings, 0);
    expect(sync.total_crossings).toBe(perFrontTotal);
    // And the per-step counts must sum to that same total.
    expect(sync.per_transition.reduce((s, t) => s + t.crossing_fronts, 0)).toBe(perFrontTotal);
  });

  it("attributes a crossing across silence to the step that REVEALS the new standing (§3)", async () => {
    // below → unstated → acceptable: the recovery is visible at round 3, so the crossing
    // belongs to step 2→3, never the silent step 1→2.
    const rounds = await Promise.all([
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "unevaluable" }, { Cap: "unevaluable" }),
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
    ]);
    const r = await computeCoherenceSynchrony(rounds);
    expect(r.per_transition[0]!.crossing_fronts).toBe(0); // silent step
    expect(r.per_transition[1]!.crossing_fronts).toBe(1); // revealing step
    expect(r.per_transition[1]!.crossed_dimensions).toEqual(["Cap"]);
    expect(r.total_crossings).toBe(1);
  });

  it("does not invent a crossing across a silent gap that returns to the same side — below → unstated → below is quiet (§3)", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "unevaluable" }, { Cap: "unevaluable" }),
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
    ]);
    const r = await computeCoherenceSynchrony(rounds);
    expect(r.total_crossings).toBe(0);
    expect(r.per_transition.every((t) => t.synchrony === "quiet")).toBe(true);
    expect(r.peak_transition).toBeNull();
    expect(r.peak_count).toBe(0);
  });

  it("an above-floor whipsaw never crosses the floor — acceptable → ideal → acceptable is all-quiet (distinct from v17)", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "ideal" }, { Cap: "ideal" }),
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
    ]);
    const r = await computeCoherenceSynchrony(rounds);
    expect(r.total_crossings).toBe(0);
    expect(exposureSynchronized(r)).toBe(false);
  });

  it("names the peak step (the most simultaneous crossings), earliest on a tie", async () => {
    // step 1→2: Cap+Term fall (2). step 2→3: Cap recovers, Fee falls (2 — a tie). step 3→4: Term recovers (1).
    // Both step 1→2 and step 2→3 have 2 crossings; the earliest (step 1→2) wins.
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Term: "acceptable", Fee: "acceptable" }, { Cap: "ideal", Term: "ideal", Fee: "ideal" }),
      mk({ Cap: "below-acceptable", Term: "below-acceptable", Fee: "acceptable" }, { Cap: "ideal", Term: "ideal", Fee: "ideal" }),
      mk({ Cap: "acceptable", Term: "below-acceptable", Fee: "below-acceptable" }, { Cap: "ideal", Term: "ideal", Fee: "ideal" }),
      mk({ Cap: "acceptable", Term: "acceptable", Fee: "below-acceptable" }, { Cap: "ideal", Term: "ideal", Fee: "ideal" }),
    ]);
    const r = await computeCoherenceSynchrony(rounds);
    expect(r.per_transition.map((t) => t.crossing_fronts)).toEqual([2, 2, 1]);
    expect(r.peak_transition).toBe(1); // earliest of the two tied peaks
    expect(r.peak_count).toBe(2);
    expect(r.synchronized_count).toBe(2);
  });

  it("reports peak_transition null and peak_count 0 when no front ever crossed the floor", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "ideal", Risk: "acceptable" }, { Cap: "acceptable", Risk: "ideal" }),
      mk({ Cap: "ideal", Risk: "ideal" }, { Cap: "acceptable", Risk: "acceptable" }),
    ]);
    const r = await computeCoherenceSynchrony(rounds);
    expect(r.peak_transition).toBeNull();
    expect(r.peak_count).toBe(0);
    expect(r.synchronized_count).toBe(0);
    expect(r.total_crossings).toBe(0);
  });

  it("ignores an unstated front entirely (silence is not exposure, §3)", async () => {
    const gapRound = () => mk({ Gap: "unevaluable" }, { Gap: "unevaluable" });
    const r = await computeCoherenceSynchrony([await gapRound(), await gapRound()]);
    expect(r.total_crossings).toBe(0);
    expect(r.per_transition[0]!.crossed_dimensions).toEqual([]);
  });

  it("is deterministic: identical rounds in identical order → identical synchrony_hash", async () => {
    const build = () =>
      Promise.all([
        mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
        mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
      ]);
    const a = await computeCoherenceSynchrony(await build());
    const c = await computeCoherenceSynchrony(await build());
    expect(a.synchrony_hash).toBe(c.synchrony_hash);
    expect(a.synchrony_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("throws on fewer than two rounds", async () => {
    const rounds = [await mk({ Cap: "ideal" }, { Cap: "ideal" })];
    await expect(computeCoherenceSynchrony(rounds)).rejects.toThrow(/at least two rounds/);
  });

  it("renders the peak step, the synchronized steps, and stable JSON", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
    ]);
    const r = await computeCoherenceSynchrony(rounds);
    const summary = renderCoherenceSynchronySummary(r);
    expect(summary).toContain("Coherence exposure synchrony across 2 rounds");
    expect(summary).toMatch(/peak step: round 1→2 \(2 fronts crossed the floor at once\)/);
    expect(summary).toMatch(/synchronized steps \(≥2 fronts crossing at once\): 1 of 1/);
    expect(summary).toMatch(/⚠ round 1→2: 2 fronts crossed \(Cap, Term\)/);
    expect(summary).toMatch(/synchrony_hash: [0-9a-f]{64}/);

    const json = JSON.parse(buildCoherenceSynchronyJson(r));
    expect(json.schema).toBe("vaulytica.posture-synchrony.v1");
    expect(json.synchrony_hash).toBe(r.synchrony_hash);
    expect(json.rounds).toBe(2);
    expect(json.total_crossings).toBe(2);
    expect(json.peak_transition).toBe(1);
    expect(json.synchronized_count).toBe(1);
    expect(json.per_transition[0].crossing_fronts).toBe(2);
  });
});
