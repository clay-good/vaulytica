import { describe, expect, it } from "vitest";
import {
  computeCoherenceBreadth,
  exposureWidened,
  buildCoherenceBreadthJson,
  renderCoherenceBreadthSummary,
} from "./coherence-breadth.js";
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

describe("computeCoherenceBreadth (spec-v22 — per-round deal standing)", () => {
  it("counts fronts below floor in each round and names them", async () => {
    // Round 1: Cap below floor. Round 2: Cap + Risk below floor.
    const rounds = await Promise.all([
      mk(
        { Cap: "below-acceptable", Law: "ideal", Risk: "acceptable" },
        { Cap: "ideal", Law: "ideal", Risk: "ideal" },
      ),
      mk(
        { Cap: "below-acceptable", Law: "ideal", Risk: "below-acceptable" },
        { Cap: "ideal", Law: "ideal", Risk: "ideal" },
      ),
    ]);
    const b = await computeCoherenceBreadth(rounds);
    expect(b.rounds).toBe(2);
    expect(b.per_round[0]!.exposed_fronts).toBe(1);
    expect(b.per_round[0]!.exposed_dimensions).toEqual(["Cap"]);
    expect(b.per_round[0]!.stated_fronts).toBe(3);
    expect(b.per_round[1]!.exposed_fronts).toBe(2);
    expect(b.per_round[1]!.exposed_dimensions).toEqual(["Cap", "Risk"]); // localeCompare-pinned
  });

  it("identifies the worst round (most fronts below floor at once), earliest on a tie", async () => {
    // Breadth path: 1 → 3 → 3 → 1. Worst is round 2 (first to reach 3), not round 3.
    const rounds = await Promise.all([
      mk(
        { Cap: "below-acceptable", Law: "ideal", Risk: "ideal" },
        { Cap: "ideal", Law: "ideal", Risk: "ideal" },
      ),
      mk(
        { Cap: "below-acceptable", Law: "below-acceptable", Risk: "below-acceptable" },
        { Cap: "ideal", Law: "ideal", Risk: "ideal" },
      ),
      mk(
        { Cap: "below-acceptable", Law: "below-acceptable", Risk: "below-acceptable" },
        { Cap: "ideal", Law: "ideal", Risk: "ideal" },
      ),
      mk(
        { Cap: "below-acceptable", Law: "ideal", Risk: "ideal" },
        { Cap: "ideal", Law: "ideal", Risk: "ideal" },
      ),
    ]);
    const b = await computeCoherenceBreadth(rounds);
    expect(b.worst_round).toBe(2);
    expect(b.worst_count).toBe(3);
  });

  it("flags a widening deal: more fronts below floor at the latest round than the first", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "below-acceptable", Risk: "ideal" }, { Cap: "ideal", Risk: "ideal" }),
      mk({ Cap: "below-acceptable", Risk: "below-acceptable" }, { Cap: "ideal", Risk: "ideal" }),
    ]);
    const b = await computeCoherenceBreadth(rounds);
    expect(b.first_count).toBe(1);
    expect(b.latest_count).toBe(2);
    expect(b.widened).toBe(true);
    expect(exposureWidened(b)).toBe(true);
  });

  it("does NOT flag a narrowing deal: fewer fronts below floor at the latest round (gate clears)", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "below-acceptable", Risk: "below-acceptable" }, { Cap: "ideal", Risk: "ideal" }),
      mk({ Cap: "below-acceptable", Risk: "acceptable" }, { Cap: "ideal", Risk: "ideal" }),
    ]);
    const b = await computeCoherenceBreadth(rounds);
    expect(b.first_count).toBe(2);
    expect(b.latest_count).toBe(1);
    expect(b.widened).toBe(false);
    expect(exposureWidened(b)).toBe(false);
  });

  it("does NOT flag a flat-but-broad deal (same count first and latest), even if persistently exposed", async () => {
    // Two fronts below floor in BOTH rounds — exposure held, did not widen.
    const rounds = await Promise.all([
      mk({ Cap: "below-acceptable", Risk: "below-acceptable" }, { Cap: "ideal", Risk: "ideal" }),
      mk({ Cap: "below-acceptable", Risk: "below-acceptable" }, { Cap: "ideal", Risk: "ideal" }),
    ]);
    const b = await computeCoherenceBreadth(rounds);
    expect(b.widened).toBe(false); // 2 → 2 is not strictly greater
    expect(b.worst_count).toBe(2);
  });

  it("does not count an unstated front as below floor (silence is not exposure, §3)", async () => {
    // `Gap` is `unevaluable` in every document → no binding floor → never counted.
    const gapRound = () =>
      mk(
        { Cap: "below-acceptable", Gap: "unevaluable" },
        { Cap: "below-acceptable", Gap: "unevaluable" },
      );
    const b = await computeCoherenceBreadth([await gapRound(), await gapRound()]);
    expect(b.per_round[0]!.exposed_fronts).toBe(1); // only Cap
    expect(b.per_round[0]!.stated_fronts).toBe(1); // Gap is unstated
    expect(b.per_round[0]!.exposed_dimensions).toEqual(["Cap"]);
  });

  it("reports worst_round null and worst_count 0 when no front was ever below floor", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "ideal", Risk: "acceptable" }, { Cap: "acceptable", Risk: "ideal" }),
      mk({ Cap: "ideal", Risk: "ideal" }, { Cap: "acceptable", Risk: "acceptable" }),
    ]);
    const b = await computeCoherenceBreadth(rounds);
    expect(b.worst_round).toBeNull();
    expect(b.worst_count).toBe(0);
    expect(b.widened).toBe(false);
  });

  it("is deterministic: identical rounds in identical order → identical breadth_hash", async () => {
    const build = () =>
      Promise.all([
        mk({ Cap: "below-acceptable", Risk: "ideal" }, { Cap: "ideal", Risk: "ideal" }),
        mk({ Cap: "below-acceptable", Risk: "below-acceptable" }, { Cap: "ideal", Risk: "ideal" }),
      ]);
    const a = await computeCoherenceBreadth(await build());
    const c = await computeCoherenceBreadth(await build());
    expect(a.breadth_hash).toBe(c.breadth_hash);
    expect(a.breadth_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("throws on fewer than two rounds", async () => {
    const rounds = [await mk({ Cap: "ideal" }, { Cap: "ideal" })];
    await expect(computeCoherenceBreadth(rounds)).rejects.toThrow(/at least two rounds/);
  });

  it("renders the per-round series, the worst round, the trend, and stable JSON", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "below-acceptable", Risk: "ideal" }, { Cap: "ideal", Risk: "ideal" }),
      mk({ Cap: "below-acceptable", Risk: "below-acceptable" }, { Cap: "ideal", Risk: "ideal" }),
    ]);
    const b = await computeCoherenceBreadth(rounds);
    const summary = renderCoherenceBreadthSummary(b);
    expect(summary).toContain("Coherence exposure breadth across 2 rounds");
    expect(summary).toMatch(/exposure widened \(1 → 2 fronts below floor\)/);
    expect(summary).toMatch(/worst round: round 2 \(2 fronts below floor at once\)/);
    expect(summary).toMatch(/round 1: 1 of 2 stated fronts below floor \(Cap\)/);
    expect(summary).toMatch(/round 2: 2 of 2 stated fronts below floor \(Cap, Risk\)/);
    expect(summary).toMatch(/breadth_hash: [0-9a-f]{64}/);

    const json = JSON.parse(buildCoherenceBreadthJson(b));
    expect(json.schema).toBe("vaulytica.posture-breadth.v1");
    expect(json.breadth_hash).toBe(b.breadth_hash);
    expect(json.rounds).toBe(2);
    expect(json.worst_round).toBe(2);
    expect(json.widened).toBe(true);
    expect(json.per_round[1].exposed_dimensions).toEqual(["Cap", "Risk"]);
  });
});
