import { describe, expect, it } from "vitest";
import {
  computeCoherenceVolatility,
  exposureVolatile,
  buildCoherenceVolatilityJson,
  renderCoherenceVolatilitySummary,
} from "./coherence-volatility.js";
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

describe("computeCoherenceVolatility (spec-v24 — per-front floor crossings)", () => {
  it("distinguishes a bounced front (2 crossings, volatile) from a stuck front (0 crossings, stable) — both `single` to v23", async () => {
    // Term: acceptable → below → acceptable = fell and cleanly recovered (2 crossings).
    // Cap:  below → below → below = never moved (0 crossings).
    // To v23 both are ONE below-floor episode (`single`); only the crossing count separates them.
    const rounds = await Promise.all([
      mk({ Term: "acceptable", Cap: "below-acceptable" }, { Term: "ideal", Cap: "ideal" }),
      mk({ Term: "below-acceptable", Cap: "below-acceptable" }, { Term: "ideal", Cap: "ideal" }),
      mk({ Term: "acceptable", Cap: "below-acceptable" }, { Term: "ideal", Cap: "ideal" }),
    ]);
    const r = await computeCoherenceVolatility(rounds);
    const term = r.fronts.find((f) => f.dimension === "Term")!;
    const cap = r.fronts.find((f) => f.dimension === "Cap")!;
    expect(term.crossings).toBe(2);
    expect(term.volatility).toBe("volatile");
    expect(cap.crossings).toBe(0);
    expect(cap.volatility).toBe("stable");
    expect(r.volatile_count).toBe(1);
    expect(exposureVolatile(r)).toBe(true);
  });

  it("counts a single fall as one crossing (monotone, gate clears)", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
    ]);
    const r = await computeCoherenceVolatility(rounds);
    const cap = r.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.crossings).toBe(1);
    expect(cap.volatility).toBe("monotone");
    expect(exposureVolatile(r)).toBe(false);
  });

  it("does not let silence count as a crossing — below → unstated → below is ZERO crossings (§3)", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "unevaluable" }, { Cap: "unevaluable" }),
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
    ]);
    const r = await computeCoherenceVolatility(rounds);
    const cap = r.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.crossings).toBe(0);
    expect(cap.volatility).toBe("stable");
    expect(exposureVolatile(r)).toBe(false);
  });

  it("counts a recovery across silence as one crossing — below → unstated → acceptable is ONE crossing (§3)", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "unevaluable" }, { Cap: "unevaluable" }),
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
    ]);
    const r = await computeCoherenceVolatility(rounds);
    const cap = r.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.crossings).toBe(1);
    expect(cap.volatility).toBe("monotone");
  });

  it("a recover-then-relapse crosses the floor twice (volatile)", async () => {
    // below → acceptable → below: down-cross at start? no — starts below, so: recovery (1), relapse (2).
    const rounds = await Promise.all([
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
    ]);
    const r = await computeCoherenceVolatility(rounds);
    const cap = r.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.crossings).toBe(2);
    expect(cap.volatility).toBe("volatile");
    expect(exposureVolatile(r)).toBe(true);
  });

  it("an above-floor whipsaw never crosses the floor — acceptable → ideal → acceptable is STABLE (distinct from v17's whipsaw)", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "ideal" }, { Cap: "ideal" }),
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
    ]);
    const r = await computeCoherenceVolatility(rounds);
    const cap = r.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.crossings).toBe(0);
    expect(cap.volatility).toBe("stable");
    expect(cap.rounds_below).toBe(0);
    expect(exposureVolatile(r)).toBe(false);
  });

  it("identifies the most volatile front (the most crossings), earliest on a tie", async () => {
    // Apex: below→acc→below→acc→below = 4 crossings. Beta: acc→below→acc = 2 crossings.
    const rounds = await Promise.all([
      mk({ Apex: "below-acceptable", Beta: "acceptable" }, { Apex: "ideal", Beta: "ideal" }),
      mk({ Apex: "acceptable", Beta: "below-acceptable" }, { Apex: "ideal", Beta: "ideal" }),
      mk({ Apex: "below-acceptable", Beta: "acceptable" }, { Apex: "ideal", Beta: "ideal" }),
      mk({ Apex: "acceptable", Beta: "ideal" }, { Apex: "ideal", Beta: "ideal" }),
      mk({ Apex: "below-acceptable", Beta: "ideal" }, { Apex: "ideal", Beta: "ideal" }),
    ]);
    const r = await computeCoherenceVolatility(rounds);
    expect(r.most_volatile_dimension).toBe("Apex");
    expect(r.max_crossings).toBe(4);
  });

  it("does not count an unstated front (silence is not exposure, §3)", async () => {
    const gapRound = () => mk({ Gap: "unevaluable" }, { Gap: "unevaluable" });
    const r = await computeCoherenceVolatility([await gapRound(), await gapRound()]);
    const gap = r.fronts.find((f) => f.dimension === "Gap")!;
    expect(gap.volatility).toBe("unstated");
    expect(gap.crossings).toBe(0);
    expect(r.class_counts.unstated).toBe(1);
  });

  it("reports max_crossings 0 and most_volatile null when no front ever crossed the floor", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "ideal", Risk: "acceptable" }, { Cap: "acceptable", Risk: "ideal" }),
      mk({ Cap: "ideal", Risk: "ideal" }, { Cap: "acceptable", Risk: "acceptable" }),
    ]);
    const r = await computeCoherenceVolatility(rounds);
    expect(r.max_crossings).toBe(0);
    expect(r.most_volatile_dimension).toBeNull();
    expect(r.volatile_count).toBe(0);
    expect(r.class_counts.stable).toBe(2);
  });

  it("is deterministic: identical rounds in identical order → identical volatility_hash", async () => {
    const build = () =>
      Promise.all([
        mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
        mk({ Cap: "acceptable" }, { Cap: "ideal" }),
        mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
      ]);
    const a = await computeCoherenceVolatility(await build());
    const c = await computeCoherenceVolatility(await build());
    expect(a.volatility_hash).toBe(c.volatility_hash);
    expect(a.volatility_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("throws on fewer than two rounds", async () => {
    const rounds = [await mk({ Cap: "ideal" }, { Cap: "ideal" })];
    await expect(computeCoherenceVolatility(rounds)).rejects.toThrow(/at least two rounds/);
  });

  it("renders the volatile fronts, their crossings, and stable JSON", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
    ]);
    const r = await computeCoherenceVolatility(rounds);
    const summary = renderCoherenceVolatilitySummary(r);
    expect(summary).toContain("Coherence exposure volatility across 3 rounds");
    expect(summary).toMatch(/1 volatile \(standing reversed across floor\)/);
    expect(summary).toMatch(/⚠ Cap: volatile — its standing crossed the floor 2 times/);
    expect(summary).toMatch(/volatility_hash: [0-9a-f]{64}/);

    const json = JSON.parse(buildCoherenceVolatilityJson(r));
    expect(json.schema).toBe("vaulytica.posture-volatility.v1");
    expect(json.volatility_hash).toBe(r.volatility_hash);
    expect(json.rounds).toBe(3);
    expect(json.volatile_count).toBe(1);
    expect(json.most_volatile_dimension).toBe("Cap");
    expect(json.fronts[0].crossings).toBe(2);
  });
});
