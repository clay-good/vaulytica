import { describe, expect, it } from "vitest";
import {
  computeCoherenceConcurrency,
  exposureConcerted,
  buildCoherenceConcurrencyJson,
  renderCoherenceConcurrencySummary,
} from "./coherence-concurrency.js";
import { computeCoherenceVolatility } from "./coherence-volatility.js";
import { computeCoherenceSynchrony } from "./coherence-synchrony.js";
import { computeCoherenceLatency } from "./coherence-latency.js";
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

describe("computeCoherenceConcurrency (spec-v29 — direction-resolved per-step crossings)", () => {
  it("flags a concerted fall — two fronts fall below floor in the same step (gate trips)", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk(
        { Cap: "below-acceptable", Term: "below-acceptable" }, // both fall → step 1→2
        { Cap: "ideal", Term: "ideal" },
      ),
    ]);
    const r = await computeCoherenceConcurrency(rounds);
    const step = r.per_transition[0]!;
    expect(step.falling).toBe(2);
    expect(step.recovering).toBe(0);
    expect(step.falling_dimensions).toEqual(["Cap", "Term"]);
    expect(step.concurrency).toBe("concerted-fall");
    expect(r.concerted_fall_count).toBe(1);
    expect(r.peak_fall_transition).toBe(1);
    expect(r.peak_fall_count).toBe(2);
    expect(r.concerted).toBe(true);
    expect(exposureConcerted(r)).toBe(true);
  });

  it("separates a concerted fall from a churn that v25 reports identically (same crossing count)", async () => {
    // Step 1→2: Cap and Term both FALL (a coordinated collapse — two crossings).
    // Step 2→3: Dog falls while Ewe recovers (a churn — both directions, two crossings).
    // To v25 both steps are "synchronized" (two crossings each); to v29 they differ.
    const rounds = await Promise.all([
      mk(
        { Cap: "acceptable", Term: "acceptable", Dog: "acceptable", Ewe: "below-acceptable" },
        { Cap: "ideal", Term: "ideal", Dog: "ideal", Ewe: "ideal" },
      ),
      mk(
        {
          Cap: "below-acceptable",
          Term: "below-acceptable",
          Dog: "acceptable",
          Ewe: "below-acceptable",
        },
        { Cap: "ideal", Term: "ideal", Dog: "ideal", Ewe: "ideal" },
      ),
      mk(
        {
          Cap: "below-acceptable",
          Term: "below-acceptable",
          Dog: "below-acceptable",
          Ewe: "acceptable",
        },
        { Cap: "ideal", Term: "ideal", Dog: "ideal", Ewe: "ideal" },
      ),
    ]);
    const r = await computeCoherenceConcurrency(rounds);
    const sync = await computeCoherenceSynchrony(rounds);
    // To v25 both steps are synchronized (two fronts crossed each step).
    expect(sync.per_transition[0]!.synchrony).toBe("synchronized");
    expect(sync.per_transition[1]!.synchrony).toBe("synchronized");
    // To v29 step 1 is a concerted fall, step 2 is a churn (one fell, one recovered).
    expect(r.per_transition[0]!.concurrency).toBe("concerted-fall");
    expect(r.per_transition[0]!.falling).toBe(2);
    expect(r.per_transition[1]!.concurrency).toBe("mixed");
    expect(r.per_transition[1]!.falling).toBe(1);
    expect(r.per_transition[1]!.recovering).toBe(1);
    expect(r.concerted_fall_count).toBe(1);
    expect(r.mixed_count).toBe(1);
  });

  it("classifies a concerted recovery — two fronts recover in the same step (no concerted fall)", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // both recover
    ]);
    const r = await computeCoherenceConcurrency(rounds);
    expect(r.per_transition[0]!.concurrency).toBe("concerted-fall");
    expect(r.per_transition[1]!.concurrency).toBe("concerted-recovery");
    expect(r.per_transition[1]!.recovering).toBe(2);
    expect(r.per_transition[1]!.recovering_dimensions).toEqual(["Cap", "Term"]);
    expect(r.concerted_recovery_count).toBe(1);
  });

  it("a concerted fall dominates even when a recovery also happens that step", async () => {
    // Step 1→2: Cap and Term fall, Fee recovers — three crossings, two falls → concerted-fall.
    const rounds = await Promise.all([
      mk(
        { Cap: "acceptable", Term: "acceptable", Fee: "below-acceptable" },
        { Cap: "ideal", Term: "ideal", Fee: "ideal" },
      ),
      mk(
        { Cap: "below-acceptable", Term: "below-acceptable", Fee: "acceptable" },
        { Cap: "ideal", Term: "ideal", Fee: "ideal" },
      ),
    ]);
    const r = await computeCoherenceConcurrency(rounds);
    const step = r.per_transition[0]!;
    expect(step.falling).toBe(2);
    expect(step.recovering).toBe(1);
    expect(step.concurrency).toBe("concerted-fall");
    expect(r.concerted).toBe(true);
  });

  it("classifies an isolated single crossing", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "below-acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
    ]);
    const r = await computeCoherenceConcurrency(rounds);
    expect(r.per_transition[0]!.concurrency).toBe("isolated");
    expect(r.concerted).toBe(false);
    expect(exposureConcerted(r)).toBe(false);
  });

  it("is a reduction of the same crossings — total_crossings equals v24's, v25's, and v28's totals", async () => {
    const rounds = await Promise.all([
      mk(
        { Cap: "acceptable", Term: "below-acceptable", Fee: "ideal" },
        { Cap: "ideal", Term: "ideal", Fee: "ideal" },
      ),
      mk(
        { Cap: "below-acceptable", Term: "acceptable", Fee: "ideal" },
        { Cap: "ideal", Term: "ideal", Fee: "ideal" },
      ),
      mk(
        { Cap: "acceptable", Term: "below-acceptable", Fee: "below-acceptable" },
        { Cap: "ideal", Term: "ideal", Fee: "ideal" },
      ),
    ]);
    const conc = await computeCoherenceConcurrency(rounds);
    const vol = await computeCoherenceVolatility(rounds);
    const sync = await computeCoherenceSynchrony(rounds);
    const lat = await computeCoherenceLatency(rounds);
    const perFrontTotal = vol.fronts.reduce((sum, f) => sum + f.crossings, 0);
    expect(conc.total_crossings).toBe(perFrontTotal);
    expect(conc.total_crossings).toBe(sync.total_crossings);
    expect(conc.total_crossings).toBe(lat.total_crossings);
    // The direction split partitions the crossings exactly.
    expect(conc.total_falls + conc.total_recoveries).toBe(conc.total_crossings);
  });

  it("attributes a crossing across silence to the round that REVEALS it, never the silent step (§3)", async () => {
    // Cap: acceptable → unstated → below. The fall is visible at round 3, so it lands
    // on step 2→3 (per-transition index 1), never the silent step 1→2.
    const rounds = await Promise.all([
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "unevaluable" }, { Cap: "unevaluable" }),
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
    ]);
    const r = await computeCoherenceConcurrency(rounds);
    expect(r.per_transition[0]!.falling).toBe(0); // the silent step
    expect(r.per_transition[1]!.falling).toBe(1); // the revealing step
    expect(r.per_transition[1]!.falling_dimensions).toEqual(["Cap"]);
  });

  it("an above-floor whipsaw crosses the floor zero times — no fall, no recovery (distinct from v17)", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "ideal" }, { Cap: "ideal" }),
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
    ]);
    const r = await computeCoherenceConcurrency(rounds);
    expect(r.total_crossings).toBe(0);
    expect(r.total_falls).toBe(0);
    expect(r.peak_fall_transition).toBeNull();
    expect(r.concerted).toBe(false);
  });

  it("reports no peak fall step when no front ever fell below floor", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "ideal", Risk: "acceptable" }, { Cap: "acceptable", Risk: "ideal" }),
      mk({ Cap: "ideal", Risk: "ideal" }, { Cap: "acceptable", Risk: "acceptable" }),
    ]);
    const r = await computeCoherenceConcurrency(rounds);
    expect(r.peak_fall_transition).toBeNull();
    expect(r.peak_fall_count).toBe(0);
    expect(r.total_falls).toBe(0);
    expect(r.total_crossings).toBe(0);
  });

  it("picks the earliest peak fall step on a tie", async () => {
    // Two fronts fall together at step 1→2 and again at step 3→4; the earlier step wins.
    const rounds = await Promise.all([
      mk({ Aaa: "acceptable", Zzz: "acceptable" }, { Aaa: "ideal", Zzz: "ideal" }),
      mk({ Aaa: "below-acceptable", Zzz: "below-acceptable" }, { Aaa: "ideal", Zzz: "ideal" }),
      mk({ Aaa: "acceptable", Zzz: "acceptable" }, { Aaa: "ideal", Zzz: "ideal" }),
      mk({ Aaa: "below-acceptable", Zzz: "below-acceptable" }, { Aaa: "ideal", Zzz: "ideal" }),
    ]);
    const r = await computeCoherenceConcurrency(rounds);
    expect(r.peak_fall_count).toBe(2);
    expect(r.peak_fall_transition).toBe(1);
    expect(r.concerted_fall_count).toBe(2);
  });

  it("treats a silent round as quiet — neither a fall nor a recovery (§3)", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "unevaluable" }, { Cap: "unevaluable" }),
    ]);
    const r = await computeCoherenceConcurrency(rounds);
    expect(r.per_transition[0]!.concurrency).toBe("quiet");
    expect(r.total_crossings).toBe(0);
  });

  it("is deterministic: identical rounds in identical order → identical concurrency_hash", async () => {
    const build = () =>
      Promise.all([
        mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
        mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
        mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
      ]);
    const a = await computeCoherenceConcurrency(await build());
    const c = await computeCoherenceConcurrency(await build());
    expect(a.concurrency_hash).toBe(c.concurrency_hash);
    expect(a.concurrency_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("throws on fewer than two rounds", async () => {
    const rounds = [await mk({ Cap: "ideal" }, { Cap: "ideal" })];
    await expect(computeCoherenceConcurrency(rounds)).rejects.toThrow(/at least two rounds/);
  });

  it("renders the peak-fall verdict and stable JSON", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
    ]);
    const r = await computeCoherenceConcurrency(rounds);
    const summary = renderCoherenceConcurrencySummary(r);
    expect(summary).toContain("Coherence exposure concurrency across 2 rounds");
    expect(summary).toMatch(/peak fall step: round 1→2 \(2 fronts fell/);
    expect(summary).toMatch(/concerted falls \(≥2 fronts falling at once\): 1 of 1/);
    expect(summary).toMatch(/concurrency_hash: [0-9a-f]{64}/);

    const json = JSON.parse(buildCoherenceConcurrencyJson(r));
    expect(json.schema).toBe("vaulytica.posture-concurrency.v1");
    expect(json.concurrency_hash).toBe(r.concurrency_hash);
    expect(json.rounds).toBe(2);
    expect(json.total_crossings).toBe(2);
    expect(json.total_falls).toBe(2);
    expect(json.total_recoveries).toBe(0);
    expect(json.concerted).toBe(true);
    expect(json.per_transition[0].falling_dimensions).toEqual(["Cap", "Term"]);
  });

  it("renders a quiet/isolated deal without a concerted-fall mark", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
    ]);
    const summary = renderCoherenceConcurrencySummary(await computeCoherenceConcurrency(rounds));
    expect(summary).toMatch(/peak fall step: round 1→2 \(1 front fell/);
    expect(summary).toMatch(/concerted falls \(≥2 fronts falling at once\): 0 of 1/);
    expect(summary).toMatch(/\[isolated\]/);
  });
});
