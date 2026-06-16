import { describe, expect, it } from "vitest";
import {
  computeCoherenceLatency,
  exposureUnrecovered,
  buildCoherenceLatencyJson,
  renderCoherenceLatencySummary,
} from "./coherence-latency.js";
import { computeCoherenceVolatility } from "./coherence-volatility.js";
import { computeCoherenceSynchrony } from "./coherence-synchrony.js";
import { computeCoherenceSettling } from "./coherence-settling.js";
import { computeCoherenceOnset } from "./coherence-onset.js";
import { computeCoherencePersistence } from "./coherence-persistence.js";
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

describe("computeCoherenceLatency (spec-v28 — rounds below floor per fall-to-recovery episode)", () => {
  it("measures a prompt recovery — fell round 2, recovered round 3 (one round below)", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }), // fall → round 2
      mk({ Cap: "acceptable" }, { Cap: "ideal" }), // recovery → round 3
    ]);
    const r = await computeCoherenceLatency(rounds);
    const cap = r.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.episodes).toEqual([{ fall_round: 2, recovery_round: 3, latency: 1 }]);
    expect(cap.latency).toBe("recovered");
    expect(cap.max_latency).toBe(1);
    expect(r.max_latency).toBe(1);
    expect(r.slowest_dimension).toBe("Cap");
    expect(r.recovered_count).toBe(1);
    expect(r.open_count).toBe(0);
    expect(r.unrecovered).toBe(false);
    expect(exposureUnrecovered(r)).toBe(false);
  });

  it("separates a slow from a prompt recovery that v24 reports identically (same crossing count)", async () => {
    // Both fronts fall once and recover once — two crossings each, identical to v24 —
    // but Cap sits below floor for one round, Term for four.
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk(
        { Cap: "below-acceptable", Term: "below-acceptable" }, // both fall → round 2
        { Cap: "ideal", Term: "ideal" },
      ),
      mk(
        { Cap: "acceptable", Term: "below-acceptable" }, // Cap recovers → round 3
        { Cap: "ideal", Term: "ideal" },
      ),
      mk({ Cap: "acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk(
        { Cap: "acceptable", Term: "acceptable" }, // Term recovers → round 6
        { Cap: "ideal", Term: "ideal" },
      ),
    ]);
    const r = await computeCoherenceLatency(rounds);
    const vol = await computeCoherenceVolatility(rounds);
    // To v24 both fronts are identical: two crossings each.
    expect(vol.fronts.find((f) => f.dimension === "Cap")!.crossings).toBe(2);
    expect(vol.fronts.find((f) => f.dimension === "Term")!.crossings).toBe(2);
    // To v28 they differ by recovery latency.
    expect(r.fronts.find((f) => f.dimension === "Cap")!.max_latency).toBe(1);
    expect(r.fronts.find((f) => f.dimension === "Term")!.max_latency).toBe(4);
    expect(r.max_latency).toBe(4);
    expect(r.slowest_dimension).toBe("Term");
    expect(r.unrecovered).toBe(false);
  });

  it("flags an unrecovered episode — a fall that never closes (the gate trips)", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }), // fall → round 2, never recovers
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
    ]);
    const r = await computeCoherenceLatency(rounds);
    const cap = r.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.episodes).toEqual([{ fall_round: 2, recovery_round: null, latency: null }]);
    expect(cap.latency).toBe("open");
    expect(cap.max_latency).toBeNull();
    expect(r.open_count).toBe(1);
    expect(r.recovered_count).toBe(0);
    expect(r.unrecovered).toBe(true);
    expect(exposureUnrecovered(r)).toBe(true);
  });

  it("is distinct from v21: a front below from round 1 is `open` to v21 but has no episode here (no in-sequence fall)", async () => {
    // Cap is stated below from the very first round — its descent predates the archive.
    const rounds = await Promise.all([
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
    ]);
    const r = await computeCoherenceLatency(rounds);
    const persist = await computeCoherencePersistence(rounds);
    // v21 calls it open (current standing below floor).
    expect(persist.fronts.find((f) => f.dimension === "Cap")!.persistence).toBe("open");
    // v28 has no in-sequence fall to pair → no episode, `steady`, gate clears.
    const cap = r.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.episodes).toEqual([]);
    expect(cap.latency).toBe("steady");
    expect(r.open_count).toBe(0);
    expect(r.unrecovered).toBe(false);
    expect(r.total_crossings).toBe(0); // it never crossed in-sequence
  });

  it("treats a leading recovery as no episode — a front below from round 1 that recovers", async () => {
    // Cap below at round 1 (pre-archive descent), recovers round 2: a recovery crossing
    // with no in-sequence fall to pair → no episode, `steady`.
    const rounds = await Promise.all([
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
    ]);
    const r = await computeCoherenceLatency(rounds);
    const cap = r.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.crossings).toBe(1); // the recovery still counts toward total_crossings (v24 parity)
    expect(cap.episodes).toEqual([]);
    expect(cap.latency).toBe("steady");
    expect(r.recovered_count).toBe(0);
    expect(r.open_count).toBe(0);
  });

  it("is a reduction of the same crossings — total_crossings equals v24's, v25's, v26's, and v27's totals", async () => {
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
    const lat = await computeCoherenceLatency(rounds);
    const vol = await computeCoherenceVolatility(rounds);
    const sync = await computeCoherenceSynchrony(rounds);
    const settle = await computeCoherenceSettling(rounds);
    const onset = await computeCoherenceOnset(rounds);
    const perFrontTotal = vol.fronts.reduce((sum, f) => sum + f.crossings, 0);
    expect(lat.total_crossings).toBe(perFrontTotal);
    expect(lat.total_crossings).toBe(sync.total_crossings);
    expect(lat.total_crossings).toBe(settle.total_crossings);
    expect(lat.total_crossings).toBe(onset.total_crossings);
  });

  it("picks the slowest recovery across many fronts (earliest dimension on a tie)", async () => {
    // Aaa and Zzz both recover after 2 rounds below; the earlier dimension wins the tie.
    const rounds = await Promise.all([
      mk({ Aaa: "acceptable", Zzz: "acceptable" }, { Aaa: "ideal", Zzz: "ideal" }),
      mk({ Aaa: "below-acceptable", Zzz: "below-acceptable" }, { Aaa: "ideal", Zzz: "ideal" }),
      mk({ Aaa: "below-acceptable", Zzz: "below-acceptable" }, { Aaa: "ideal", Zzz: "ideal" }),
      mk({ Aaa: "acceptable", Zzz: "acceptable" }, { Aaa: "ideal", Zzz: "ideal" }),
    ]);
    const r = await computeCoherenceLatency(rounds);
    expect(r.max_latency).toBe(2);
    expect(r.slowest_dimension).toBe("Aaa");
  });

  it("silence inside a gap does not reset the standing; the span is measured to the revealing round (§3)", async () => {
    // Cap falls round 2, is unstated round 3, recovers round 4: it sat below across the
    // silent round (last known standing = below), recovery lands on the revealing round.
    const rounds = await Promise.all([
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }), // fall → round 2
      mk({ Cap: "unevaluable" }, { Cap: "unevaluable" }), // silent: not a recovery
      mk({ Cap: "acceptable" }, { Cap: "ideal" }), // recovery revealed → round 4
    ]);
    const r = await computeCoherenceLatency(rounds);
    const cap = r.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.episodes).toEqual([{ fall_round: 2, recovery_round: 4, latency: 2 }]);
    expect(r.total_crossings).toBe(2);
  });

  it("attributes a fall across silence to the round that REVEALS it, never the silent step (§3)", async () => {
    // acceptable → unstated → below: the fall is visible at round 3, so the episode opens there.
    const rounds = await Promise.all([
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "unevaluable" }, { Cap: "unevaluable" }),
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
    ]);
    const r = await computeCoherenceLatency(rounds);
    const cap = r.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.episodes).toEqual([{ fall_round: 3, recovery_round: null, latency: null }]);
    expect(cap.latency).toBe("open");
  });

  it("an above-floor whipsaw never crosses the floor — no episode (distinct from v17)", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "ideal" }, { Cap: "ideal" }),
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
    ]);
    const r = await computeCoherenceLatency(rounds);
    expect(r.total_crossings).toBe(0);
    expect(r.fronts.find((f) => f.dimension === "Cap")!.episodes).toEqual([]);
    expect(r.max_latency).toBeNull();
    expect(r.unrecovered).toBe(false);
  });

  it("reports no episode and max_latency null when no front ever fell below floor", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "ideal", Risk: "acceptable" }, { Cap: "acceptable", Risk: "ideal" }),
      mk({ Cap: "ideal", Risk: "ideal" }, { Cap: "acceptable", Risk: "acceptable" }),
    ]);
    const r = await computeCoherenceLatency(rounds);
    expect(r.max_latency).toBeNull();
    expect(r.slowest_dimension).toBeNull();
    expect(r.recovered_count).toBe(0);
    expect(r.open_count).toBe(0);
    expect(r.total_crossings).toBe(0);
  });

  it("ignores an unstated front entirely (silence is not exposure, §3)", async () => {
    const gapRound = () => mk({ Gap: "unevaluable" }, { Gap: "unevaluable" });
    const r = await computeCoherenceLatency([await gapRound(), await gapRound()]);
    expect(r.total_crossings).toBe(0);
    expect(r.fronts.find((f) => f.dimension === "Gap")!.latency).toBe("unstated");
    expect(r.class_counts.unstated).toBe(1);
  });

  it("handles two episodes on one front — a recovered then an unrecovered fall", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }), // fall → round 2
      mk({ Cap: "acceptable" }, { Cap: "ideal" }), // recovery → round 3 (latency 1)
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }), // fall → round 4, never recovers
    ]);
    const r = await computeCoherenceLatency(rounds);
    const cap = r.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.episodes).toEqual([
      { fall_round: 2, recovery_round: 3, latency: 1 },
      { fall_round: 4, recovery_round: null, latency: null },
    ]);
    expect(cap.latency).toBe("open"); // an open episode dominates the class
    expect(cap.max_latency).toBe(1); // the closed episode's latency
    expect(r.recovered_count).toBe(1);
    expect(r.open_count).toBe(1);
    expect(r.unrecovered).toBe(true);
  });

  it("is deterministic: identical rounds in identical order → identical latency_hash", async () => {
    const build = () =>
      Promise.all([
        mk({ Cap: "acceptable" }, { Cap: "ideal" }),
        mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
        mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      ]);
    const a = await computeCoherenceLatency(await build());
    const c = await computeCoherenceLatency(await build());
    expect(a.latency_hash).toBe(c.latency_hash);
    expect(a.latency_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("throws on fewer than two rounds", async () => {
    const rounds = [await mk({ Cap: "ideal" }, { Cap: "ideal" })];
    await expect(computeCoherenceLatency(rounds)).rejects.toThrow(/at least two rounds/);
  });

  it("renders the slowest-recovery verdict and stable JSON", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
    ]);
    const r = await computeCoherenceLatency(rounds);
    const summary = renderCoherenceLatencySummary(r);
    expect(summary).toContain("Coherence exposure recovery latency across 3 rounds");
    expect(summary).toMatch(/slowest recovery: Cap — sat below floor for 1 round/);
    expect(summary).toMatch(/1 recovered, 0 unrecovered/);
    expect(summary).toMatch(/latency_hash: [0-9a-f]{64}/);

    const json = JSON.parse(buildCoherenceLatencyJson(r));
    expect(json.schema).toBe("vaulytica.posture-latency.v1");
    expect(json.latency_hash).toBe(r.latency_hash);
    expect(json.rounds).toBe(3);
    expect(json.total_crossings).toBe(2);
    expect(json.max_latency).toBe(1);
    expect(json.slowest_dimension).toBe("Cap");
    expect(json.open_count).toBe(0);
    expect(json.fronts[0].episodes[0]).toEqual({
      fall_round: 2,
      recovery_round: 3,
      latency: 1,
    });
  });

  it("renders an unrecovered episode distinctly", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
    ]);
    const summary = renderCoherenceLatencySummary(await computeCoherenceLatency(rounds));
    expect(summary).toMatch(/never recovered/);
    expect(summary).toMatch(/1 unrecovered/);
  });
});
