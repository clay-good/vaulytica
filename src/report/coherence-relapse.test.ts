import { describe, expect, it } from "vitest";
import {
  computeCoherenceRelapse,
  exposureImmediateRelapse,
  buildCoherenceRelapseJson,
  renderCoherenceRelapseSummary,
} from "./coherence-relapse.js";
import { computeCoherenceVolatility } from "./coherence-volatility.js";
import { computeCoherenceSynchrony } from "./coherence-synchrony.js";
import { computeCoherenceLatency } from "./coherence-latency.js";
import { computeCoherenceConcurrency } from "./coherence-concurrency.js";
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

describe("computeCoherenceRelapse (spec-v30 — rounds above floor per recovery-to-relapse span)", () => {
  it("measures an immediate relapse — recovered round 3, fell again round 4 (one round above)", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }), // fall → round 2 (first fall, no interval)
      mk({ Cap: "acceptable" }, { Cap: "ideal" }), // recovery → round 3 (opens interval)
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }), // fall → round 4 (relapse, clean_rounds 1)
    ]);
    const r = await computeCoherenceRelapse(rounds);
    const cap = r.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.intervals).toEqual([{ recovery_round: 3, fall_round: 4, clean_rounds: 1 }]);
    expect(cap.relapse).toBe("relapsed");
    expect(cap.min_interval).toBe(1);
    expect(r.min_interval).toBe(1);
    expect(r.quickest_dimension).toBe("Cap");
    expect(r.relapse_count).toBe(1);
    expect(r.held_count).toBe(0);
    expect(r.immediate).toBe(true);
    expect(exposureImmediateRelapse(r)).toBe(true);
  });

  it("separates a durable fix from a fix that did not hold that v24 reports identically (same crossing count)", async () => {
    // Both fronts fall, recover, fall again — three crossings each, identical to v24 —
    // but Cap holds above floor for one round before relapsing, Term for three.
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk(
        { Cap: "below-acceptable", Term: "below-acceptable" }, // both fall → round 2
        { Cap: "ideal", Term: "ideal" },
      ),
      mk(
        { Cap: "acceptable", Term: "acceptable" }, // both recover → round 3
        { Cap: "ideal", Term: "ideal" },
      ),
      mk(
        { Cap: "below-acceptable", Term: "acceptable" }, // Cap relapses → round 4 (held 1 round)
        { Cap: "ideal", Term: "ideal" },
      ),
      mk({ Cap: "below-acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk(
        { Cap: "below-acceptable", Term: "below-acceptable" }, // Term relapses → round 6 (held 3 rounds)
        { Cap: "ideal", Term: "ideal" },
      ),
    ]);
    const r = await computeCoherenceRelapse(rounds);
    const vol = await computeCoherenceVolatility(rounds);
    // To v24 both fronts are identical: three crossings each (fall, recover, fall).
    expect(vol.fronts.find((f) => f.dimension === "Cap")!.crossings).toBe(3);
    expect(vol.fronts.find((f) => f.dimension === "Term")!.crossings).toBe(3);
    // To v30 they differ by relapse interval.
    expect(r.fronts.find((f) => f.dimension === "Cap")!.min_interval).toBe(1);
    expect(r.fronts.find((f) => f.dimension === "Term")!.min_interval).toBe(3);
    expect(r.min_interval).toBe(1);
    expect(r.quickest_dimension).toBe("Cap");
    expect(r.immediate).toBe(true);
  });

  it("a recovery that holds (never undone) is an open interval — `held`, gate clears", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "acceptable" }, { Cap: "ideal" }), // recovery → round 2, never falls again
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
    ]);
    const r = await computeCoherenceRelapse(rounds);
    const cap = r.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.intervals).toEqual([{ recovery_round: 2, fall_round: null, clean_rounds: null }]);
    expect(cap.relapse).toBe("held");
    expect(cap.min_interval).toBeNull();
    expect(r.held_count).toBe(1);
    expect(r.relapse_count).toBe(0);
    expect(r.immediate).toBe(false);
    expect(exposureImmediateRelapse(r)).toBe(false);
  });

  it("is the mirror of v28: a fall that never recovered is `open` to v28 but `steady` here (no recovery to pair forward)", async () => {
    // Cap falls round 2 and never recovers: v28 has an open episode; v30 has no recovery
    // crossing to pair forward, so no interval — `steady`.
    const rounds = await Promise.all([
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
    ]);
    const r = await computeCoherenceRelapse(rounds);
    const lat = await computeCoherenceLatency(rounds);
    // v28 calls it open (a fall that never recovered).
    expect(lat.fronts.find((f) => f.dimension === "Cap")!.latency).toBe("open");
    // v30 has no recovery to pair forward → no interval, `steady`, gate clears.
    const cap = r.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.intervals).toEqual([]);
    expect(cap.relapse).toBe("steady");
    expect(r.relapse_count).toBe(0);
    expect(r.held_count).toBe(0);
    expect(r.immediate).toBe(false);
  });

  it("pairs a leading recovery forward — a front below from round 1 that recovers and holds is `held` (mirror of v28's `steady`)", async () => {
    // Cap below at round 1 (pre-archive descent), recovers round 2: v28 treats this as a
    // leading recovery with no fall to pair (`steady`); v30 pairs it FORWARD with the next
    // fall — here none, so the recovery held (`held`).
    const rounds = await Promise.all([
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
    ]);
    const r = await computeCoherenceRelapse(rounds);
    const lat = await computeCoherenceLatency(rounds);
    expect(lat.fronts.find((f) => f.dimension === "Cap")!.latency).toBe("steady"); // v28
    const cap = r.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.crossings).toBe(1); // the recovery still counts toward total_crossings (v24 parity)
    expect(cap.intervals).toEqual([{ recovery_round: 2, fall_round: null, clean_rounds: null }]);
    expect(cap.relapse).toBe("held");
    expect(r.held_count).toBe(1);
  });

  it("a leading recovery that IS relapsed counts as a relapse — below round 1, recover round 2, fall round 3", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "acceptable" }, { Cap: "ideal" }), // recovery → round 2
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }), // relapse → round 3 (held 1 round)
    ]);
    const r = await computeCoherenceRelapse(rounds);
    const cap = r.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.intervals).toEqual([{ recovery_round: 2, fall_round: 3, clean_rounds: 1 }]);
    expect(cap.relapse).toBe("relapsed");
    expect(r.immediate).toBe(true);
  });

  it("is a reduction of the same crossings — total_crossings equals v24's, v25's, v28's, and v29's totals", async () => {
    const rounds = await Promise.all([
      mk(
        { Cap: "below-acceptable", Term: "acceptable", Fee: "ideal" },
        { Cap: "ideal", Term: "ideal", Fee: "ideal" },
      ),
      mk(
        { Cap: "acceptable", Term: "below-acceptable", Fee: "ideal" },
        { Cap: "ideal", Term: "ideal", Fee: "ideal" },
      ),
      mk(
        { Cap: "below-acceptable", Term: "acceptable", Fee: "below-acceptable" },
        { Cap: "ideal", Term: "ideal", Fee: "ideal" },
      ),
    ]);
    const rel = await computeCoherenceRelapse(rounds);
    const vol = await computeCoherenceVolatility(rounds);
    const sync = await computeCoherenceSynchrony(rounds);
    const lat = await computeCoherenceLatency(rounds);
    const conc = await computeCoherenceConcurrency(rounds);
    const perFrontTotal = vol.fronts.reduce((sum, f) => sum + f.crossings, 0);
    expect(rel.total_crossings).toBe(perFrontTotal);
    expect(rel.total_crossings).toBe(sync.total_crossings);
    expect(rel.total_crossings).toBe(lat.total_crossings);
    expect(rel.total_crossings).toBe(conc.total_crossings);
  });

  it("picks the quickest relapse across many fronts (earliest dimension on a tie)", async () => {
    // Aaa and Zzz both held above floor for 2 rounds before relapsing; the earlier wins.
    const rounds = await Promise.all([
      mk({ Aaa: "below-acceptable", Zzz: "below-acceptable" }, { Aaa: "ideal", Zzz: "ideal" }),
      mk({ Aaa: "acceptable", Zzz: "acceptable" }, { Aaa: "ideal", Zzz: "ideal" }), // recover r2
      mk({ Aaa: "acceptable", Zzz: "acceptable" }, { Aaa: "ideal", Zzz: "ideal" }),
      mk({ Aaa: "below-acceptable", Zzz: "below-acceptable" }, { Aaa: "ideal", Zzz: "ideal" }), // relapse r4 (held 2)
    ]);
    const r = await computeCoherenceRelapse(rounds);
    expect(r.min_interval).toBe(2);
    expect(r.quickest_dimension).toBe("Aaa");
    expect(r.immediate).toBe(false); // held 2 rounds, not an immediate relapse
  });

  it("silence inside a clean interval does not reset the standing; the span is measured to the revealing round (§3)", async () => {
    // Cap recovers round 2, is unstated round 3, falls again round 4: it held above across
    // the silent round (last known standing = above), relapse lands on the revealing round.
    const rounds = await Promise.all([
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "acceptable" }, { Cap: "ideal" }), // recovery → round 2
      mk({ Cap: "unevaluable" }, { Cap: "unevaluable" }), // silent: not a fall
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }), // relapse revealed → round 4
    ]);
    const r = await computeCoherenceRelapse(rounds);
    const cap = r.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.intervals).toEqual([{ recovery_round: 2, fall_round: 4, clean_rounds: 2 }]);
    expect(r.immediate).toBe(false); // clean_rounds 2 (span across the silent round), not adjacent
    expect(r.total_crossings).toBe(2);
  });

  it("attributes a recovery across silence to the round that REVEALS it, never the silent step (§3)", async () => {
    // below → unstated → above: the recovery is visible at round 3, so the interval opens there.
    const rounds = await Promise.all([
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "unevaluable" }, { Cap: "unevaluable" }),
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
    ]);
    const r = await computeCoherenceRelapse(rounds);
    const cap = r.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.intervals).toEqual([{ recovery_round: 3, fall_round: null, clean_rounds: null }]);
    expect(cap.relapse).toBe("held");
  });

  it("an above-floor whipsaw never crosses the floor — no interval (distinct from v17)", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "ideal" }, { Cap: "ideal" }),
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
    ]);
    const r = await computeCoherenceRelapse(rounds);
    expect(r.total_crossings).toBe(0);
    expect(r.fronts.find((f) => f.dimension === "Cap")!.intervals).toEqual([]);
    expect(r.min_interval).toBeNull();
    expect(r.immediate).toBe(false);
  });

  it("reports no interval and min_interval null when no front ever recovered", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "ideal", Risk: "acceptable" }, { Cap: "acceptable", Risk: "ideal" }),
      mk({ Cap: "ideal", Risk: "ideal" }, { Cap: "acceptable", Risk: "acceptable" }),
    ]);
    const r = await computeCoherenceRelapse(rounds);
    expect(r.min_interval).toBeNull();
    expect(r.quickest_dimension).toBeNull();
    expect(r.relapse_count).toBe(0);
    expect(r.held_count).toBe(0);
    expect(r.total_crossings).toBe(0);
  });

  it("ignores an unstated front entirely (silence is not exposure, §3)", async () => {
    const gapRound = () => mk({ Gap: "unevaluable" }, { Gap: "unevaluable" });
    const r = await computeCoherenceRelapse([await gapRound(), await gapRound()]);
    expect(r.total_crossings).toBe(0);
    expect(r.fronts.find((f) => f.dimension === "Gap")!.relapse).toBe("unstated");
    expect(r.class_counts.unstated).toBe(1);
  });

  it("handles two intervals on one front — a relapse then a held recovery", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "acceptable" }, { Cap: "ideal" }), // recovery → round 2
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }), // relapse → round 3 (held 1 round)
      mk({ Cap: "acceptable" }, { Cap: "ideal" }), // recovery → round 4, holds
    ]);
    const r = await computeCoherenceRelapse(rounds);
    const cap = r.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.intervals).toEqual([
      { recovery_round: 2, fall_round: 3, clean_rounds: 1 },
      { recovery_round: 4, fall_round: null, clean_rounds: null },
    ]);
    expect(cap.relapse).toBe("relapsed"); // a closed interval dominates the class
    expect(cap.min_interval).toBe(1); // the closed interval's clean rounds
    expect(r.relapse_count).toBe(1);
    expect(r.held_count).toBe(1);
    expect(r.immediate).toBe(true);
  });

  it("is deterministic: identical rounds in identical order → identical relapse_hash", async () => {
    const build = () =>
      Promise.all([
        mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
        mk({ Cap: "acceptable" }, { Cap: "ideal" }),
        mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
      ]);
    const a = await computeCoherenceRelapse(await build());
    const c = await computeCoherenceRelapse(await build());
    expect(a.relapse_hash).toBe(c.relapse_hash);
    expect(a.relapse_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("throws on fewer than two rounds", async () => {
    const rounds = [await mk({ Cap: "ideal" }, { Cap: "ideal" })];
    await expect(computeCoherenceRelapse(rounds)).rejects.toThrow(/at least two rounds/);
  });

  it("renders the quickest-relapse verdict and stable JSON", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
    ]);
    const r = await computeCoherenceRelapse(rounds);
    const summary = renderCoherenceRelapseSummary(r);
    expect(summary).toContain("Coherence exposure relapse interval across 3 rounds");
    expect(summary).toMatch(/quickest relapse: Cap — held above floor for 1 round/);
    expect(summary).toMatch(/1 relapsed, 0 held/);
    expect(summary).toMatch(/relapse_hash: [0-9a-f]{64}/);

    const json = JSON.parse(buildCoherenceRelapseJson(r));
    expect(json.schema).toBe("vaulytica.posture-relapse.v1");
    expect(json.relapse_hash).toBe(r.relapse_hash);
    expect(json.rounds).toBe(3);
    expect(json.total_crossings).toBe(2);
    expect(json.min_interval).toBe(1);
    expect(json.quickest_dimension).toBe("Cap");
    expect(json.immediate).toBe(true);
    expect(json.fronts[0].intervals[0]).toEqual({
      recovery_round: 2,
      fall_round: 3,
      clean_rounds: 1,
    });
  });

  it("renders a held recovery distinctly", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
    ]);
    const summary = renderCoherenceRelapseSummary(await computeCoherenceRelapse(rounds));
    expect(summary).toMatch(/held/);
    expect(summary).toMatch(/0 relapsed, 1 held/);
  });
});
