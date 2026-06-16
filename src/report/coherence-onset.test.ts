import { describe, expect, it } from "vitest";
import {
  computeCoherenceOnset,
  exposureEarlyOnset,
  buildCoherenceOnsetJson,
  renderCoherenceOnsetSummary,
} from "./coherence-onset.js";
import { computeCoherenceVolatility } from "./coherence-volatility.js";
import { computeCoherenceSynchrony } from "./coherence-synchrony.js";
import { computeCoherenceSettling } from "./coherence-settling.js";
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

describe("computeCoherenceOnset (spec-v27 — time of the first floor crossing)", () => {
  it("flags an EARLY onset — the floor was crossed in the opening round", async () => {
    // Cap falls below floor in the first step 1→2: already moving from the start.
    const rounds = await Promise.all([
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
    ]);
    const r = await computeCoherenceOnset(rounds);
    expect(r.onset_round).toBe(2);
    expect(r.lead_in).toBe(0);
    expect(r.active_count).toBe(1);
    expect(r.early_onset).toBe(true);
    expect(r.per_transition.map((t) => t.state)).toEqual(["active", "still"]);
    expect(exposureEarlyOnset(r)).toBe(true);
  });

  it("reports a clean lead-in — the floor was held steady, then crossed late", async () => {
    // Cap holds the floor through three steady steps, falls only in step 4→5: lead-in 3.
    const rounds = await Promise.all([
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
    ]);
    const r = await computeCoherenceOnset(rounds);
    expect(r.onset_round).toBe(5);
    expect(r.lead_in).toBe(3);
    expect(r.active_count).toBe(1);
    expect(r.early_onset).toBe(false);
    expect(exposureEarlyOnset(r)).toBe(false);
  });

  it("distinguishes an early-onset from a clean-lead-in deal that v26 reports identically", async () => {
    // Both deals end unsettled (the final transition crosses) with the SAME settling_round —
    // v26 cannot tell them apart. v27 separates them by their first crossing: one degraded
    // from the opening, the other held a clean lead-in before its first slip.
    const early = await Promise.all([
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }), // first crossing: round 1→2
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }), // last crossing: final step
    ]);
    const clean = await Promise.all([
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }), // first crossing: round 2→3
      mk({ Cap: "acceptable" }, { Cap: "ideal" }), // last crossing: final step
    ]);
    const earlySettle = await computeCoherenceSettling(early);
    const cleanSettle = await computeCoherenceSettling(clean);
    expect(earlySettle.settling_round).toBe(cleanSettle.settling_round); // identical to v26
    expect(earlySettle.unsettled).toBe(cleanSettle.unsettled);

    const earlyOnset = await computeCoherenceOnset(early);
    const cleanOnset = await computeCoherenceOnset(clean);
    expect(earlyOnset.early_onset).toBe(true);
    expect(cleanOnset.early_onset).toBe(false);
    expect(earlyOnset.onset_round).toBe(2);
    expect(cleanOnset.onset_round).toBe(3);
    expect(earlyOnset.lead_in).toBe(0);
    expect(cleanOnset.lead_in).toBe(1);
  });

  it("locates the EARLIEST crossing across many fronts (a fall in the opening is early)", async () => {
    // Cap falls 1→2 (the earliest crossing), Term falls 2→3, Cap recovers 3→4. onset=2, early.
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "below-acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
    ]);
    const r = await computeCoherenceOnset(rounds);
    expect(r.per_transition.map((t) => t.crossing_fronts)).toEqual([1, 1, 1]);
    expect(r.active_count).toBe(3);
    expect(r.onset_round).toBe(2);
    expect(r.lead_in).toBe(0);
    expect(r.early_onset).toBe(true);
    expect(r.per_transition[0]!.crossed_dimensions).toEqual(["Cap"]);
  });

  it("is a reduction of the same crossings — total_crossings equals v24's, v25's, and v26's totals", async () => {
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
    const onset = await computeCoherenceOnset(rounds);
    const vol = await computeCoherenceVolatility(rounds);
    const sync = await computeCoherenceSynchrony(rounds);
    const settle = await computeCoherenceSettling(rounds);
    const perFrontTotal = vol.fronts.reduce((sum, f) => sum + f.crossings, 0);
    expect(onset.total_crossings).toBe(perFrontTotal);
    expect(onset.total_crossings).toBe(sync.total_crossings);
    expect(onset.total_crossings).toBe(settle.total_crossings);
  });

  it("attributes a crossing across silence to the step that REVEALS it, never the silent step (§3)", async () => {
    // acceptable → unstated → below: the fall is visible at round 3 (the final step),
    // so the onset is round 3 with a clean lead-in of 1 — never on the silent step 1→2.
    const rounds = await Promise.all([
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "unevaluable" }, { Cap: "unevaluable" }),
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
    ]);
    const r = await computeCoherenceOnset(rounds);
    expect(r.per_transition[0]!.state).toBe("still"); // silent step
    expect(r.per_transition[1]!.state).toBe("active"); // revealing step
    expect(r.onset_round).toBe(3);
    expect(r.lead_in).toBe(1);
    expect(r.early_onset).toBe(false);
    expect(r.total_crossings).toBe(1);
  });

  it("an opening round left entirely unstated is NOT an early onset — silence at the open is a clean lead-in (§3)", async () => {
    // The opening round is unstated; Cap is first seen at round 2 already below, then recovers
    // 2→3 (the first visible crossing). The silent open is not an onset; lead-in counts it.
    const rounds = await Promise.all([
      mk({ Cap: "unevaluable" }, { Cap: "unevaluable" }),
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
    ]);
    const r = await computeCoherenceOnset(rounds);
    expect(r.per_transition[0]!.state).toBe("still"); // silent open: no crossing
    expect(r.onset_round).toBe(3);
    expect(r.lead_in).toBe(1);
    expect(r.early_onset).toBe(false); // the silent opening step is not a crossing
    expect(exposureEarlyOnset(r)).toBe(false);
  });

  it("an above-floor whipsaw never crosses the floor — no onset, no active step (distinct from v17)", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "ideal" }, { Cap: "ideal" }),
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
    ]);
    const r = await computeCoherenceOnset(rounds);
    expect(r.total_crossings).toBe(0);
    expect(r.active_count).toBe(0);
    expect(r.early_onset).toBe(false);
  });

  it("reports onset_round null and lead_in = all steps when no front ever crossed the floor", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "ideal", Risk: "acceptable" }, { Cap: "acceptable", Risk: "ideal" }),
      mk({ Cap: "ideal", Risk: "ideal" }, { Cap: "acceptable", Risk: "acceptable" }),
      mk({ Cap: "ideal", Risk: "ideal" }, { Cap: "acceptable", Risk: "acceptable" }),
    ]);
    const r = await computeCoherenceOnset(rounds);
    expect(r.onset_round).toBeNull();
    expect(r.lead_in).toBe(2); // every step is a clean lead-in
    expect(r.active_count).toBe(0);
    expect(r.early_onset).toBe(false);
    expect(r.total_crossings).toBe(0);
  });

  it("ignores an unstated front entirely (silence is not exposure, §3)", async () => {
    const gapRound = () => mk({ Gap: "unevaluable" }, { Gap: "unevaluable" });
    const r = await computeCoherenceOnset([await gapRound(), await gapRound()]);
    expect(r.total_crossings).toBe(0);
    expect(r.onset_round).toBeNull();
    expect(r.per_transition[0]!.crossed_dimensions).toEqual([]);
  });

  it("is deterministic: identical rounds in identical order → identical onset_hash", async () => {
    const build = () =>
      Promise.all([
        mk({ Cap: "acceptable" }, { Cap: "ideal" }),
        mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
      ]);
    const a = await computeCoherenceOnset(await build());
    const c = await computeCoherenceOnset(await build());
    expect(a.onset_hash).toBe(c.onset_hash);
    expect(a.onset_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("throws on fewer than two rounds", async () => {
    const rounds = [await mk({ Cap: "ideal" }, { Cap: "ideal" })];
    await expect(computeCoherenceOnset(rounds)).rejects.toThrow(/at least two rounds/);
  });

  it("renders the onset verdict, the clean lead-in, and stable JSON", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
    ]);
    const r = await computeCoherenceOnset(rounds);
    const summary = renderCoherenceOnsetSummary(r);
    expect(summary).toContain("Coherence exposure onset across 3 rounds");
    expect(summary).toMatch(/at round 3/);
    expect(summary).toMatch(/active steps \(a front crossed the floor\): 1 of 2; clean lead-in: 1/);
    expect(summary).toMatch(/onset_hash: [0-9a-f]{64}/);

    const json = JSON.parse(buildCoherenceOnsetJson(r));
    expect(json.schema).toBe("vaulytica.posture-onset.v1");
    expect(json.onset_hash).toBe(r.onset_hash);
    expect(json.rounds).toBe(3);
    expect(json.total_crossings).toBe(1);
    expect(json.onset_round).toBe(3);
    expect(json.lead_in).toBe(1);
    expect(json.early_onset).toBe(false);
    expect(json.per_transition[1].state).toBe("active");
  });

  it("renders an EARLY onset distinctly", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
    ]);
    const summary = renderCoherenceOnsetSummary(await computeCoherenceOnset(rounds));
    expect(summary).toMatch(/EARLY/);
    expect(summary).toMatch(/the opening transition/);
  });
});
