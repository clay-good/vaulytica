import { describe, expect, it } from "vitest";
import {
  computeCoherenceSettling,
  exposureUnsettled,
  buildCoherenceSettlingJson,
  renderCoherenceSettlingSummary,
} from "./coherence-settling.js";
import { computeCoherenceVolatility } from "./coherence-volatility.js";
import { computeCoherenceSynchrony } from "./coherence-synchrony.js";
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

describe("computeCoherenceSettling (spec-v26 — time of the last floor crossing)", () => {
  it("flags an UNSETTLED close — the floor was crossed in the final round", async () => {
    // Cap falls below floor only in the final step 2→3: still moving at the close.
    const rounds = await Promise.all([
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
    ]);
    const r = await computeCoherenceSettling(rounds);
    expect(r.settling_round).toBe(3);
    expect(r.quiet_tail).toBe(0);
    expect(r.active_count).toBe(1);
    expect(r.unsettled).toBe(true);
    expect(r.per_transition.map((t) => t.state)).toEqual(["still", "active"]);
    expect(exposureUnsettled(r)).toBe(true);
  });

  it("reports a SETTLED deal — the floor was crossed early, then steady to the close", async () => {
    // Cap falls in step 1→2 and never crosses again: settled at round 2, three quiet steps follow.
    const rounds = await Promise.all([
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
    ]);
    const r = await computeCoherenceSettling(rounds);
    expect(r.settling_round).toBe(2);
    expect(r.quiet_tail).toBe(3);
    expect(r.active_count).toBe(1);
    expect(r.unsettled).toBe(false);
    expect(exposureUnsettled(r)).toBe(false);
  });

  it("distinguishes an early-cross from a late-cross that v24 and v25 report identically", async () => {
    // Both deals: exactly one front crosses the floor exactly once. To v24 each is one
    // monotone front (crossings=1); to v25 each is one isolated step (not synchronized).
    // v26 separates them: the early one settled, the late one did not.
    const early = await computeCoherenceSettling(
      await Promise.all([
        mk({ Cap: "acceptable" }, { Cap: "ideal" }),
        mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
        mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
      ]),
    );
    const late = await computeCoherenceSettling(
      await Promise.all([
        mk({ Cap: "acceptable" }, { Cap: "ideal" }),
        mk({ Cap: "acceptable" }, { Cap: "ideal" }),
        mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
      ]),
    );
    expect(early.total_crossings).toBe(late.total_crossings); // identical to v24/v25
    expect(early.unsettled).toBe(false);
    expect(late.unsettled).toBe(true);
    expect(early.settling_round).toBe(2);
    expect(late.settling_round).toBe(3);
  });

  it("locates the LATEST crossing across many fronts (a recovery in the final round is unsettled)", async () => {
    // Cap falls 1→2, Term falls 2→3, Cap recovers 3→4 (the latest crossing). settling=4, unsettled.
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "below-acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
    ]);
    const r = await computeCoherenceSettling(rounds);
    expect(r.per_transition.map((t) => t.crossing_fronts)).toEqual([1, 1, 1]);
    expect(r.active_count).toBe(3);
    expect(r.settling_round).toBe(4);
    expect(r.quiet_tail).toBe(0);
    expect(r.unsettled).toBe(true);
    expect(r.per_transition[2]!.crossed_dimensions).toEqual(["Cap"]);
  });

  it("is a reduction of the same crossings — total_crossings equals v24's and v25's totals", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Term: "below-acceptable", Fee: "ideal" }, { Cap: "ideal", Term: "ideal", Fee: "ideal" }),
      mk({ Cap: "below-acceptable", Term: "acceptable", Fee: "ideal" }, { Cap: "ideal", Term: "ideal", Fee: "ideal" }),
      mk({ Cap: "acceptable", Term: "below-acceptable", Fee: "below-acceptable" }, { Cap: "ideal", Term: "ideal", Fee: "ideal" }),
    ]);
    const settling = await computeCoherenceSettling(rounds);
    const vol = await computeCoherenceVolatility(rounds);
    const sync = await computeCoherenceSynchrony(rounds);
    const perFrontTotal = vol.fronts.reduce((sum, f) => sum + f.crossings, 0);
    expect(settling.total_crossings).toBe(perFrontTotal);
    expect(settling.total_crossings).toBe(sync.total_crossings);
  });

  it("attributes a crossing across silence to the step that REVEALS it, never the silent step (§3)", async () => {
    // below → unstated → acceptable: the recovery is visible at round 3 (the final step),
    // so the deal is unsettled, settling at round 3 — never on the silent step 1→2.
    const rounds = await Promise.all([
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "unevaluable" }, { Cap: "unevaluable" }),
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
    ]);
    const r = await computeCoherenceSettling(rounds);
    expect(r.per_transition[0]!.state).toBe("still"); // silent step
    expect(r.per_transition[1]!.state).toBe("active"); // revealing step
    expect(r.settling_round).toBe(3);
    expect(r.unsettled).toBe(true);
    expect(r.total_crossings).toBe(1);
  });

  it("a final round left entirely unstated is SETTLED — silence at the close is stability, not movement (§3)", async () => {
    // Cap falls 1→2 (the last real movement), then the final round is unstated.
    const rounds = await Promise.all([
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "unevaluable" }, { Cap: "unevaluable" }),
    ]);
    const r = await computeCoherenceSettling(rounds);
    expect(r.settling_round).toBe(2);
    expect(r.quiet_tail).toBe(1);
    expect(r.unsettled).toBe(false); // the silent final step is not a crossing
    expect(exposureUnsettled(r)).toBe(false);
  });

  it("an above-floor whipsaw never crosses the floor — settled with no active step (distinct from v17)", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "ideal" }, { Cap: "ideal" }),
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
    ]);
    const r = await computeCoherenceSettling(rounds);
    expect(r.total_crossings).toBe(0);
    expect(r.active_count).toBe(0);
    expect(r.unsettled).toBe(false);
  });

  it("reports settling_round null and quiet_tail = all steps when no front ever crossed the floor", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "ideal", Risk: "acceptable" }, { Cap: "acceptable", Risk: "ideal" }),
      mk({ Cap: "ideal", Risk: "ideal" }, { Cap: "acceptable", Risk: "acceptable" }),
      mk({ Cap: "ideal", Risk: "ideal" }, { Cap: "acceptable", Risk: "acceptable" }),
    ]);
    const r = await computeCoherenceSettling(rounds);
    expect(r.settling_round).toBeNull();
    expect(r.quiet_tail).toBe(2); // every step is quiet
    expect(r.active_count).toBe(0);
    expect(r.unsettled).toBe(false);
    expect(r.total_crossings).toBe(0);
  });

  it("ignores an unstated front entirely (silence is not exposure, §3)", async () => {
    const gapRound = () => mk({ Gap: "unevaluable" }, { Gap: "unevaluable" });
    const r = await computeCoherenceSettling([await gapRound(), await gapRound()]);
    expect(r.total_crossings).toBe(0);
    expect(r.settling_round).toBeNull();
    expect(r.per_transition[0]!.crossed_dimensions).toEqual([]);
  });

  it("is deterministic: identical rounds in identical order → identical settling_hash", async () => {
    const build = () =>
      Promise.all([
        mk({ Cap: "acceptable" }, { Cap: "ideal" }),
        mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
      ]);
    const a = await computeCoherenceSettling(await build());
    const c = await computeCoherenceSettling(await build());
    expect(a.settling_hash).toBe(c.settling_hash);
    expect(a.settling_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("throws on fewer than two rounds", async () => {
    const rounds = [await mk({ Cap: "ideal" }, { Cap: "ideal" })];
    await expect(computeCoherenceSettling(rounds)).rejects.toThrow(/at least two rounds/);
  });

  it("renders the settling verdict, the quiet tail, and stable JSON", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
    ]);
    const r = await computeCoherenceSettling(rounds);
    const summary = renderCoherenceSettlingSummary(r);
    expect(summary).toContain("Coherence exposure settling across 3 rounds");
    expect(summary).toMatch(/settled at round 2/);
    expect(summary).toMatch(/active steps \(a front crossed the floor\): 1 of 2; quiet tail: 1/);
    expect(summary).toMatch(/settling_hash: [0-9a-f]{64}/);

    const json = JSON.parse(buildCoherenceSettlingJson(r));
    expect(json.schema).toBe("vaulytica.posture-settling.v1");
    expect(json.settling_hash).toBe(r.settling_hash);
    expect(json.rounds).toBe(3);
    expect(json.total_crossings).toBe(1);
    expect(json.settling_round).toBe(2);
    expect(json.quiet_tail).toBe(1);
    expect(json.unsettled).toBe(false);
    expect(json.per_transition[0].state).toBe("active");
  });

  it("renders an UNSETTLED close distinctly", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
    ]);
    const summary = renderCoherenceSettlingSummary(await computeCoherenceSettling(rounds));
    expect(summary).toMatch(/UNSETTLED/);
    expect(summary).toMatch(/the final transition/);
  });
});
