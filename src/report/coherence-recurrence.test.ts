import { describe, expect, it } from "vitest";
import {
  computeCoherenceRecurrence,
  exposureRecurred,
  buildCoherenceRecurrenceJson,
  renderCoherenceRecurrenceSummary,
} from "./coherence-recurrence.js";
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

describe("computeCoherenceRecurrence (spec-v23 — per-front below-floor episodes)", () => {
  it("distinguishes a recover-then-relapse (2 episodes, recurring) from a steady descent (1 episode, single)", async () => {
    // Cap: below → acceptable → below = recovered and relapsed (2 episodes).
    // Law: below → below → below = one steady descent (1 episode).
    // Both have rounds_below = 3 vs 2 — v21 would report Cap as `open, 2 rounds`,
    // identical in shape to a 2-round steady descent; only the episode count separates them.
    const rounds = await Promise.all([
      mk({ Cap: "below-acceptable", Law: "below-acceptable" }, { Cap: "ideal", Law: "ideal" }),
      mk({ Cap: "acceptable", Law: "below-acceptable" }, { Cap: "ideal", Law: "ideal" }),
      mk({ Cap: "below-acceptable", Law: "below-acceptable" }, { Cap: "ideal", Law: "ideal" }),
    ]);
    const r = await computeCoherenceRecurrence(rounds);
    const cap = r.fronts.find((f) => f.dimension === "Cap")!;
    const law = r.fronts.find((f) => f.dimension === "Law")!;
    expect(cap.below_runs).toBe(2);
    expect(cap.recurrence).toBe("recurring");
    expect(cap.episodes).toEqual([
      { first_round: 1, last_round: 1 },
      { first_round: 3, last_round: 3 },
    ]);
    expect(law.below_runs).toBe(1);
    expect(law.recurrence).toBe("single");
    expect(law.episodes).toEqual([{ first_round: 1, last_round: 3 }]);
    expect(r.recurring_count).toBe(1);
    expect(exposureRecurred(r)).toBe(true);
  });

  it("does not let silence split an episode — below → unstated → below is ONE episode (§3)", async () => {
    // Cap is unstated (unevaluable) in round 2; its below-floor stretch is not split.
    const rounds = await Promise.all([
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "unevaluable" }, { Cap: "unevaluable" }),
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
    ]);
    const r = await computeCoherenceRecurrence(rounds);
    const cap = r.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.below_runs).toBe(1); // silence does not split
    expect(cap.recurrence).toBe("single");
    expect(cap.episodes).toEqual([{ first_round: 1, last_round: 3 }]);
    expect(exposureRecurred(r)).toBe(false);
  });

  it("a STATED recovery does split an episode — below → acceptable → below is TWO episodes", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
    ]);
    const r = await computeCoherenceRecurrence(rounds);
    const cap = r.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.below_runs).toBe(2);
    expect(cap.recurrence).toBe("recurring");
  });

  it("a recurred-then-resolved front still trips the gate (it relapsed even though it later recovered)", async () => {
    // below → acceptable → below → acceptable: 2 episodes, latest stated floor recovered.
    const rounds = await Promise.all([
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
    ]);
    const r = await computeCoherenceRecurrence(rounds);
    const cap = r.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.below_runs).toBe(2);
    expect(cap.recurrence).toBe("recurring");
    expect(exposureRecurred(r)).toBe(true);
  });

  it("a single-episode front still below floor at the end does NOT trip the gate (one episode is not churn)", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
    ]);
    const r = await computeCoherenceRecurrence(rounds);
    const cap = r.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.below_runs).toBe(1);
    expect(cap.recurrence).toBe("single");
    expect(exposureRecurred(r)).toBe(false);
  });

  it("identifies the most recurrent front (the most episodes), earliest on a tie", async () => {
    // Apex: below→acc→below→acc→below = 3 episodes. Beta: below→acc→below = 2 episodes.
    const rounds = await Promise.all([
      mk({ Apex: "below-acceptable", Beta: "below-acceptable" }, { Apex: "ideal", Beta: "ideal" }),
      mk({ Apex: "acceptable", Beta: "acceptable" }, { Apex: "ideal", Beta: "ideal" }),
      mk({ Apex: "below-acceptable", Beta: "below-acceptable" }, { Apex: "ideal", Beta: "ideal" }),
      mk({ Apex: "acceptable", Beta: "ideal" }, { Apex: "ideal", Beta: "ideal" }),
      mk({ Apex: "below-acceptable", Beta: "ideal" }, { Apex: "ideal", Beta: "ideal" }),
    ]);
    const r = await computeCoherenceRecurrence(rounds);
    expect(r.most_recurrent_dimension).toBe("Apex");
    expect(r.max_runs).toBe(3);
  });

  it("does not count an unstated front (silence is not exposure, §3)", async () => {
    // `Gap` is `unevaluable` in every document → no binding floor → unstated.
    const gapRound = () => mk({ Gap: "unevaluable" }, { Gap: "unevaluable" });
    const r = await computeCoherenceRecurrence([await gapRound(), await gapRound()]);
    const gap = r.fronts.find((f) => f.dimension === "Gap")!;
    expect(gap.recurrence).toBe("unstated");
    expect(gap.below_runs).toBe(0);
    expect(r.class_counts.unstated).toBe(1);
  });

  it("reports max_runs 0 and most_recurrent null when no front was ever below floor", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "ideal", Risk: "acceptable" }, { Cap: "acceptable", Risk: "ideal" }),
      mk({ Cap: "ideal", Risk: "ideal" }, { Cap: "acceptable", Risk: "acceptable" }),
    ]);
    const r = await computeCoherenceRecurrence(rounds);
    expect(r.max_runs).toBe(0);
    expect(r.most_recurrent_dimension).toBeNull();
    expect(r.recurring_count).toBe(0);
    expect(r.class_counts.none).toBe(2);
  });

  it("is deterministic: identical rounds in identical order → identical recurrence_hash", async () => {
    const build = () =>
      Promise.all([
        mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
        mk({ Cap: "acceptable" }, { Cap: "ideal" }),
        mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
      ]);
    const a = await computeCoherenceRecurrence(await build());
    const c = await computeCoherenceRecurrence(await build());
    expect(a.recurrence_hash).toBe(c.recurrence_hash);
    expect(a.recurrence_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("throws on fewer than two rounds", async () => {
    const rounds = [await mk({ Cap: "ideal" }, { Cap: "ideal" })];
    await expect(computeCoherenceRecurrence(rounds)).rejects.toThrow(/at least two rounds/);
  });

  it("renders the recurring fronts, their episodes, and stable JSON", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
    ]);
    const r = await computeCoherenceRecurrence(rounds);
    const summary = renderCoherenceRecurrenceSummary(r);
    expect(summary).toContain("Coherence exposure recurrence across 3 rounds");
    expect(summary).toMatch(/1 recurring \(recovered & relapsed\)/);
    expect(summary).toMatch(
      /⚠ Cap: recurring — below floor in 2 separate episodes \(round 1, round 3\)/,
    );
    expect(summary).toMatch(/recurrence_hash: [0-9a-f]{64}/);

    const json = JSON.parse(buildCoherenceRecurrenceJson(r));
    expect(json.schema).toBe("vaulytica.posture-recurrence.v1");
    expect(json.recurrence_hash).toBe(r.recurrence_hash);
    expect(json.rounds).toBe(3);
    expect(json.recurring_count).toBe(1);
    expect(json.most_recurrent_dimension).toBe("Cap");
    expect(json.fronts[0].episodes).toEqual([
      { first_round: 1, last_round: 1 },
      { first_round: 3, last_round: 3 },
    ]);
  });
});
