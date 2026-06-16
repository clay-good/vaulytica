import { describe, expect, it } from "vitest";
import {
  computeCoherenceTenure,
  exposureMajorityBelow,
  buildCoherenceTenureJson,
  renderCoherenceTenureSummary,
} from "./coherence-tenure.js";
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

describe("computeCoherenceTenure (spec-v31 — share of stated span below floor)", () => {
  it("measures a strict majority — below floor 4 of 5 stated rounds (80%)", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "acceptable" }, { Cap: "ideal" }), // recovers at the close
    ]);
    const t = await computeCoherenceTenure(rounds);
    const cap = t.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.stated_rounds).toBe(5);
    expect(cap.below_rounds).toBe(4);
    expect(cap.share).toBeCloseTo(0.8);
    expect(cap.tenure).toBe("majority");
    expect(t.max_share).toBeCloseTo(0.8);
    expect(t.heaviest_dimension).toBe("Cap");
    expect(t.majority).toBe(true);
    expect(exposureMajorityBelow(t)).toBe(true);
  });

  it("separates a brief dip from a chronic burden that v21 reports identically (both `resolved`)", async () => {
    // Cap: below in round 2 only, recovers (1/5 = minority).
    // Term: below in rounds 1–4, recovers at round 5 (4/5 = majority).
    // To v21 both are `resolved` (recovered by the close); to v31 they are opposites.
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
    ]);
    const t = await computeCoherenceTenure(rounds);
    const p = await computeCoherencePersistence(rounds);
    expect(p.fronts.find((f) => f.dimension === "Cap")!.persistence).toBe("resolved");
    expect(p.fronts.find((f) => f.dimension === "Term")!.persistence).toBe("resolved");
    expect(t.fronts.find((f) => f.dimension === "Cap")!.tenure).toBe("minority");
    expect(t.fronts.find((f) => f.dimension === "Term")!.tenure).toBe("majority");
    expect(t.heaviest_dimension).toBe("Term");
    expect(t.max_share).toBeCloseTo(0.8);
    expect(t.majority).toBe(true);
  });

  it("a fresh late dip is `open` to v21 but a minority to v31 (gate clears)", async () => {
    // Cap acceptable rounds 1–4, below floor only at round 5 (1/5 = minority, but `open` to v21).
    const rounds = await Promise.all([
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
    ]);
    const t = await computeCoherenceTenure(rounds);
    const p = await computeCoherencePersistence(rounds);
    expect(p.fronts.find((f) => f.dimension === "Cap")!.persistence).toBe("open"); // below now
    const cap = t.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.below_rounds).toBe(1);
    expect(cap.tenure).toBe("minority");
    expect(t.majority).toBe(false);
    expect(exposureMajorityBelow(t)).toBe(false);
  });

  it("an exact split is a minority, not a majority (below 2 of 4)", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
    ]);
    const t = await computeCoherenceTenure(rounds);
    const cap = t.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.below_rounds).toBe(2);
    expect(cap.stated_rounds).toBe(4);
    expect(cap.share).toBeCloseTo(0.5);
    expect(cap.tenure).toBe("minority");
    expect(t.majority).toBe(false);
  });

  it("normalizes by STATED rounds, not total rounds — below both times it was on the table reads 100% (§3)", async () => {
    // Cap stated only in rounds 1 and 2 (below both), silent rounds 3–5. v21 would call this
    // "2 of 5 rounds"; v31 reads 2 of 2 STATED rounds = 100%, a majority.
    const rounds = await Promise.all([
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "unevaluable" }, { Cap: "unevaluable" }),
      mk({ Cap: "unevaluable" }, { Cap: "unevaluable" }),
      mk({ Cap: "unevaluable" }, { Cap: "unevaluable" }),
    ]);
    const t = await computeCoherenceTenure(rounds);
    const cap = t.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.stated_rounds).toBe(2);
    expect(cap.below_rounds).toBe(2);
    expect(cap.share).toBe(1);
    expect(cap.tenure).toBe("majority");
    expect(t.max_share).toBe(1);
  });

  it("total_below_rounds equals v21's rounds_below summed across fronts (the join invariant)", async () => {
    const rounds = await Promise.all([
      mk(
        { Cap: "below-acceptable", Term: "acceptable", Fee: "below-acceptable" },
        { Cap: "ideal", Term: "ideal", Fee: "ideal" },
      ),
      mk(
        { Cap: "acceptable", Term: "below-acceptable", Fee: "below-acceptable" },
        { Cap: "ideal", Term: "ideal", Fee: "ideal" },
      ),
      mk(
        { Cap: "below-acceptable", Term: "acceptable", Fee: "acceptable" },
        { Cap: "ideal", Term: "ideal", Fee: "ideal" },
      ),
    ]);
    const t = await computeCoherenceTenure(rounds);
    const p = await computeCoherencePersistence(rounds);
    const persistTotal = p.fronts.reduce((sum, f) => sum + f.rounds_below, 0);
    expect(t.total_below_rounds).toBe(persistTotal);
    expect(t.total_stated_rounds).toBe(9); // 3 fronts × 3 rounds, all stated
  });

  it("picks the heaviest share across fronts by exact integer ratio (earliest dimension on a tie)", async () => {
    // Aaa: below 1 of 2 stated (50%). Zzz: below 2 of 3 stated (67%). Zzz is heavier.
    const rounds = await Promise.all([
      mk({ Aaa: "below-acceptable", Zzz: "below-acceptable" }, { Aaa: "ideal", Zzz: "ideal" }),
      mk({ Aaa: "acceptable", Zzz: "below-acceptable" }, { Aaa: "ideal", Zzz: "ideal" }),
      mk({ Aaa: "unevaluable", Zzz: "acceptable" }, { Aaa: "unevaluable", Zzz: "ideal" }),
    ]);
    const t = await computeCoherenceTenure(rounds);
    expect(t.fronts.find((f) => f.dimension === "Aaa")!.share).toBeCloseTo(0.5);
    expect(t.fronts.find((f) => f.dimension === "Zzz")!.share).toBeCloseTo(2 / 3);
    expect(t.heaviest_dimension).toBe("Zzz");
    expect(t.max_share).toBeCloseTo(2 / 3);
  });

  it("breaks a heaviest-share tie by earliest dimension (localeCompare order)", async () => {
    // Aaa and Zzz both below 1 of 2 stated rounds (50%); the earlier dimension wins.
    const rounds = await Promise.all([
      mk({ Aaa: "below-acceptable", Zzz: "below-acceptable" }, { Aaa: "ideal", Zzz: "ideal" }),
      mk({ Aaa: "acceptable", Zzz: "acceptable" }, { Aaa: "ideal", Zzz: "ideal" }),
    ]);
    const t = await computeCoherenceTenure(rounds);
    expect(t.heaviest_dimension).toBe("Aaa");
    expect(t.max_share).toBeCloseTo(0.5);
  });

  it("reports no heaviest occupancy when no front was ever below floor", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "ideal", Risk: "acceptable" }, { Cap: "acceptable", Risk: "ideal" }),
      mk({ Cap: "ideal", Risk: "ideal" }, { Cap: "acceptable", Risk: "acceptable" }),
    ]);
    const t = await computeCoherenceTenure(rounds);
    expect(t.max_share).toBeNull();
    expect(t.heaviest_dimension).toBeNull();
    expect(t.majority).toBe(false);
    expect(t.total_below_rounds).toBe(0);
    expect(t.class_counts.none).toBe(2);
  });

  it("ignores an unstated front entirely (silence is not exposure, §3)", async () => {
    const gapRound = () => mk({ Gap: "unevaluable" }, { Gap: "unevaluable" });
    const t = await computeCoherenceTenure([await gapRound(), await gapRound()]);
    const gap = t.fronts.find((f) => f.dimension === "Gap")!;
    expect(gap.stated_rounds).toBe(0);
    expect(gap.below_rounds).toBe(0);
    expect(gap.share).toBeNull();
    expect(gap.tenure).toBe("unstated");
    expect(t.class_counts.unstated).toBe(1);
    expect(t.majority).toBe(false);
  });

  it("a front stated once and below floor reads 100% / majority (no minimum stated-round count)", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "ideal", New: "unevaluable" }, { Cap: "ideal", New: "unevaluable" }),
      mk({ Cap: "ideal", New: "below-acceptable" }, { Cap: "ideal", New: "ideal" }),
    ]);
    const t = await computeCoherenceTenure(rounds);
    const nf = t.fronts.find((f) => f.dimension === "New")!;
    expect(nf.stated_rounds).toBe(1);
    expect(nf.below_rounds).toBe(1);
    expect(nf.share).toBe(1);
    expect(nf.tenure).toBe("majority");
    expect(t.majority).toBe(true);
  });

  it("is deterministic: identical rounds in identical order → identical tenure_hash", async () => {
    const build = () =>
      Promise.all([
        mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
        mk({ Cap: "acceptable" }, { Cap: "ideal" }),
        mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
      ]);
    const a = await computeCoherenceTenure(await build());
    const c = await computeCoherenceTenure(await build());
    expect(a.tenure_hash).toBe(c.tenure_hash);
    expect(a.tenure_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("throws on fewer than two rounds", async () => {
    const rounds = [await mk({ Cap: "ideal" }, { Cap: "ideal" })];
    await expect(computeCoherenceTenure(rounds)).rejects.toThrow(/at least two rounds/);
  });

  it("renders the heaviest-occupancy verdict and stable JSON", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
    ]);
    const t = await computeCoherenceTenure(rounds);
    const summary = renderCoherenceTenureSummary(t);
    expect(summary).toContain("Coherence exposure tenure across 3 rounds");
    expect(summary).toMatch(/heaviest occupancy: Cap — below floor 67% of its stated rounds/);
    expect(summary).toMatch(/1 majority/);
    expect(summary).toMatch(/tenure_hash: [0-9a-f]{64}/);

    const json = JSON.parse(buildCoherenceTenureJson(t));
    expect(json.schema).toBe("vaulytica.posture-tenure.v1");
    expect(json.tenure_hash).toBe(t.tenure_hash);
    expect(json.rounds).toBe(3);
    expect(json.total_below_rounds).toBe(2);
    expect(json.total_stated_rounds).toBe(3);
    expect(json.heaviest_dimension).toBe("Cap");
    expect(json.majority).toBe(true);
    expect(json.fronts[0]).toMatchObject({
      dimension: "Cap",
      stated_rounds: 3,
      below_rounds: 2,
      tenure: "majority",
    });
  });

  it("renders a none-below verdict distinctly", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "ideal" }, { Cap: "ideal" }),
    ]);
    const summary = renderCoherenceTenureSummary(await computeCoherenceTenure(rounds));
    expect(summary).toMatch(/heaviest occupancy: none/);
  });
});
