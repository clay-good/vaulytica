import { describe, expect, it } from "vitest";
import {
  computeCoherenceMatrix,
  exposureBlackout,
  buildCoherenceMatrixJson,
  renderCoherenceMatrixSummary,
} from "./coherence-matrix.js";
import { computeCoherenceBreadth } from "./coherence-breadth.js";
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

/** A round built from two docs; the second is always `ideal`, so each front's binding floor is its first tier. */
const mk = (a: Record<string, NegotiationTier>, b: Record<string, NegotiationTier>) =>
  bundlePostureCoherence(bundle(["msa.docx", a], ["order.docx", b]));

const B: NegotiationTier = "below-acceptable";
const A: NegotiationTier = "acceptable";
const I: NegotiationTier = "ideal";
const U: NegotiationTier = "unevaluable";

/**
 * Assemble N rounds from a map of front → equal-length tier path. The second doc is `ideal` so each
 * front's binding floor is its first tier — *except* when that tier is `unevaluable`, where the
 * second doc is `unevaluable` too, so the front is genuinely unstated that round (binding floor
 * `null`) rather than silently floored at `ideal`.
 */
function rounds(paths: Record<string, NegotiationTier[]>) {
  const names = Object.keys(paths);
  const n = paths[names[0]!]!.length;
  return Promise.all(
    Array.from({ length: n }, (_, i) => {
      const doc1: Record<string, NegotiationTier> = {};
      const doc2: Record<string, NegotiationTier> = {};
      for (const name of names) {
        const tier = paths[name]![i]!;
        doc1[name] = tier;
        doc2[name] = tier === "unevaluable" ? "unevaluable" : "ideal";
      }
      return mk(doc1, doc2);
    }),
  );
}

describe("computeCoherenceMatrix (spec-v44 — per-front × per-round floor-state grid)", () => {
  it("lays out the raw grid with below/above/unstated cells, rows pinned by localeCompare", async () => {
    // Cap: above, below, below, above. Term: above, below, above, below. Ind: below, below, above, above.
    const matrix = await computeCoherenceMatrix(
      await rounds({
        Cap: [A, B, B, A],
        Term: [I, B, A, B],
        Ind: [B, B, A, I],
      }),
    );

    expect(matrix.rounds).toBe(4);
    // Rows are localeCompare-sorted: Cap, Ind, Term.
    expect(matrix.fronts.map((f) => f.dimension)).toEqual(["Cap", "Ind", "Term"]);

    const cap = matrix.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.cells).toEqual(["above", "below", "below", "above"]);
    expect(cap.below_rounds).toBe(2);
    expect(cap.stated_rounds).toBe(4);

    const ind = matrix.fronts.find((f) => f.dimension === "Ind")!;
    expect(ind.cells).toEqual(["below", "below", "above", "above"]);

    // Round 2 (index 1) is a blackout: all three stated fronts below.
    expect(matrix.blackout_rounds).toEqual([2]);
    expect(matrix.has_blackout).toBe(true);
    expect(exposureBlackout(matrix)).toBe(true);
  });

  it("maps ideal and acceptable to the same `above` cell (the floor is binary)", async () => {
    const matrix = await computeCoherenceMatrix(await rounds({ Cap: [I, A], Term: [A, I] }));
    for (const f of matrix.fronts) {
      expect(f.cells).toEqual(["above", "above"]);
      expect(f.below_rounds).toBe(0);
      expect(f.stated_rounds).toBe(2);
    }
    expect(matrix.has_blackout).toBe(false);
    expect(matrix.cell_counts).toEqual({ below: 0, above: 4, unstated: 0 });
  });

  it("treats an unstated front-round as `unstated`, never `below` (§3 honesty)", async () => {
    // Cap is unstated in round 2 (both docs silent). It must not count as below floor.
    const matrix = await computeCoherenceMatrix(await rounds({ Cap: [B, U, B], Term: [B, B, B] }));
    const cap = matrix.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.cells).toEqual(["below", "unstated", "below"]);
    expect(cap.below_rounds).toBe(2);
    expect(cap.stated_rounds).toBe(2);

    // Round 2: only Term is stated (and below) → it is still a blackout (every *stated* front below).
    expect(matrix.per_round[1]).toMatchObject({
      round: 2,
      below_fronts: 1,
      stated_fronts: 1,
      blackout: true,
    });
    expect(matrix.blackout_rounds).toEqual([1, 2, 3]);
  });

  it("a round with no stated front is never a blackout", async () => {
    const matrix = await computeCoherenceMatrix(await rounds({ Cap: [B, U], Term: [B, U] }));
    expect(matrix.per_round[1]).toMatchObject({
      round: 2,
      below_fronts: 0,
      stated_fronts: 0,
      blackout: false,
    });
    expect(matrix.blackout_rounds).toEqual([1]);
    expect(matrix.has_blackout).toBe(true);
  });

  it("clears the gate when at least one front holds the line every round (no full column)", async () => {
    // Term is above floor in every round, so no round can black out, however exposed Cap is.
    const matrix = await computeCoherenceMatrix(await rounds({ Cap: [B, B, B], Term: [A, A, A] }));
    expect(matrix.has_blackout).toBe(false);
    expect(exposureBlackout(matrix)).toBe(false);
    expect(matrix.blackout_rounds).toEqual([]);
    for (const r of matrix.per_round) {
      expect(r.below_fronts).toBe(1);
      expect(r.stated_fronts).toBe(2);
    }
  });

  it("is distinct from v22 breadth: a deal blacks out in round 1 then recovers (widened false, blackout true)", async () => {
    // Round 1 every front below (blackout); the deal then recovers, so the latest round has fewer
    // fronts below than the first → v22 `widened` is false while v44 `has_blackout` is true.
    const cs = await rounds({ Cap: [B, A, A], Term: [B, A, A] });
    const matrix = await computeCoherenceMatrix(cs);
    const breadth = await computeCoherenceBreadth(cs);
    expect(matrix.has_blackout).toBe(true);
    expect(matrix.blackout_rounds).toEqual([1]);
    expect(breadth.widened).toBe(false); // 2 fronts below in round 1, 0 in round 3
  });

  it("is distinct from v22 breadth: a deal widens 1→2 of 3 fronts but never a full column (widened true, blackout false)", async () => {
    const cs = await rounds({ Cap: [B, B, B], Term: [A, A, B], Ind: [A, A, A] });
    const matrix = await computeCoherenceMatrix(cs);
    const breadth = await computeCoherenceBreadth(cs);
    expect(matrix.has_blackout).toBe(false); // Ind holds the line every round
    expect(breadth.widened).toBe(true); // 1 front below in round 1, 2 in round 3
  });

  it("ties its per-round below-front counts to v22 breadth's exposed_fronts by construction", async () => {
    const cs = await rounds({ Cap: [B, A, B], Term: [A, B, B], Ind: [B, B, A] });
    const matrix = await computeCoherenceMatrix(cs);
    const breadth = await computeCoherenceBreadth(cs);
    for (let i = 0; i < matrix.per_round.length; i++) {
      expect(matrix.per_round[i]!.below_fronts).toBe(breadth.per_round[i]!.exposed_fronts);
      expect(matrix.per_round[i]!.stated_fronts).toBe(breadth.per_round[i]!.stated_fronts);
    }
  });

  it("ties the whole-grid cell tally to the per-front and per-round counts by construction", async () => {
    const matrix = await computeCoherenceMatrix(await rounds({ Cap: [B, U, A], Term: [B, B, A] }));
    const belowFromRows = matrix.fronts.reduce((s, f) => s + f.below_rounds, 0);
    const belowFromRounds = matrix.per_round.reduce((s, r) => s + r.below_fronts, 0);
    expect(matrix.cell_counts.below).toBe(belowFromRows);
    expect(matrix.cell_counts.below).toBe(belowFromRounds);
    const total = matrix.cell_counts.below + matrix.cell_counts.above + matrix.cell_counts.unstated;
    expect(total).toBe(matrix.rounds * matrix.fronts.length);
  });

  it("is deterministic: identical rounds in identical order → identical matrix_hash", async () => {
    const build = () => rounds({ Cap: [B, A, B], Term: [A, B, A] });
    const a = await computeCoherenceMatrix(await build());
    const c = await computeCoherenceMatrix(await build());
    expect(a.matrix_hash).toBe(c.matrix_hash);
    expect(a.matrix_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("throws on fewer than two rounds", async () => {
    const single = [await mk({ Cap: "ideal" }, { Cap: "ideal" })];
    await expect(computeCoherenceMatrix(single)).rejects.toThrow(/at least two rounds/);
  });

  it("renders a heatmap with a legend, blackout verdict, and stable JSON", async () => {
    const matrix = await computeCoherenceMatrix(
      await rounds({ Cap: [A, B, B, A], Term: [I, B, A, B], Ind: [B, B, A, I] }),
    );
    const summary = renderCoherenceMatrixSummary(matrix);
    expect(summary).toContain("Coherence exposure matrix across 4 rounds × 3 fronts");
    expect(summary).toMatch(/legend: ▓ below floor/);
    expect(summary).toMatch(/blackout \(every stated front below floor\): round 2\./);
    expect(summary).toMatch(/Cap/);
    expect(summary).toMatch(/▓/);
    expect(summary).toMatch(/cells: \d+ below, \d+ above, \d+ unstated \(of 12\)\./);
    expect(summary).toMatch(/matrix_hash: [0-9a-f]{64}/);

    const json = JSON.parse(buildCoherenceMatrixJson(matrix));
    expect(json.schema).toBe("vaulytica.posture-matrix.v1");
    expect(json.matrix_hash).toBe(matrix.matrix_hash);
    expect(json.rounds).toBe(4);
    expect(json.has_blackout).toBe(true);
    expect(json.blackout_rounds).toEqual([2]);
    expect(json.fronts.find((f: { dimension: string }) => f.dimension === "Cap")).toMatchObject({
      cells: ["above", "below", "below", "above"],
      below_rounds: 2,
      stated_rounds: 4,
    });
  });

  it("renders a none-blackout line when no round is a full column", async () => {
    const summary = renderCoherenceMatrixSummary(
      await computeCoherenceMatrix(await rounds({ Cap: [B, B], Term: [A, A] })),
    );
    expect(summary).toMatch(/blackout: none/);
  });

  it("pluralizes the blackout-round line for multiple rounds", async () => {
    const summary = renderCoherenceMatrixSummary(
      await computeCoherenceMatrix(await rounds({ Cap: [B, B], Term: [B, B] })),
    );
    expect(summary).toMatch(/blackout \(every stated front below floor\): rounds 1, 2\./);
  });
});
