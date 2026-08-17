import { describe, expect, it } from "vitest";

import { bundlePostureCoherence, type CoherenceInput } from "./posture-coherence.js";
import type { NegotiationPosture, NegotiationTier } from "../playbooks/custom-interpreter.js";

import { computeCoherenceAffinity } from "./coherence-affinity.js";
import { computeCoherenceVolatility } from "./coherence-volatility.js";
import { computeCoherenceSynchrony } from "./coherence-synchrony.js";
import { computeCoherenceSettling } from "./coherence-settling.js";
import { computeCoherenceOnset } from "./coherence-onset.js";
import { computeCoherencePersistence } from "./coherence-persistence.js";
import { computeCoherenceBreadth } from "./coherence-breadth.js";

/**
 * Adversarial coverage for the coherence family.
 *
 * These modules are hand-derived variants of one template, and each has its own
 * unit test — but those tests exercise the shapes the module was written for.
 * This one feeds every entry point the inputs nobody designs for: no rounds,
 * one round, rounds where every score ties (so a "pick the best" comparator has
 * no winner), and a front label containing a non-BMP character (which is two
 * UTF-16 code units, so any length-based slicing can split it).
 *
 * The assertions are properties rather than expected values: no NaN or
 * Infinity anywhere in the result, no ratio outside [0, 1], and no U+FFFD in
 * any rendered string. A module can change what it computes without breaking
 * this; it breaks only if a result stops being well-formed.
 */

function posture(map: Record<string, NegotiationTier>): NegotiationPosture {
  return {
    positions: Object.entries(map).map(([dimension, tier]) => ({ dimension, tier })),
    counts: { ideal: 0, acceptable: 0, below_acceptable: 0, unevaluable: 0 },
    posture_hash: "test",
  };
}

const bundle = (...docs: Array<[string, Record<string, NegotiationTier>]>): CoherenceInput[] =>
  docs.map(([document, map]) => ({ document, posture: posture(map) }));

/** One round = two documents; each front's binding floor is the weaker tier. */
const round = async (
  a: Record<string, NegotiationTier>,
  b: Record<string, NegotiationTier> = a,
): Promise<Awaited<ReturnType<typeof bundlePostureCoherence>>> =>
  await bundlePostureCoherence(bundle(["msa.docx", a], ["order.docx", b]));

type Rounds = Awaited<ReturnType<typeof bundlePostureCoherence>>[];

const COMPUTERS: Array<[string, (rounds: Rounds) => Promise<unknown>]> = [
  ["affinity", (r) => computeCoherenceAffinity(r)],
  ["volatility", (r) => computeCoherenceVolatility(r)],
  ["synchrony", (r) => computeCoherenceSynchrony(r)],
  ["settling", (r) => computeCoherenceSettling(r)],
  ["onset", (r) => computeCoherenceOnset(r)],
  ["persistence", (r) => computeCoherencePersistence(r)],
  ["breadth", (r) => computeCoherenceBreadth(r)],
];

/** Collect every way a result could be malformed. */
function malformed(label: string, value: unknown, out: string[] = []): string[] {
  if (typeof value === "number") {
    if (!Number.isFinite(value)) out.push(`${label} = ${value}`);
    if (/ratio|share|rate|fraction/i.test(label) && (value < 0 || value > 1)) {
      out.push(`${label} = ${value}, outside [0,1]`);
    }
  } else if (typeof value === "string") {
    if (value.includes("�")) out.push(`${label} contains U+FFFD`);
  } else if (Array.isArray(value)) {
    value.forEach((v, i) => malformed(`${label}[${i}]`, v, out));
  } else if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) malformed(`${label}.${k}`, v, out);
  }
  return out;
}

describe("coherence family — adversarial inputs", () => {
  it.each(COMPUTERS)(
    "%s rejects a round set too short to have a transition",
    async (_l, compute) => {
      await expect(compute([])).rejects.toThrow(/at least two rounds/i);
      await expect(compute([await round({ Cap: "ideal" }, { Cap: "acceptable" })])).rejects.toThrow(
        /at least two rounds/i,
      );
    },
  );

  it.each(COMPUTERS)(
    "%s returns a well-formed result when every front is tied",
    async (label, compute) => {
      const rounds = [
        await round({ A: "ideal", B: "ideal" }),
        await round({ A: "ideal", B: "ideal" }),
      ];
      expect(malformed(label, await compute(rounds))).toEqual([]);
    },
  );

  // A non-BMP label is two UTF-16 code units, so any length-based slice can
  // cut it in half and emit U+FFFD into a rendered summary.
  it.each(COMPUTERS)(
    "%s returns a well-formed result for a non-BMP front label",
    async (label, compute) => {
      const rounds = [
        await round({ "𝔸 Cap": "ideal" }, { "𝔸 Cap": "acceptable" }),
        await round({ "𝔸 Cap": "below-acceptable" }),
      ];
      expect(malformed(label, await compute(rounds))).toEqual([]);
    },
  );

  it.each(COMPUTERS)("%s returns a well-formed result on real movement", async (label, compute) => {
    const rounds = [
      await round({ Cap: "ideal", Term: "acceptable" }, { Cap: "acceptable", Term: "acceptable" }),
      await round({ Cap: "below-acceptable", Term: "ideal" }),
    ];
    expect(malformed(label, await compute(rounds))).toEqual([]);
  });
});
