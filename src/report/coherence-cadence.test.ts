import { describe, expect, it } from "vitest";
import {
  computeCoherenceCadence,
  exposureOscillates,
  buildCoherenceCadenceJson,
  renderCoherenceCadenceSummary,
} from "./coherence-cadence.js";
import { computeCoherenceVolatility } from "./coherence-volatility.js";
import { computeCoherenceTenure } from "./coherence-tenure.js";
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

describe("computeCoherenceCadence (spec-v39 — per-front floor-crossing churn rate)", () => {
  it("measures an oscillating front — crosses on a strict majority of its transitions", async () => {
    // Term flips every transition (3 of 3 crossings → oscillating); Cap crosses once of 3 (settled).
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r0
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // r1: both↓
      mk({ Cap: "below-acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // r2: Term↑
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // r3: Term↓
    ]);
    const cad = await computeCoherenceCadence(rounds);

    const term = cad.fronts.find((f) => f.dimension === "Term")!;
    expect(term.stated_rounds).toBe(4);
    expect(term.transitions).toBe(3);
    expect(term.crossings).toBe(3);
    expect(term.cadence).toBe(1);
    expect(term.class).toBe("oscillating");

    const cap = cad.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.transitions).toBe(3);
    expect(cap.crossings).toBe(1); // fell at t0, then held below
    expect(cap.cadence).toBeCloseTo(1 / 3);
    expect(cap.class).toBe("settled");

    expect(cad.oscillating).toBe(true);
    expect(exposureOscillates(cad)).toBe(true);
    expect(cad.busiest_dimension).toBe("Term");
    expect(cad.max_cadence).toBe(1);
    expect(cad.class_counts).toMatchObject({ oscillating: 1, settled: 1 });
  });

  it("a front that crosses but not for a strict majority of its transitions clears the gate", async () => {
    // Cap crosses twice of four transitions (50% — not a strict majority) → settled, gate clears.
    const rounds = await Promise.all([
      mk({ Cap: "acceptable" }, { Cap: "ideal" }), // r0
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }), // r1: ↓ (cross)
      mk({ Cap: "acceptable" }, { Cap: "ideal" }), // r2: ↑ (cross)
      mk({ Cap: "acceptable" }, { Cap: "ideal" }), // r3: hold
      mk({ Cap: "acceptable" }, { Cap: "ideal" }), // r4: hold
    ]);
    const cad = await computeCoherenceCadence(rounds);
    const cap = cad.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.transitions).toBe(4);
    expect(cap.crossings).toBe(2);
    expect(cap.cadence).toBe(0.5);
    expect(cap.class).toBe("settled");
    expect(cad.oscillating).toBe(false);
  });

  it("is distinct from v24 volatility (raw count) — a volatile front can be settled here", async () => {
    // Cap crosses twice over four transitions: v24 calls it volatile (≥ 2 crossings); v39 calls it
    // settled (a 50% rate). The two axes genuinely diverge.
    const rounds = await Promise.all([
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }), // cross
      mk({ Cap: "acceptable" }, { Cap: "ideal" }), // cross
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
    ]);
    const cad = await computeCoherenceCadence(rounds);
    const vol = await computeCoherenceVolatility(rounds);
    const capCad = cad.fronts.find((f) => f.dimension === "Cap")!;
    const capVol = vol.fronts.find((f) => f.dimension === "Cap")!;
    expect(capVol.crossings).toBe(2);
    expect(capVol.volatility).toBe("volatile"); // v24 gate trips on the count
    expect(capCad.class).toBe("settled"); // v39 gate clears on the rate
    // total_crossings equals v24's crossings summed across fronts, by construction.
    expect(cad.total_crossings).toBe(vol.fronts.reduce((s, f) => s + f.crossings, 0));
  });

  it("is distinct from v31 tenure (dwell) — same below-floor share, opposite churn", async () => {
    // Both fronts sit below floor in 2 of their 4 stated rounds (a 50% tenure, minority to v31), but
    // Cap dips once and holds (settled churn) while Flip alternates every round (oscillating churn).
    const rounds = await Promise.all([
      mk(
        { Cap: "below-acceptable", Flip: "below-acceptable" },
        { Cap: "ideal", Flip: "ideal" },
      ), // r0: Cap below, Flip below
      mk(
        { Cap: "below-acceptable", Flip: "acceptable" },
        { Cap: "ideal", Flip: "ideal" },
      ), // r1: Cap below, Flip↑
      mk({ Cap: "acceptable", Flip: "below-acceptable" }, { Cap: "ideal", Flip: "ideal" }), // r2: Cap↑, Flip↓
      mk({ Cap: "acceptable", Flip: "acceptable" }, { Cap: "ideal", Flip: "ideal" }), // r3: Flip↑
    ]);
    const cad = await computeCoherenceCadence(rounds);
    const ten = await computeCoherenceTenure(rounds);

    const capTen = ten.fronts.find((f) => f.dimension === "Cap")!;
    const flipTen = ten.fronts.find((f) => f.dimension === "Flip")!;
    expect(capTen.below_rounds).toBe(2);
    expect(flipTen.below_rounds).toBe(2); // identical dwell
    expect(capTen.tenure).toBe("minority");
    expect(flipTen.tenure).toBe("minority");

    const capCad = cad.fronts.find((f) => f.dimension === "Cap")!;
    const flipCad = cad.fronts.find((f) => f.dimension === "Flip")!;
    expect(capCad.crossings).toBe(1); // one dip, then held
    expect(capCad.class).toBe("settled");
    expect(flipCad.crossings).toBe(3); // flips every transition
    expect(flipCad.class).toBe("oscillating"); // opposite churn, identical dwell
  });

  it("treats silence as neither a crossing nor a transition (§3) — across a silent gap on the revealing step", async () => {
    // Cap: acceptable, below (cross), silent, acceptable (cross, revealed). Stated 3 rounds → 2
    // transitions, both crossings → oscillating; the silent round neither crosses nor counts.
    const rounds = await Promise.all([
      mk({ Cap: "acceptable" }, { Cap: "ideal" }), // r0
      mk({ Cap: "below-acceptable" }, { Cap: "ideal" }), // r1: ↓
      mk({ Cap: "unevaluable" }, { Cap: "unevaluable" }), // r2: silent
      mk({ Cap: "acceptable" }, { Cap: "ideal" }), // r3: ↑ revealed
    ]);
    const cad = await computeCoherenceCadence(rounds);
    const cap = cad.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.stated_rounds).toBe(3);
    expect(cap.transitions).toBe(2);
    expect(cap.crossings).toBe(2);
    expect(cap.class).toBe("oscillating");
  });

  it("classes a front stated only once as static (no transition to measure)", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Once: "below-acceptable" }, { Cap: "ideal", Once: "ideal" }), // r0
      mk({ Cap: "acceptable" }, { Cap: "ideal" }), // r1: Once absent
      mk({ Cap: "acceptable" }, { Cap: "ideal" }), // r2: Once absent
    ]);
    const cad = await computeCoherenceCadence(rounds);
    const once = cad.fronts.find((f) => f.dimension === "Once")!;
    expect(once.stated_rounds).toBe(1);
    expect(once.transitions).toBe(0);
    expect(once.crossings).toBe(0);
    expect(once.cadence).toBeNull();
    expect(once.class).toBe("static");
  });

  it("classes a never-stated front as unstated and never ranks it", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
    ]);
    const cad = await computeCoherenceCadence(rounds);
    // Cap never crosses → settled with zero churn; no oscillating front, no busiest.
    expect(cad.fronts.find((f) => f.dimension === "Cap")!.class).toBe("settled");
    expect(cad.busiest_dimension).toBeNull();
    expect(cad.max_cadence).toBeNull();
    expect(cad.oscillating).toBe(false);
  });

  it("picks the busiest churn across fronts by exact integer ratio (ratio beats label order)", async () => {
    // Aaa crosses 2 of 4 transitions (50%); Zzz crosses 1 of 1 (100%) — Zzz wins though it sorts last.
    const rounds = await Promise.all([
      mk({ Aaa: "acceptable", Zzz: "acceptable" }, { Aaa: "ideal", Zzz: "ideal" }), // r0
      mk({ Aaa: "below-acceptable", Zzz: "below-acceptable" }, { Aaa: "ideal", Zzz: "ideal" }), // r1: Aaa↓, Zzz↓
      mk({ Aaa: "below-acceptable" }, { Aaa: "ideal" }), // r2: Aaa hold; Zzz now absent
      mk({ Aaa: "acceptable" }, { Aaa: "ideal" }), // r3: Aaa↑
      mk({ Aaa: "acceptable" }, { Aaa: "ideal" }), // r4: hold
    ]);
    const cad = await computeCoherenceCadence(rounds);
    const aaa = cad.fronts.find((f) => f.dimension === "Aaa")!;
    const zzz = cad.fronts.find((f) => f.dimension === "Zzz")!;
    expect(aaa.crossings).toBe(2); // ↓ at t0, ↑ at t2 (Aaa stated all 5 rounds → 4 transitions)
    expect(aaa.transitions).toBe(4);
    expect(zzz.crossings).toBe(1); // ↓ at its one transition
    expect(zzz.transitions).toBe(1);
    expect(cad.busiest_dimension).toBe("Zzz"); // 100% beats 50%, though Zzz sorts after Aaa
    expect(cad.max_cadence).toBe(1);
  });

  it("breaks a busiest-churn tie by earliest front (localeCompare order)", async () => {
    // Both fronts flip every transition (100%); the earliest label wins the tie.
    const rounds = await Promise.all([
      mk({ Aaa: "acceptable", Bbb: "acceptable" }, { Aaa: "ideal", Bbb: "ideal" }),
      mk({ Aaa: "below-acceptable", Bbb: "below-acceptable" }, { Aaa: "ideal", Bbb: "ideal" }), // both↓
      mk({ Aaa: "acceptable", Bbb: "acceptable" }, { Aaa: "ideal", Bbb: "ideal" }), // both↑
    ]);
    const cad = await computeCoherenceCadence(rounds);
    expect(cad.max_cadence).toBe(1);
    expect(cad.busiest_dimension).toBe("Aaa");
  });

  it("is deterministic: identical rounds in identical order → identical cadence_hash", async () => {
    const build = () =>
      Promise.all([
        mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
        mk({ Cap: "below-acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
        mk({ Cap: "acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
      ]);
    const a = await computeCoherenceCadence(await build());
    const c = await computeCoherenceCadence(await build());
    expect(a.cadence_hash).toBe(c.cadence_hash);
    expect(a.cadence_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("throws on fewer than two rounds", async () => {
    const rounds = [await mk({ Cap: "ideal" }, { Cap: "ideal" })];
    await expect(computeCoherenceCadence(rounds)).rejects.toThrow(/at least two rounds/);
  });

  it("renders the busiest-churn verdict and stable JSON", async () => {
    const rounds = await Promise.all([
      mk({ Term: "acceptable" }, { Term: "ideal" }),
      mk({ Term: "below-acceptable" }, { Term: "ideal" }), // ↓
      mk({ Term: "acceptable" }, { Term: "ideal" }), // ↑
    ]);
    const cad = await computeCoherenceCadence(rounds);
    const summary = renderCoherenceCadenceSummary(cad);
    expect(summary).toContain("Coherence exposure cadence across 3 rounds");
    expect(summary).toMatch(/busiest churn: Term — crossed the floor on 100% of its transitions/);
    expect(summary).toMatch(/1 oscillating/);
    expect(summary).toMatch(/cadence_hash: [0-9a-f]{64}/);

    const json = JSON.parse(buildCoherenceCadenceJson(cad));
    expect(json.schema).toBe("vaulytica.posture-cadence.v1");
    expect(json.cadence_hash).toBe(cad.cadence_hash);
    expect(json.rounds).toBe(3);
    expect(json.total_crossings).toBe(2);
    expect(json.total_transitions).toBe(2);
    expect(json.busiest_dimension).toBe("Term");
    expect(json.oscillating).toBe(true);
    expect(json.fronts[0]).toMatchObject({
      dimension: "Term",
      transitions: 2,
      crossings: 2,
      class: "oscillating",
    });
  });

  it("renders a none-crossed verdict distinctly", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
      mk({ Cap: "acceptable" }, { Cap: "ideal" }),
    ]);
    const summary = renderCoherenceCadenceSummary(await computeCoherenceCadence(rounds));
    expect(summary).toMatch(/busiest churn: none/);
  });
});
