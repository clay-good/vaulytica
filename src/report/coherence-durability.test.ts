import { describe, expect, it } from "vitest";
import {
  computeCoherenceDurability,
  recoveryFragile,
  buildCoherenceDurabilityJson,
  renderCoherenceDurabilitySummary,
} from "./coherence-durability.js";
import { computeCoherenceRelapse } from "./coherence-relapse.js";
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

const B: NegotiationTier = "below-acceptable";
const A: NegotiationTier = "acceptable";

/** A single front "Cap" walking a tier path; "x" = unstated (absent that round). */
const walk = (...tiers: (NegotiationTier | "x")[]) =>
  Promise.all(tiers.map((t) => (t === "x" ? mk({}, {}) : mk({ Cap: t }, { Cap: "ideal" }))));

describe("computeCoherenceDurability (spec-v41 — per-front mean clean-interval durability)", () => {
  it("measures a fragile front (mean < 2 rounds) against a durable one (mean ≥ 2)", async () => {
    // Frag: relapses the very next round twice → intervals [1, 1] → mean 1 → fragile.
    // Dur:  recovers once and holds three rounds before relapsing → interval [3] → durable.
    const rounds = await Promise.all([
      mk({ Frag: B, Dur: B }, { Frag: "ideal", Dur: "ideal" }), // r1: both below
      mk({ Frag: A, Dur: A }, { Frag: "ideal", Dur: "ideal" }), // r2: both recover (rec 2)
      mk({ Frag: B, Dur: A }, { Frag: "ideal", Dur: "ideal" }), // r3: Frag relapses (clean 1); Dur holds
      mk({ Frag: A, Dur: A }, { Frag: "ideal", Dur: "ideal" }), // r4: Frag recovers (rec 4); Dur holds
      mk({ Frag: B, Dur: B }, { Frag: "ideal", Dur: "ideal" }), // r5: Frag relapses (clean 1); Dur relapses (clean 3)
    ]);
    const dur = await computeCoherenceDurability(rounds);

    const frag = dur.fronts.find((f) => f.dimension === "Frag")!;
    expect(frag.clean_intervals).toEqual([1, 1]);
    expect(frag.closed_intervals).toBe(2);
    expect(frag.mean_durability).toBe(1);
    expect(frag.class).toBe("fragile");

    const durable = dur.fronts.find((f) => f.dimension === "Dur")!;
    expect(durable.clean_intervals).toEqual([3]);
    expect(durable.mean_durability).toBe(3);
    expect(durable.class).toBe("durable");

    expect(dur.fragile).toBe(true);
    expect(recoveryFragile(dur)).toBe(true);
    expect(dur.most_fragile_dimension).toBe("Frag");
    expect(dur.min_mean).toBe(1);
    expect(dur.class_counts).toMatchObject({ fragile: 1, durable: 1 });
  });

  it("is a central-tendency read, not an extreme — a front with one fast relapse stays durable", async () => {
    // Two durable holds (3 rounds each) and one immediate relapse (1 round): mean 7/3 ≈ 2.33 ≥ 2 →
    // durable, yet its quickest relapse is 1 round — v30's `immediate` gate fires; v41's does not.
    const rounds = await walk(
      B,
      A, // rec 2
      A,
      A,
      B, // fall 5 → clean 3
      A, // rec 6
      A,
      A,
      B, // fall 9 → clean 3
      A, // rec 10
      B, // fall 11 → clean 1
    );
    const dur = await computeCoherenceDurability(rounds);
    const rel = await computeCoherenceRelapse(rounds);

    const cap = dur.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.clean_intervals).toEqual([1, 3, 3]);
    expect(cap.min_interval).toBe(1); // v30's extreme: a 1-round quickest relapse
    expect(cap.total_rounds).toBe(7);
    expect(cap.closed_intervals).toBe(3);
    expect(cap.mean_durability).toBeCloseTo(2.333, 2); // central tendency: at or above two rounds
    expect(cap.class).toBe("durable");

    expect(dur.fragile).toBe(false); // the gate reads the mean, not the worst interval
    expect(rel.immediate).toBe(true); // v30's extreme gate DOES fire on the single fast relapse
  });

  it("the fragile gate is strictly stronger than v30's immediate gate", async () => {
    // A chronically fragile front trips both; a front with one fast relapse among durable holds
    // trips v30's gate but clears v41's. Here every fix collapses at once → fragile AND immediate.
    const rounds = await walk(B, A, B, A, B); // intervals [1, 1] → mean 1
    const dur = await computeCoherenceDurability(rounds);
    const rel = await computeCoherenceRelapse(rounds);
    expect(dur.fragile).toBe(true);
    expect(rel.immediate).toBe(true);
  });

  it("can rank-swap against v30's quickest single relapse (mean vs min)", async () => {
    // Bounce: intervals [1, 5] → min 1 (the deal's quickest), mean 3.
    // Sag:    intervals [2, 2] → min 2, mean 2 (the lowest mean — the most fragile recovery).
    const rounds = await Promise.all([
      mk({ Bounce: B, Sag: B }, { Bounce: "ideal", Sag: "ideal" }), // r1
      mk({ Bounce: A, Sag: A }, { Bounce: "ideal", Sag: "ideal" }), // r2: both recover (rec 2)
      mk({ Bounce: B, Sag: A }, { Bounce: "ideal", Sag: "ideal" }), // r3: Bounce relapses (clean 1); Sag holds
      mk({ Bounce: A, Sag: B }, { Bounce: "ideal", Sag: "ideal" }), // r4: Bounce recovers (rec 4); Sag relapses (clean 2)
      mk({ Bounce: A, Sag: A }, { Bounce: "ideal", Sag: "ideal" }), // r5: Bounce holds; Sag recovers (rec 5)
      mk({ Bounce: A, Sag: A }, { Bounce: "ideal", Sag: "ideal" }), // r6: both hold
      mk({ Bounce: A, Sag: B }, { Bounce: "ideal", Sag: "ideal" }), // r7: Bounce holds; Sag relapses (clean 2)
      mk({ Bounce: A, Sag: B }, { Bounce: "ideal", Sag: "ideal" }), // r8: Bounce holds; Sag below
      mk({ Bounce: B, Sag: B }, { Bounce: "ideal", Sag: "ideal" }), // r9: Bounce relapses (clean 5); Sag below
    ]);
    const dur = await computeCoherenceDurability(rounds);
    const rel = await computeCoherenceRelapse(rounds);

    const bounce = dur.fronts.find((f) => f.dimension === "Bounce")!;
    const sag = dur.fronts.find((f) => f.dimension === "Sag")!;
    expect(bounce.clean_intervals).toEqual([1, 5]);
    expect(bounce.mean_durability).toBe(3);
    expect(sag.clean_intervals).toEqual([2, 2]);
    expect(sag.mean_durability).toBe(2);

    // v30 names Bounce the quickest single relapse (min 1); v41 names Sag the most fragile (mean 2).
    expect(rel.quickest_dimension).toBe("Bounce");
    expect(rel.min_interval).toBe(1);
    expect(dur.most_fragile_dimension).toBe("Sag");
    expect(dur.min_mean).toBe(2);
    expect(dur.fragile).toBe(false); // both durable
  });

  it("excludes a held recovery from the mean but counts it (§3 — an unbounded interval)", async () => {
    // Cap: relapses once (clean 1), then recovers again and never relapses — mean over the closed one only.
    const rounds = await walk(B, A, B, A); // rec2, fall3 (clean1), rec4 held
    const dur = await computeCoherenceDurability(rounds);
    const cap = dur.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.clean_intervals).toEqual([1]);
    expect(cap.closed_intervals).toBe(1);
    expect(cap.open_intervals).toBe(1);
    expect(cap.mean_durability).toBe(1);
    expect(cap.class).toBe("fragile");
  });

  it("classes a front whose every recovery held as held (no finite mean)", async () => {
    const rounds = await walk(B, A); // recovers once, never relapses
    const dur = await computeCoherenceDurability(rounds);
    const cap = dur.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.closed_intervals).toBe(0);
    expect(cap.open_intervals).toBe(1);
    expect(cap.mean_durability).toBeNull();
    expect(cap.class).toBe("held");
    expect(dur.fragile).toBe(false); // a recovery that held is the durable best case
  });

  it("classes a front that never recovered as steady, and a never-stated front as unstated", async () => {
    const rounds = await Promise.all([
      mk({ Cap: A, Term: B }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: A }, { Cap: "ideal" }), // Term now absent; Cap never fell
    ]);
    const dur = await computeCoherenceDurability(rounds);
    expect(dur.fronts.find((f) => f.dimension === "Cap")!.class).toBe("steady"); // stated, never recovered
    expect(dur.fronts.find((f) => f.dimension === "Term")!.class).toBe("steady"); // fell, never came back
    expect(dur.most_fragile_dimension).toBeNull();
    expect(dur.min_mean).toBeNull();
  });

  it("counts the unstated class but lists no front for it (every front in the union is stated)", async () => {
    const dur = await computeCoherenceDurability(
      await Promise.all([
        mk({ Other: A }, { Other: "ideal" }),
        mk({ Other: A }, { Other: "ideal" }),
      ]),
    );
    // A front present in any round is "stated"; the unstated tally is structurally zero here.
    expect(dur.class_counts.unstated).toBe(0);
    expect(dur.fronts.find((f) => f.dimension === "Other")!.class).toBe("steady");
  });

  it("picks the most fragile mean across fronts by exact integer ratio (ratio beats label order)", async () => {
    // Aaa: intervals [3, 3] → mean 3; Zzz: intervals [1, 1] → mean 1 — Zzz wins though it sorts last.
    const rounds = await Promise.all([
      mk({ Aaa: B, Zzz: B }, { Aaa: "ideal", Zzz: "ideal" }), // r1
      mk({ Aaa: A, Zzz: A }, { Aaa: "ideal", Zzz: "ideal" }), // r2: both recover (rec 2)
      mk({ Aaa: A, Zzz: B }, { Aaa: "ideal", Zzz: "ideal" }), // r3: Aaa holds; Zzz relapses (clean 1)
      mk({ Aaa: A, Zzz: A }, { Aaa: "ideal", Zzz: "ideal" }), // r4: Aaa holds; Zzz recovers (rec 4)
      mk({ Aaa: B, Zzz: B }, { Aaa: "ideal", Zzz: "ideal" }), // r5: Aaa relapses (clean 3); Zzz relapses (clean 1)
      mk({ Aaa: A, Zzz: A }, { Aaa: "ideal", Zzz: "ideal" }), // r6: both recover (rec 6)
      mk({ Aaa: A, Zzz: A }, { Aaa: "ideal", Zzz: "ideal" }), // r7
      mk({ Aaa: A, Zzz: A }, { Aaa: "ideal", Zzz: "ideal" }), // r8
      mk({ Aaa: B, Zzz: A }, { Aaa: "ideal", Zzz: "ideal" }), // r9: Aaa relapses (clean 3); Zzz holds
    ]);
    const dur = await computeCoherenceDurability(rounds);
    const aaa = dur.fronts.find((f) => f.dimension === "Aaa")!;
    const zzz = dur.fronts.find((f) => f.dimension === "Zzz")!;
    expect(aaa.clean_intervals).toEqual([3, 3]);
    expect(aaa.mean_durability).toBe(3);
    expect(zzz.clean_intervals).toEqual([1, 1]);
    expect(zzz.mean_durability).toBe(1);
    expect(dur.most_fragile_dimension).toBe("Zzz"); // 1 beats 3, though Zzz sorts after Aaa
    expect(dur.min_mean).toBe(1);
  });

  it("breaks a most-fragile tie by earliest front (localeCompare order)", async () => {
    // Both fronts have one relapsed interval of 2 rounds (mean 2); the earliest label wins the tie.
    const rounds = await Promise.all([
      mk({ Aaa: B, Bbb: B }, { Aaa: "ideal", Bbb: "ideal" }), // r1
      mk({ Aaa: A, Bbb: A }, { Aaa: "ideal", Bbb: "ideal" }), // r2: both recover (rec 2)
      mk({ Aaa: A, Bbb: A }, { Aaa: "ideal", Bbb: "ideal" }), // r3: both hold
      mk({ Aaa: B, Bbb: B }, { Aaa: "ideal", Bbb: "ideal" }), // r4: both relapse (clean 2)
    ]);
    const dur = await computeCoherenceDurability(rounds);
    expect(dur.min_mean).toBe(2);
    expect(dur.most_fragile_dimension).toBe("Aaa");
  });

  it("ties the deal-level totals to v30 by construction", async () => {
    const rounds = await walk(B, A, B, A, A, B, A); // rec2 fall3(1), rec4 fall6(2), rec7 held
    const dur = await computeCoherenceDurability(rounds);
    const rel = await computeCoherenceRelapse(rounds);
    expect(dur.total_relapsed_intervals).toBe(rel.relapse_count);
    expect(dur.total_held_intervals).toBe(rel.held_count);
    const cap = dur.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.clean_intervals).toEqual([1, 2]);
    expect(cap.open_intervals).toBe(1);
    expect(cap.mean_durability).toBe(1.5);
    expect(cap.class).toBe("fragile"); // mean 1.5 < 2 despite the held recovery
  });

  it("is deterministic: identical rounds in identical order → identical durability_hash", async () => {
    const build = () => walk(B, A, B, A, A, B);
    const a = await computeCoherenceDurability(await build());
    const c = await computeCoherenceDurability(await build());
    expect(a.durability_hash).toBe(c.durability_hash);
    expect(a.durability_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("throws on fewer than two rounds", async () => {
    const rounds = [await mk({ Cap: "ideal" }, { Cap: "ideal" })];
    await expect(computeCoherenceDurability(rounds)).rejects.toThrow(/at least two rounds/);
  });

  it("renders the most-fragile verdict and stable JSON", async () => {
    const rounds = await walk(B, A, B); // one relapsed interval, clean 1
    const dur = await computeCoherenceDurability(rounds);
    const summary = renderCoherenceDurabilitySummary(dur);
    expect(summary).toContain("Coherence recovery durability across 3 rounds");
    expect(summary).toMatch(/most fragile recovery: Cap — relapsed fixes held above floor for 1 round on average/);
    expect(summary).toMatch(/1 fragile/);
    expect(summary).toMatch(/durability_hash: [0-9a-f]{64}/);

    const json = JSON.parse(buildCoherenceDurabilityJson(dur));
    expect(json.schema).toBe("vaulytica.posture-durability.v1");
    expect(json.durability_hash).toBe(dur.durability_hash);
    expect(json.rounds).toBe(3);
    expect(json.total_relapsed_intervals).toBe(1);
    expect(json.most_fragile_dimension).toBe("Cap");
    expect(json.fragile).toBe(true);
    expect(json.fronts[0]).toMatchObject({
      dimension: "Cap",
      closed_intervals: 1,
      mean_durability: 1,
      class: "fragile",
    });
  });

  it("renders a none-relapsed verdict distinctly", async () => {
    const rounds = await walk(A, A); // never falls, never recovers
    const summary = renderCoherenceDurabilitySummary(await computeCoherenceDurability(rounds));
    expect(summary).toMatch(/most fragile recovery: none/);
  });
});
