import { describe, expect, it } from "vitest";
import {
  computeCoherenceDuration,
  exposureLingers,
  buildCoherenceDurationJson,
  renderCoherenceDurationSummary,
} from "./coherence-duration.js";
import { computeCoherenceLatency } from "./coherence-latency.js";
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

describe("computeCoherenceDuration (spec-v40 — per-front mean recovered-exposure duration)", () => {
  it("measures a lingering front (mean ≥ 2 rounds) against a brief one (mean < 2)", async () => {
    // Term: one episode of 3 rounds below → mean 3 → lingering.
    // Cap:  one episode of 1 round below  → mean 1 → brief.
    const rounds = await Promise.all([
      mk({ Cap: A, Term: A }, { Cap: "ideal", Term: "ideal" }), // r1
      mk({ Cap: B, Term: B }, { Cap: "ideal", Term: "ideal" }), // r2: both fall
      mk({ Cap: A, Term: B }, { Cap: "ideal", Term: "ideal" }), // r3: Cap recovers (lat 1), Term holds below
      mk({ Cap: A, Term: B }, { Cap: "ideal", Term: "ideal" }), // r4: Term holds below
      mk({ Cap: A, Term: A }, { Cap: "ideal", Term: "ideal" }), // r5: Term recovers (lat 3)
    ]);
    const dur = await computeCoherenceDuration(rounds);

    const term = dur.fronts.find((f) => f.dimension === "Term")!;
    expect(term.latencies).toEqual([3]);
    expect(term.closed_episodes).toBe(1);
    expect(term.mean_duration).toBe(3);
    expect(term.class).toBe("lingering");

    const cap = dur.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.latencies).toEqual([1]);
    expect(cap.mean_duration).toBe(1);
    expect(cap.class).toBe("brief");

    expect(dur.lingering).toBe(true);
    expect(exposureLingers(dur)).toBe(true);
    expect(dur.longest_mean_dimension).toBe("Term");
    expect(dur.max_mean).toBe(3);
    expect(dur.class_counts).toMatchObject({ lingering: 1, brief: 1 });
  });

  it("is a central-tendency read, not an extreme — a front with one bad round stays brief", async () => {
    // Three prompt recoveries (1 round each) and one slow one (4 rounds): mean 7/4 = 1.75 < 2 → brief,
    // yet max_latency 4. A `max_latency` extreme would flag it; the mean does not — it usually recovers
    // the next round.
    const rounds = await walk(
      A,
      B,
      A, // ep1: lat 1
      B,
      A, // ep2: lat 1
      B,
      A, // ep3: lat 1
      B,
      B,
      B,
      B,
      A, // ep4: lat 4
    );
    const dur = await computeCoherenceDuration(rounds);
    const cap = dur.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.latencies).toEqual([1, 1, 1, 4]);
    expect(cap.max_latency).toBe(4); // v28's extreme: a 4-round worst recovery
    expect(cap.total_rounds).toBe(7);
    expect(cap.closed_episodes).toBe(4);
    expect(cap.mean_duration).toBe(1.75); // central tendency: under two rounds
    expect(cap.class).toBe("brief");
    expect(dur.lingering).toBe(false); // the gate reads the mean, not the worst episode
  });

  it("can rank-swap against v28's slowest single recovery (mean vs max)", async () => {
    // Spike: episodes [1, 6] → max 6 (the deal's slowest), mean 3.5.
    // Drag:  episodes [4, 4] → max 4, mean 4 (the chronic lingerer).
    const rounds = await Promise.all([
      mk({ Spike: A, Drag: A }, { Spike: "ideal", Drag: "ideal" }), // r1
      mk({ Spike: B, Drag: B }, { Spike: "ideal", Drag: "ideal" }), // r2: both fall
      mk({ Spike: A, Drag: B }, { Spike: "ideal", Drag: "ideal" }), // r3: Spike recovers (lat 1); Drag below
      mk({ Spike: B, Drag: B }, { Spike: "ideal", Drag: "ideal" }), // r4: Spike falls; Drag below
      mk({ Spike: B, Drag: B }, { Spike: "ideal", Drag: "ideal" }), // r5: Drag below (4th)
      mk({ Spike: B, Drag: A }, { Spike: "ideal", Drag: "ideal" }), // r6: Drag recovers (lat 4); Spike below
      mk({ Spike: B, Drag: B }, { Spike: "ideal", Drag: "ideal" }), // r7: Drag falls; Spike below
      mk({ Spike: B, Drag: B }, { Spike: "ideal", Drag: "ideal" }), // r8
      mk({ Spike: B, Drag: B }, { Spike: "ideal", Drag: "ideal" }), // r9
      mk({ Spike: A, Drag: B }, { Spike: "ideal", Drag: "ideal" }), // r10: Spike recovers (lat 5)
      mk({ Spike: A, Drag: A }, { Spike: "ideal", Drag: "ideal" }), // r11: Drag recovers (lat 4)
    ]);
    const dur = await computeCoherenceDuration(rounds);
    const lat = await computeCoherenceLatency(rounds);

    const spike = dur.fronts.find((f) => f.dimension === "Spike")!;
    const drag = dur.fronts.find((f) => f.dimension === "Drag")!;
    expect(spike.latencies).toEqual([1, 6]);
    expect(spike.mean_duration).toBe(3.5);
    expect(drag.latencies).toEqual([4, 4]);
    expect(drag.mean_duration).toBe(4);

    // v28 names Spike the slowest single recovery (max 6); v40 names Drag the chronic lingerer (mean 4).
    expect(lat.slowest_dimension).toBe("Spike");
    expect(lat.max_latency).toBe(6);
    expect(dur.longest_mean_dimension).toBe("Drag");
    expect(dur.max_mean).toBe(4);
  });

  it("excludes an open episode from the mean but counts it (§3 — an unbounded duration)", async () => {
    // Cap: recovers once (lat 3), then falls again and never recovers — mean over the closed one only.
    const rounds = await walk(A, B, B, B, A, B, B);
    const dur = await computeCoherenceDuration(rounds);
    const cap = dur.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.latencies).toEqual([3]);
    expect(cap.closed_episodes).toBe(1);
    expect(cap.open_episodes).toBe(1);
    expect(cap.mean_duration).toBe(3);
    expect(cap.class).toBe("lingering");
  });

  it("classes a front that fell and never recovered as open (no finite mean)", async () => {
    const rounds = await walk(A, B, B);
    const dur = await computeCoherenceDuration(rounds);
    const cap = dur.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.closed_episodes).toBe(0);
    expect(cap.open_episodes).toBe(1);
    expect(cap.mean_duration).toBeNull();
    expect(cap.class).toBe("open");
    expect(dur.lingering).toBe(false); // v28's gate owns the unrecovered fall; v40 clears
  });

  it("classes a front that never fell as steady, and a never-stated front as unstated", async () => {
    const rounds = await Promise.all([
      mk({ Cap: A, Term: A }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: A }, { Cap: "ideal" }), // Term now absent
    ]);
    const dur = await computeCoherenceDuration(rounds);
    expect(dur.fronts.find((f) => f.dimension === "Cap")!.class).toBe("steady"); // stated, never fell
    expect(dur.longest_mean_dimension).toBeNull();
    expect(dur.max_mean).toBeNull();
  });

  it("classes a never-stated front as unstated", async () => {
    const rounds = await Promise.all([
      mk({ Cap: A }, { Cap: "ideal" }),
      mk({ Cap: A }, { Cap: "ideal" }),
    ]);
    const dur = await computeCoherenceDuration(rounds);
    expect(dur.fronts.find((f) => f.dimension === "Cap")!.class).toBe("steady");
    expect(dur.lingering).toBe(false);
  });

  it("picks the longest mean across fronts by exact integer ratio (ratio beats label order)", async () => {
    // Aaa: episodes [1, 1] → mean 1; Zzz: one episode [3] → mean 3 — Zzz wins though it sorts last.
    const rounds = await Promise.all([
      mk({ Aaa: A, Zzz: A }, { Aaa: "ideal", Zzz: "ideal" }), // r1
      mk({ Aaa: B, Zzz: B }, { Aaa: "ideal", Zzz: "ideal" }), // r2: both fall
      mk({ Aaa: A, Zzz: B }, { Aaa: "ideal", Zzz: "ideal" }), // r3: Aaa recovers (lat 1); Zzz below
      mk({ Aaa: B, Zzz: B }, { Aaa: "ideal", Zzz: "ideal" }), // r4: Aaa falls; Zzz below
      mk({ Aaa: A, Zzz: A }, { Aaa: "ideal", Zzz: "ideal" }), // r5: Aaa recovers (lat 1); Zzz recovers (lat 3)
    ]);
    const dur = await computeCoherenceDuration(rounds);
    const aaa = dur.fronts.find((f) => f.dimension === "Aaa")!;
    const zzz = dur.fronts.find((f) => f.dimension === "Zzz")!;
    expect(aaa.mean_duration).toBe(1);
    expect(zzz.mean_duration).toBe(3);
    expect(dur.longest_mean_dimension).toBe("Zzz"); // 3 beats 1, though Zzz sorts after Aaa
    expect(dur.max_mean).toBe(3);
  });

  it("breaks a longest-mean tie by earliest front (localeCompare order)", async () => {
    // Both fronts have one episode of 2 rounds (mean 2); the earliest label wins the tie.
    const rounds = await Promise.all([
      mk({ Aaa: A, Bbb: A }, { Aaa: "ideal", Bbb: "ideal" }),
      mk({ Aaa: B, Bbb: B }, { Aaa: "ideal", Bbb: "ideal" }), // both fall
      mk({ Aaa: B, Bbb: B }, { Aaa: "ideal", Bbb: "ideal" }), // both below
      mk({ Aaa: A, Bbb: A }, { Aaa: "ideal", Bbb: "ideal" }), // both recover (lat 2)
    ]);
    const dur = await computeCoherenceDuration(rounds);
    expect(dur.max_mean).toBe(2);
    expect(dur.longest_mean_dimension).toBe("Aaa");
  });

  it("ties the deal-level totals to v28 by construction", async () => {
    const rounds = await walk(A, B, A, B, B, A, B, B); // ep1 lat1, ep2 lat2, then an open fall
    const dur = await computeCoherenceDuration(rounds);
    const lat = await computeCoherenceLatency(rounds);
    expect(dur.total_closed_episodes).toBe(lat.recovered_count);
    expect(dur.total_open_episodes).toBe(lat.open_count);
    const cap = dur.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.latencies).toEqual([1, 2]);
    expect(cap.open_episodes).toBe(1);
    expect(cap.mean_duration).toBe(1.5);
    expect(cap.class).toBe("brief"); // mean 1.5 < 2 despite the open fall (v28's gate owns that)
  });

  it("is deterministic: identical rounds in identical order → identical duration_hash", async () => {
    const build = () => walk(A, B, B, A, B, A);
    const a = await computeCoherenceDuration(await build());
    const c = await computeCoherenceDuration(await build());
    expect(a.duration_hash).toBe(c.duration_hash);
    expect(a.duration_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("throws on fewer than two rounds", async () => {
    const rounds = [await mk({ Cap: "ideal" }, { Cap: "ideal" })];
    await expect(computeCoherenceDuration(rounds)).rejects.toThrow(/at least two rounds/);
  });

  it("renders the chronic-lingerer verdict and stable JSON", async () => {
    const rounds = await walk(A, B, B, B, A); // one episode, lat 3
    const dur = await computeCoherenceDuration(rounds);
    const summary = renderCoherenceDurationSummary(dur);
    expect(summary).toContain("Coherence exposure duration across 5 rounds");
    expect(summary).toMatch(
      /chronic lingerer: Cap — recovered exposures averaged 3 rounds below floor/,
    );
    expect(summary).toMatch(/1 lingering/);
    expect(summary).toMatch(/duration_hash: [0-9a-f]{64}/);

    const json = JSON.parse(buildCoherenceDurationJson(dur));
    expect(json.schema).toBe("vaulytica.posture-duration.v1");
    expect(json.duration_hash).toBe(dur.duration_hash);
    expect(json.rounds).toBe(5);
    expect(json.total_closed_episodes).toBe(1);
    expect(json.longest_mean_dimension).toBe("Cap");
    expect(json.lingering).toBe(true);
    expect(json.fronts[0]).toMatchObject({
      dimension: "Cap",
      closed_episodes: 1,
      mean_duration: 3,
      class: "lingering",
    });
  });

  it("renders a none-recovered verdict distinctly", async () => {
    const rounds = await walk(A, A); // never falls
    const summary = renderCoherenceDurationSummary(await computeCoherenceDuration(rounds));
    expect(summary).toMatch(/chronic lingerer: none/);
  });
});
