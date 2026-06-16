import { describe, expect, it } from "vitest";
import {
  computeCoherenceWeakFront,
  exposurePersistentlyWeak,
  buildCoherenceWeakFrontJson,
  renderCoherenceWeakFrontSummary,
} from "./coherence-weak-front.js";
import { computeCoherenceConcession } from "./coherence-concession.js";
import { computeCoherenceRecoveryOrder } from "./coherence-recovery-order.js";
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

describe("computeCoherenceWeakFront (spec-v38 — persistent weak front: concedes first AND recovers last)", () => {
  it("names a front that both concedes first and recovers last against the same partner", async () => {
    // Cap & Term. Term concedes first (falls before Cap) and recovers last (climbs back after Cap):
    //   r0 all above; r1 Term↓ (t0); r2 Cap↓ (t1); r3 Cap↑ (t2); r4 Term↑ (t3).
    // Falls: Term {0}, Cap {1} → Term concedes first (0<1). Recoveries: Cap {2}, Term {3} → Term last.
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // Term↓ (t0)
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // Cap↓ (t1)
      mk({ Cap: "acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // Cap↑ (t2)
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // Term↑ (t3)
    ]);
    const wf = await computeCoherenceWeakFront(rounds);
    expect(wf.weak_fronts).toEqual(["Term"]);
    expect(wf.most_exposed_front).toBe("Term");
    expect(wf.has_persistent_weak_front).toBe(true);
    expect(exposurePersistentlyWeak(wf)).toBe(true);

    const term = wf.fronts.find((f) => f.dimension === "Term")!;
    expect(term.class).toBe("persistent-weak");
    expect(term.concedes_first_against).toEqual(["Cap"]);
    expect(term.recovers_last_against).toEqual(["Cap"]);
    expect(term.confirmed_against).toEqual(["Cap"]); // same partner on both axes

    // Cap is the mirror: it neither concedes first nor recovers last → omitted entirely.
    expect(wf.fronts.find((f) => f.dimension === "Cap")).toBeUndefined();
    expect(wf.class_counts).toEqual({ "persistent-weak": 1, conceding: 0, lagging: 0 });
  });

  it("distinguishes a conceding-only (volatile) front from a lagging-only front — neither is gated", async () => {
    // Cap concedes first vs Term but recovers first vs Term → conceding-only (volatile).
    // Term recovers last vs Cap but never concedes first → lagging-only. No persistent weak front.
    //   r0 above; r1 Cap↓ (t0); r2 Cap↑ (t1); r3 Term↓ (t2); r4 Term↑ (t3).
    // Falls: Cap {0}, Term {2} → Cap concedes first. Recoveries: Cap {1}, Term {3} → Cap recovers first
    // (so Term recovers last).
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "below-acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // Cap↓ (t0)
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // Cap↑ (t1)
      mk({ Cap: "acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // Term↓ (t2)
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // Term↑ (t3)
    ]);
    const wf = await computeCoherenceWeakFront(rounds);
    expect(wf.has_persistent_weak_front).toBe(false);
    expect(wf.weak_fronts).toEqual([]);
    expect(wf.most_exposed_front).toBeNull();

    const cap = wf.fronts.find((f) => f.dimension === "Cap")!;
    expect(cap.class).toBe("conceding");
    expect(cap.concedes_first_against).toEqual(["Term"]);
    expect(cap.recovers_last_against).toEqual([]);

    const term = wf.fronts.find((f) => f.dimension === "Term")!;
    expect(term.class).toBe("lagging");
    expect(term.recovers_last_against).toEqual(["Cap"]);
    expect(term.concedes_first_against).toEqual([]);

    expect(wf.class_counts).toEqual({ "persistent-weak": 0, conceding: 1, lagging: 1 });
  });

  it("gates a front weak across multiple partners (concession + recovery edges span the book)", async () => {
    // Three fronts. Term concedes first vs Cap and recovers last vs both Cap and Zzz — the weak edges
    // span the book. It is persistently weak; confirmed_against (same-partner on both axes) holds vs Cap.
    const rounds = await Promise.all([
      mk(
        { Cap: "acceptable", Term: "acceptable", Zzz: "acceptable" },
        { Cap: "ideal", Term: "ideal", Zzz: "ideal" },
      ), // r0
      mk(
        { Cap: "acceptable", Term: "below-acceptable", Zzz: "below-acceptable" },
        { Cap: "ideal", Term: "ideal", Zzz: "ideal" },
      ), // r1: Term↓ (t0), Zzz↓ (t0)
      mk(
        { Cap: "below-acceptable", Term: "below-acceptable", Zzz: "below-acceptable" },
        { Cap: "ideal", Term: "ideal", Zzz: "ideal" },
      ), // r2: Cap↓ (t1)
      mk(
        { Cap: "below-acceptable", Term: "below-acceptable", Zzz: "acceptable" },
        { Cap: "ideal", Term: "ideal", Zzz: "ideal" },
      ), // r3: Zzz↑ (t2)
      mk(
        { Cap: "acceptable", Term: "below-acceptable", Zzz: "acceptable" },
        { Cap: "ideal", Term: "ideal", Zzz: "ideal" },
      ), // r4: Cap↑ (t3)
      mk(
        { Cap: "acceptable", Term: "acceptable", Zzz: "acceptable" },
        { Cap: "ideal", Term: "ideal", Zzz: "ideal" },
      ), // r5: Term↑ (t4)
    ]);
    // Falls: Cap {1}, Term {0}, Zzz {0}. Recoveries: Cap {3}, Term {4}, Zzz {2}.
    const wf = await computeCoherenceWeakFront(rounds);
    const term = wf.fronts.find((f) => f.dimension === "Term")!;
    // Concession (Cap,Term): Term first 1, Cap 0 → leading, first_conceder Term → Term concedes first vs Cap.
    expect(term.concedes_first_against).toContain("Cap");
    // Recovery (Term,Zzz): Zzz {2} < Term {4} → leading, last_recoverer Term → Term recovers last vs Zzz.
    expect(term.recovers_last_against).toEqual(["Cap", "Zzz"]);
    expect(term.confirmed_against).toEqual(["Cap"]); // weak on both axes vs Cap
    expect(term.class).toBe("persistent-weak");
    expect(wf.has_persistent_weak_front).toBe(true);
  });

  it("can trip v36 and v37 on different fronts yet have no persistent weak front", async () => {
    // Cap concedes first (vs Term) AND recovers first (vs Term) → Cap conceding-only, Term lagging-only.
    // v36 sees a leading concession (Cap), v37 sees a leading recovery order (Term lags), but no single
    // front is the weak side of both → the join clears.
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "below-acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // Cap↓ (t0)
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // Cap↑ (t1)
      mk({ Cap: "acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // Term↓ (t2)
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // Term↑ (t3)
    ]);
    const conc = await computeCoherenceConcession(rounds);
    const ro = await computeCoherenceRecoveryOrder(rounds);
    const wf = await computeCoherenceWeakFront(rounds);
    expect(conc.concedes).toBe(true); // Cap concedes first
    expect(ro.lags).toBe(true); // Term recovers last
    expect(wf.has_persistent_weak_front).toBe(false); // but no single weak-on-both front
  });

  it("picks the most-exposed front by integer leading-edge count, earliest label on a tie", async () => {
    // Two persistent-weak fronts. Aaa is weak vs two partners on each axis (4 edges); Mmm vs one (2
    // edges) → Aaa is most-exposed by count. Build: Aaa concedes first vs {Bbb,Ccc} and recovers last
    // vs {Bbb,Ccc}; Mmm concedes first vs {Ccc} and recovers last vs {Ccc}.
    // Simpler: make all the "other" fronts (Bbb, Ccc) strong (never weak), and Aaa weak on both axes vs
    // both, Mmm weak on both axes vs one.
    const rounds = await Promise.all([
      mk(
        { Aaa: "acceptable", Bbb: "acceptable", Ccc: "acceptable", Mmm: "acceptable" },
        { Aaa: "ideal", Bbb: "ideal", Ccc: "ideal", Mmm: "ideal" },
      ), // r0 all above
      mk(
        { Aaa: "below-acceptable", Bbb: "acceptable", Ccc: "acceptable", Mmm: "below-acceptable" },
        { Aaa: "ideal", Bbb: "ideal", Ccc: "ideal", Mmm: "ideal" },
      ), // r1: Aaa↓, Mmm↓ (t0) — they concede first (before Bbb/Ccc)
      mk(
        { Aaa: "below-acceptable", Bbb: "below-acceptable", Ccc: "below-acceptable", Mmm: "below-acceptable" },
        { Aaa: "ideal", Bbb: "ideal", Ccc: "ideal", Mmm: "ideal" },
      ), // r2: Bbb↓, Ccc↓ (t1)
      mk(
        { Aaa: "below-acceptable", Bbb: "acceptable", Ccc: "acceptable", Mmm: "below-acceptable" },
        { Aaa: "ideal", Bbb: "ideal", Ccc: "ideal", Mmm: "ideal" },
      ), // r3: Bbb↑, Ccc↑ (t2) — they recover first
      mk(
        { Aaa: "acceptable", Bbb: "acceptable", Ccc: "acceptable", Mmm: "acceptable" },
        { Aaa: "ideal", Bbb: "ideal", Ccc: "ideal", Mmm: "ideal" },
      ), // r4: Aaa↑, Mmm↑ (t3) — they recover last
    ]);
    // Falls: Aaa {0}, Mmm {0}, Bbb {1}, Ccc {1}. Recoveries: Bbb {2}, Ccc {2}, Aaa {3}, Mmm {3}.
    // Aaa concedes first vs {Bbb,Ccc}; recovers last vs {Bbb,Ccc} → 4 edges, persistent-weak.
    // Mmm same as Aaa → 4 edges too. So they tie; earliest label (Aaa) wins.
    const wf = await computeCoherenceWeakFront(rounds);
    expect(wf.weak_fronts).toEqual(["Aaa", "Mmm"]);
    expect(wf.most_exposed_front).toBe("Aaa"); // tie on 4 edges → earliest label
    const aaa = wf.fronts.find((f) => f.dimension === "Aaa")!;
    expect(aaa.concedes_first_against).toEqual(["Bbb", "Ccc"]);
    expect(aaa.recovers_last_against).toEqual(["Bbb", "Ccc"]);
    expect(aaa.confirmed_against).toEqual(["Bbb", "Ccc"]);
  });

  it("omits a front with no weak signal on either axis", async () => {
    // Cap & Term recover/fall in perfect lockstep → no leading concession or recovery order at all.
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // both↓ (t0)
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // both↑ (t1)
    ]);
    const wf = await computeCoherenceWeakFront(rounds);
    expect(wf.fronts).toHaveLength(0);
    expect(wf.has_persistent_weak_front).toBe(false);
    expect(wf.most_exposed_front).toBeNull();
  });

  it("is deterministic: identical rounds in identical order → identical weak_front_hash", async () => {
    const build = () =>
      Promise.all([
        mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
        mk({ Cap: "acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
        mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
        mk({ Cap: "acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }),
        mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
      ]);
    const a = await computeCoherenceWeakFront(await build());
    const c = await computeCoherenceWeakFront(await build());
    expect(a.weak_front_hash).toBe(c.weak_front_hash);
    expect(a.weak_front_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("throws on fewer than two rounds (delegated to v36/v37)", async () => {
    const rounds = [await mk({ Cap: "ideal" }, { Cap: "ideal" })];
    await expect(computeCoherenceWeakFront(rounds)).rejects.toThrow(/at least two rounds/);
  });

  it("renders the most-exposed front and stable JSON", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // Term↓ (t0)
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // Cap↓ (t1)
      mk({ Cap: "acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // Cap↑ (t2)
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // Term↑ (t3)
    ]);
    const wf = await computeCoherenceWeakFront(rounds);
    const summary = renderCoherenceWeakFrontSummary(wf);
    expect(summary).toContain("Coherence persistent weak front across 5 rounds");
    expect(summary).toMatch(/most-exposed front: Term — concedes first vs Cap; recovers last vs Cap/);
    expect(summary).toMatch(/1 persistent-weak/);
    expect(summary).toMatch(/weak_front_hash: [0-9a-f]{64}/);

    const json = JSON.parse(buildCoherenceWeakFrontJson(wf));
    expect(json.schema).toBe("vaulytica.posture-weak-front.v1");
    expect(json.weak_front_hash).toBe(wf.weak_front_hash);
    expect(json.rounds).toBe(5);
    expect(json.weak_fronts).toEqual(["Term"]);
    expect(json.most_exposed_front).toBe("Term");
    expect(json.has_persistent_weak_front).toBe(true);
    expect(json.fronts[0]).toMatchObject({
      dimension: "Term",
      concedes_first_against: ["Cap"],
      recovers_last_against: ["Cap"],
      confirmed_against: ["Cap"],
      class: "persistent-weak",
    });
  });

  it("renders a none-weak verdict distinctly", async () => {
    const rounds = await Promise.all([
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }),
      mk({ Cap: "below-acceptable", Term: "below-acceptable" }, { Cap: "ideal", Term: "ideal" }), // both↓
      mk({ Cap: "acceptable", Term: "acceptable" }, { Cap: "ideal", Term: "ideal" }), // both↑
    ]);
    const summary = renderCoherenceWeakFrontSummary(await computeCoherenceWeakFront(rounds));
    expect(summary).toMatch(/persistent weak front: none/);
  });
});
