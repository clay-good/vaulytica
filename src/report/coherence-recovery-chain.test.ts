import { describe, expect, it } from "vitest";
import {
  computeCoherenceRecoveryChain,
  exposureRecoveryCyclic,
  buildCoherenceRecoveryChainJson,
  renderCoherenceRecoveryChainSummary,
} from "./coherence-recovery-chain.js";
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

/** A round built from two docs; the second is always `ideal`, so each front's binding floor is its first tier. */
const mk = (a: Record<string, NegotiationTier>, b: Record<string, NegotiationTier>) =>
  bundlePostureCoherence(bundle(["msa.docx", a], ["order.docx", b]));

const B: NegotiationTier = "below-acceptable";
const A: NegotiationTier = "acceptable";

/**
 * A front's tier path of length `n` whose binding floor flips across the acceptable floor at exactly
 * the given transition `steps` (a crossing at step `k` ⟺ the floor differs between round `k` and
 * `k+1`). Starts **below** the floor (`start = B`) so the *first* crossing is a recovery — matches the
 * silence-free recovery scan v37/v43 use.
 */
function path(steps: number[], n: number, start: NegotiationTier = B): NegotiationTier[] {
  const set = new Set(steps);
  const out: NegotiationTier[] = [];
  let cur = start;
  for (let i = 0; i < n; i++) {
    out.push(cur);
    if (set.has(i)) cur = cur === B ? A : B;
  }
  return out;
}

/** Assemble N rounds from a map of front → equal-length tier path (each round's second doc is `ideal`). */
function rounds(paths: Record<string, NegotiationTier[]>) {
  const names = Object.keys(paths);
  const n = paths[names[0]!]!.length;
  return Promise.all(
    Array.from({ length: n }, (_, i) => {
      const doc1: Record<string, NegotiationTier> = {};
      const doc2: Record<string, NegotiationTier> = {};
      for (const name of names) {
        doc1[name] = paths[name]![i]!;
        doc2[name] = "ideal";
      }
      return mk(doc1, doc2);
    }),
  );
}

describe("computeCoherenceRecoveryChain (spec-v43 — transitive recovery-order chain)", () => {
  it("composes pairwise recovery orders into an acyclic chain with a tailwater sink, relay, and source", async () => {
    // Cap recovers first (step 0), Term next (step 1), Ind last (step 2) → Cap recovers before Term &
    // Ind, Term recovers before Ind. A clean restoration order: Cap source, Term relay, Ind tailwater.
    const chain = await computeCoherenceRecoveryChain(
      await rounds({ Cap: path([0], 4), Term: path([1], 4), Ind: path([2], 4) }),
    );

    const cap = chain.fronts.find((f) => f.dimension === "Cap")!;
    const term = chain.fronts.find((f) => f.dimension === "Term")!;
    const ind = chain.fronts.find((f) => f.dimension === "Ind")!;

    expect(cap.class).toBe("source");
    expect(cap.reach).toBe(2);
    expect(cap.recovered_before_by).toBe(0);
    expect(cap.recovers_before_directly).toEqual(["Ind", "Term"]); // sorted by label

    expect(term.class).toBe("relay");
    expect(term.reach).toBe(1);
    expect(term.recovered_before_by).toBe(1);

    expect(ind.class).toBe("sink");
    expect(ind.reach).toBe(0);
    expect(ind.recovered_before_by).toBe(2);

    expect(chain.acyclic).toBe(true);
    expect(chain.cyclic).toBe(false);
    expect(exposureRecoveryCyclic(chain)).toBe(false);
    expect(chain.tailwater).toBe("Ind");
    expect(chain.max_lag).toBe(2);
    expect(chain.edges).toBe(3);
    expect(chain.class_counts).toMatchObject({ source: 1, relay: 1, sink: 1, cyclic: 0 });
  });

  it("detects an intransitive recovery cycle no pairwise read can see (the gate fires)", async () => {
    // A recovery Condorcet triple: each front recovers at positions that make it a strict 5-of-9
    // majority first-recoverer over the next, in a loop — Bbb recovers before Aaa, Aaa before Ccc,
    // Ccc before Bbb — yet no front recovers before all.
    // Aaa recovers {2,4,9}, Bbb {1,6,8}, Ccc {3,5,7}: Bbb beats Aaa, Ccc beats Bbb, Aaa beats Ccc.
    const chain = await computeCoherenceRecoveryChain(
      await rounds({
        Aaa: path([2, 3, 4, 8, 9], 11),
        Bbb: path([1, 5, 6, 7, 8], 11),
        Ccc: path([3, 4, 5, 6, 7], 11),
      }),
    );

    expect(chain.cyclic).toBe(true);
    expect(chain.acyclic).toBe(false);
    expect(exposureRecoveryCyclic(chain)).toBe(true);
    expect(chain.tailwater).toBeNull(); // no sink: every front recovers before another
    expect(chain.max_lag).toBe(0);
    expect(chain.edges).toBe(3);

    for (const f of chain.fronts) {
      expect(f.class).toBe("cyclic");
      expect(f.in_cycle).toBe(true);
      expect(f.reach).toBe(2); // each transitively recovers before the other two
      expect(f.recovered_before_by).toBe(2);
    }
    // The rotational edges: Bbb→Aaa, Ccc→Bbb, Aaa→Ccc.
    expect(chain.fronts.find((f) => f.dimension === "Bbb")!.recovers_before_directly).toEqual([
      "Aaa",
    ]);
    expect(chain.fronts.find((f) => f.dimension === "Ccc")!.recovers_before_directly).toEqual([
      "Bbb",
    ]);
    expect(chain.fronts.find((f) => f.dimension === "Aaa")!.recovers_before_directly).toEqual([
      "Ccc",
    ]);
  });

  it("ties its edge count to v37's leading-pair tally by construction", async () => {
    const cs = await rounds({ Cap: path([0], 4), Term: path([1], 4), Ind: path([2], 4) });
    const chain = await computeCoherenceRecoveryChain(cs);
    const ro = await computeCoherenceRecoveryOrder(cs);
    expect(chain.edges).toBe(ro.class_counts.leading);
  });

  it("an interleaved pair (no consistent first-recoverer) creates no edge — both fronts isolated", async () => {
    // Cap recovers {0,5} vs Term {2,4}: an even 2-2 split → v37 `interleaved` → no directed edge.
    const chain = await computeCoherenceRecoveryChain(
      await rounds({ Cap: path([0, 4, 5], 7), Term: path([2, 3, 4], 7) }),
    );
    expect(chain.edges).toBe(0);
    expect(chain.fronts.every((f) => f.class === "isolated")).toBe(true);
    expect(chain.tailwater).toBeNull();
    expect(chain.acyclic).toBe(true); // no edges → vacuously acyclic
    expect(chain.cyclic).toBe(false);
  });

  it("a front that never recovers is isolated (reach 0, recovered-before-by 0)", async () => {
    // Cap recovers before Term; Quiet never falls and so never recovers → no edge touches Quiet.
    const chain = await computeCoherenceRecoveryChain(
      await rounds({ Cap: path([0], 4), Term: path([1], 4), Quiet: path([], 4, A) }),
    );
    const quiet = chain.fronts.find((f) => f.dimension === "Quiet")!;
    expect(quiet.class).toBe("isolated");
    expect(quiet.reach).toBe(0);
    expect(quiet.recovered_before_by).toBe(0);
    expect(chain.tailwater).toBe("Term");
    expect(chain.max_lag).toBe(1);
  });

  it("a sink fed by an upstream cycle still has a tailwater, yet the relation is cyclic", async () => {
    // Late recovers once at step 10 (latest of all) → every cyclic front recovers before it; the trio
    // still loops upstream. Late is the tailwater (restored after all three), the relation cyclic.
    const chain = await computeCoherenceRecoveryChain(
      await rounds({
        Late: path([10], 12),
        Aaa: path([2, 3, 4, 8, 9], 12),
        Bbb: path([1, 5, 6, 7, 8], 12),
        Ccc: path([3, 4, 5, 6, 7], 12),
      }),
    );
    expect(chain.cyclic).toBe(true);
    const late = chain.fronts.find((f) => f.dimension === "Late")!;
    expect(late.class).toBe("sink");
    expect(late.reach).toBe(0);
    expect(late.recovered_before_by).toBe(3); // all three cyclic fronts transitively recover before it
    expect(chain.tailwater).toBe("Late");
    expect(chain.max_lag).toBe(3);
    expect(chain.edges).toBe(6); // 3 cycle edges + 3 edges into Late
  });

  it("is deterministic: identical rounds in identical order → identical recovery_chain_hash", async () => {
    const build = () => rounds({ Cap: path([0], 4), Term: path([1], 4), Ind: path([2], 4) });
    const a = await computeCoherenceRecoveryChain(await build());
    const c = await computeCoherenceRecoveryChain(await build());
    expect(a.recovery_chain_hash).toBe(c.recovery_chain_hash);
    expect(a.recovery_chain_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("throws on fewer than two rounds", async () => {
    const single = [await mk({ Cap: "ideal" }, { Cap: "ideal" })];
    await expect(computeCoherenceRecoveryChain(single)).rejects.toThrow(/at least two rounds/);
  });

  it("renders the tailwater, ordering verdict, and stable JSON", async () => {
    const chain = await computeCoherenceRecoveryChain(
      await rounds({ Cap: path([0], 4), Term: path([1], 4), Ind: path([2], 4) }),
    );
    const summary = renderCoherenceRecoveryChainSummary(chain);
    expect(summary).toContain("Coherence exposure recovery chain across 4 rounds");
    expect(summary).toMatch(
      /tailwater: Ind — transitively recovered after 2 fronts, restored last of all/,
    );
    expect(summary).toMatch(/ordering: acyclic/);
    expect(summary).toMatch(/1 sink, 1 relay, 0 cyclic, 1 source, 0 isolated \(3 edges\)/);
    expect(summary).toMatch(
      /Ind: sink — recovers before 0, recovered after by 2 \(recovers before none directly\)/,
    );
    expect(summary).toMatch(/recovery_chain_hash: [0-9a-f]{64}/);

    const json = JSON.parse(buildCoherenceRecoveryChainJson(chain));
    expect(json.schema).toBe("vaulytica.posture-recovery-chain.v1");
    expect(json.recovery_chain_hash).toBe(chain.recovery_chain_hash);
    expect(json.rounds).toBe(4);
    expect(json.edges).toBe(3);
    expect(json.tailwater).toBe("Ind");
    expect(json.acyclic).toBe(true);
    expect(json.fronts.find((f: { dimension: string }) => f.dimension === "Ind")).toMatchObject({
      reach: 0,
      recovered_before_by: 2,
      in_cycle: false,
      class: "sink",
    });
  });

  it("renders the intransitive verdict and a none-tailwater line distinctly", async () => {
    const chain = await computeCoherenceRecoveryChain(
      await rounds({
        Aaa: path([2, 3, 4, 8, 9], 11),
        Bbb: path([1, 5, 6, 7, 8], 11),
        Ccc: path([3, 4, 5, 6, 7], 11),
      }),
    );
    const summary = renderCoherenceRecoveryChainSummary(chain);
    expect(summary).toMatch(/tailwater: none/);
    expect(summary).toMatch(/ordering: intransitive/);
    expect(summary).toMatch(/3 cyclic/);
  });
});
