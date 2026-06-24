import { describe, expect, it } from "vitest";
import {
  computeCoherenceChain,
  exposureCyclic,
  buildCoherenceChainJson,
  renderCoherenceChainSummary,
} from "./coherence-chain.js";
import { computeCoherencePrecedence } from "./coherence-precedence.js";
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
 * `k+1`). Starts above the floor; matches the silence-free crossing scan v24/v35 use.
 */
function path(steps: number[], n: number, start: NegotiationTier = A): NegotiationTier[] {
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

describe("computeCoherenceChain (spec-v42 — transitive lead-lag chain)", () => {
  it("composes pairwise leads into an acyclic chain with a headwater source, relay, and sink", async () => {
    // Cap crosses first (step 0), Term next (step 1), Ind last (step 2) → Cap leads Term & Ind,
    // Term leads Ind. A clean pipeline: Cap source, Term relay, Ind sink.
    const chain = await computeCoherenceChain(
      await rounds({ Cap: path([0], 4), Term: path([1], 4), Ind: path([2], 4) }),
    );

    const cap = chain.fronts.find((f) => f.dimension === "Cap")!;
    const term = chain.fronts.find((f) => f.dimension === "Term")!;
    const ind = chain.fronts.find((f) => f.dimension === "Ind")!;

    expect(cap.class).toBe("source");
    expect(cap.reach).toBe(2);
    expect(cap.led_by).toBe(0);
    expect(cap.leads_directly).toEqual(["Ind", "Term"]); // sorted by label

    expect(term.class).toBe("relay");
    expect(term.reach).toBe(1);
    expect(term.led_by).toBe(1);

    expect(ind.class).toBe("sink");
    expect(ind.reach).toBe(0);
    expect(ind.led_by).toBe(2);

    expect(chain.acyclic).toBe(true);
    expect(chain.cyclic).toBe(false);
    expect(exposureCyclic(chain)).toBe(false);
    expect(chain.headwater).toBe("Cap");
    expect(chain.max_reach).toBe(2);
    expect(chain.edges).toBe(3);
    expect(chain.class_counts).toMatchObject({ source: 1, relay: 1, sink: 1, cyclic: 0 });
  });

  it("detects an intransitive cycle no pairwise read can see (the gate fires)", async () => {
    // The canonical non-transitive (Condorcet) triple: each front crosses the floor at positions
    // that make it a strict 5-of-9 majority first-mover over the next, in a loop —
    // Bbb leads Aaa, Aaa leads Ccc, Ccc leads Bbb — yet no front leads all.
    const chain = await computeCoherenceChain(
      await rounds({
        Aaa: path([1, 3, 8], 10),
        Bbb: path([0, 5, 7], 10),
        Ccc: path([2, 4, 6], 10),
      }),
    );

    expect(chain.cyclic).toBe(true);
    expect(chain.acyclic).toBe(false);
    expect(exposureCyclic(chain)).toBe(true);
    expect(chain.headwater).toBeNull(); // no source: every front is led by another
    expect(chain.max_reach).toBe(0);
    expect(chain.edges).toBe(3);

    for (const f of chain.fronts) {
      expect(f.class).toBe("cyclic");
      expect(f.in_cycle).toBe(true);
      expect(f.reach).toBe(2); // each transitively leads the other two
      expect(f.led_by).toBe(2);
    }
    // The rotational edges: Bbb→Aaa, Aaa→Ccc, Ccc→Bbb.
    expect(chain.fronts.find((f) => f.dimension === "Bbb")!.leads_directly).toEqual(["Aaa"]);
    expect(chain.fronts.find((f) => f.dimension === "Aaa")!.leads_directly).toEqual(["Ccc"]);
    expect(chain.fronts.find((f) => f.dimension === "Ccc")!.leads_directly).toEqual(["Bbb"]);
  });

  it("ties its edge count to v35's leading-pair tally by construction", async () => {
    const cs = await rounds({ Cap: path([0], 4), Term: path([1], 4), Ind: path([2], 4) });
    const chain = await computeCoherenceChain(cs);
    const prec = await computeCoherencePrecedence(cs);
    expect(chain.edges).toBe(prec.class_counts.leading);
  });

  it("an interleaved pair (no consistent first-mover) creates no edge — both fronts isolated", async () => {
    // Cap{0,3} vs Term{1,2}: an even 2-2 split → v35 `interleaved` → no directed edge.
    const chain = await computeCoherenceChain(
      await rounds({ Cap: path([0, 3], 5), Term: path([1, 2], 5) }),
    );
    expect(chain.edges).toBe(0);
    expect(chain.fronts.every((f) => f.class === "isolated")).toBe(true);
    expect(chain.headwater).toBeNull();
    expect(chain.acyclic).toBe(true); // no edges → vacuously acyclic
    expect(chain.cyclic).toBe(false);
  });

  it("a front that never crosses the floor is isolated (reach 0, led-by 0)", async () => {
    // Cap leads Term; Quiet never crosses (stays above) → no edge touches Quiet.
    const chain = await computeCoherenceChain(
      await rounds({ Cap: path([0], 4), Term: path([1], 4), Quiet: path([], 4) }),
    );
    const quiet = chain.fronts.find((f) => f.dimension === "Quiet")!;
    expect(quiet.class).toBe("isolated");
    expect(quiet.reach).toBe(0);
    expect(quiet.led_by).toBe(0);
    expect(chain.headwater).toBe("Cap");
  });

  it("a source feeding into a downstream cycle still has a headwater, yet the relation is cyclic", async () => {
    // Up crosses once at step 0 (earliest of all) → leads the three cyclic fronts; the trio still loops.
    const chain = await computeCoherenceChain(
      await rounds({
        Up: path([0], 11),
        Aaa: path([2, 4, 9], 11),
        Bbb: path([1, 6, 8], 11),
        Ccc: path([3, 5, 7], 11),
      }),
    );
    expect(chain.cyclic).toBe(true);
    const up = chain.fronts.find((f) => f.dimension === "Up")!;
    expect(up.class).toBe("source");
    expect(up.led_by).toBe(0);
    expect(up.reach).toBe(3); // transitively leads all three cyclic fronts
    expect(chain.headwater).toBe("Up");
    expect(chain.max_reach).toBe(3);
  });

  it("is deterministic: identical rounds in identical order → identical chain_hash", async () => {
    const build = () => rounds({ Cap: path([0], 4), Term: path([1], 4), Ind: path([2], 4) });
    const a = await computeCoherenceChain(await build());
    const c = await computeCoherenceChain(await build());
    expect(a.chain_hash).toBe(c.chain_hash);
    expect(a.chain_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("throws on fewer than two rounds", async () => {
    const single = [await mk({ Cap: "ideal" }, { Cap: "ideal" })];
    await expect(computeCoherenceChain(single)).rejects.toThrow(/at least two rounds/);
  });

  it("renders the headwater, ordering verdict, and stable JSON", async () => {
    const chain = await computeCoherenceChain(
      await rounds({ Cap: path([0], 4), Term: path([1], 4), Ind: path([2], 4) }),
    );
    const summary = renderCoherenceChainSummary(chain);
    expect(summary).toContain("Coherence exposure lead chain across 4 rounds");
    expect(summary).toMatch(/headwater: Cap — transitively leads 2 fronts with nothing upstream/);
    expect(summary).toMatch(/ordering: acyclic/);
    expect(summary).toMatch(/1 source, 1 relay, 0 cyclic, 1 sink, 0 isolated \(3 edges\)/);
    expect(summary).toMatch(/Cap: source — reaches 2, led by 0 \(directly leads Ind, Term\)/);
    expect(summary).toMatch(/chain_hash: [0-9a-f]{64}/);

    const json = JSON.parse(buildCoherenceChainJson(chain));
    expect(json.schema).toBe("vaulytica.posture-chain.v1");
    expect(json.chain_hash).toBe(chain.chain_hash);
    expect(json.rounds).toBe(4);
    expect(json.edges).toBe(3);
    expect(json.headwater).toBe("Cap");
    expect(json.acyclic).toBe(true);
    expect(json.fronts.find((f: { dimension: string }) => f.dimension === "Cap")).toMatchObject({
      reach: 2,
      led_by: 0,
      in_cycle: false,
      class: "source",
    });
  });

  it("renders the intransitive verdict and a none-headwater line distinctly", async () => {
    const chain = await computeCoherenceChain(
      await rounds({
        Aaa: path([1, 3, 8], 10),
        Bbb: path([0, 5, 7], 10),
        Ccc: path([2, 4, 6], 10),
      }),
    );
    const summary = renderCoherenceChainSummary(chain);
    expect(summary).toMatch(/headwater: none/);
    expect(summary).toMatch(/ordering: intransitive/);
    expect(summary).toMatch(/3 cyclic/);
  });
});
