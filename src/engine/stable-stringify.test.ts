/**
 * stableStringify hardening (harden-determinism-guards).
 *
 * The old replacer treated ANY second visit to an object as a cycle and
 * serialized it as `undefined` — a shared sub-object between two hashed
 * fields silently truncated the hash input. Now: shared (acyclic)
 * references serialize completely at every occurrence; a genuine cycle
 * throws a TypeError naming the key path — never a silent drop.
 */

import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { stableStringify } from "./runner.js";

/** Reference canonicalization: deep clone with sorted keys, no sharing. */
function canonicalize(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(canonicalize);
  if (v && typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(v as Record<string, unknown>).sort()) {
      const child = canonicalize((v as Record<string, unknown>)[k]);
      if (child !== undefined) out[k] = child;
    }
    return out;
  }
  // JSON.parse can never produce -0 (JSON.stringify(-0) === "0").
  if (typeof v === "number" && Object.is(v, -0)) return 0;
  return v;
}

describe("stableStringify — shared references serialize completely", () => {
  it("a sub-object shared between two fields appears fully in both", () => {
    const shared = { id: "cite-1", source: "9 U.S.C. § 2" };
    const value = { a: shared, b: shared, list: [shared, { other: shared }] };
    const parsed = JSON.parse(stableStringify(value)) as typeof value;
    expect(parsed.a).toEqual(shared);
    expect(parsed.b).toEqual(shared); // the old replacer emitted undefined here
    expect(parsed.list[0]).toEqual(shared);
    expect((parsed.list[1] as { other: unknown }).other).toEqual(shared);
  });

  it("property: arbitrary acyclic values with intentional aliasing round-trip to the reference canonicalization", () => {
    fc.assert(
      fc.property(fc.jsonValue({ maxDepth: 4 }), (v) => {
        // Introduce aliasing: embed the same value twice.
        const aliased = { first: v, second: v, arr: [v, v] };
        expect(JSON.parse(stableStringify(aliased))).toEqual(canonicalize(aliased));
      }),
      { numRuns: 200 },
    );
  });

  it("sorts keys at every level", () => {
    expect(stableStringify({ b: { z: 1, a: 2 }, a: 3 })).toBe('{"a":3,"b":{"a":2,"z":1}}');
  });
});

describe("stableStringify — genuine cycles throw, never truncate", () => {
  it("throws a TypeError naming the key path for an object cycle", () => {
    const node: Record<string, unknown> = { name: "root" };
    node.child = { back: node };
    expect(() => stableStringify({ top: node })).toThrow(TypeError);
    expect(() => stableStringify({ top: node })).toThrow(/top\.child\.back/);
  });

  it("throws for a cycle through an array", () => {
    const arr: unknown[] = [1, 2];
    arr.push({ loop: arr });
    expect(() => stableStringify({ items: arr })).toThrow(/hash inputs must be trees/);
  });

  it("self-reference at the root throws", () => {
    const self: Record<string, unknown> = {};
    self.me = self;
    expect(() => stableStringify(self)).toThrow(TypeError);
  });
});
