import { describe, expect, it } from "vitest";

import { ESTATE_CHECK_RULES } from "./estate-checks.js";
import { buildContext } from "../../../_test-fixtures.js";
import type { Playbook, Rule, RuleContext } from "../../../finding.js";

const WILL_PB: Playbook = { id: "last-will-and-testament", version: "1.0.0" };

/**
 * `buildContext` (the shared fixture) always assigns the `generic-fallback`
 * playbook. Every rule in this file needs `ctx.playbook.id` to be
 * `last-will-and-testament` (one of `applies_to_playbooks`), so wrap it with
 * an override — mirroring `trust-estate-ruleset.test.ts`'s `withPb` helper.
 */
function willContext(...sections: [string, ...string[]][]): RuleContext {
  const ctx = buildContext(...sections);
  return { ...ctx, playbook: WILL_PB };
}

function findRule(id: string): Rule {
  const rule = ESTATE_CHECK_RULES.find((r) => r.id === id);
  if (!rule) throw new Error(`rule ${id} not found`);
  return rule;
}

describe("ESTATE_CHECK_RULES — registry contract", () => {
  it("every rule declares applies_to_playbooks for will + trust + codicil and the estate-checks gate", () => {
    for (const r of ESTATE_CHECK_RULES) {
      expect(r.applies_to_playbooks, r.id).toEqual(
        expect.arrayContaining(["last-will-and-testament", "revocable-living-trust", "codicil"]),
      );
      expect(r.applies_to_playbooks?.length, r.id).toBe(3);
      expect(r.assertion_gate, r.id).toBe("estate-checks");
      expect(r.category, r.id).toBe("estate-checks");
    }
  });

  it("has stable, unique EST-1xx/2xx/3xx ids", () => {
    const ids = ESTATE_CHECK_RULES.map((r) => r.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const id of ids) expect(id).toMatch(/^EST-[123]\d{2}$/);
  });
});

describe("EST-101 — attestation clause presence", () => {
  it("fires when no attestation clause is present", () => {
    const ctx = willContext([
      "Last Will and Testament",
      "I, John Doe, revoke all prior wills. I nominate Jane Doe as executor.",
    ]);
    const finding = findRule("EST-101").check(ctx);
    expect(finding).not.toBeNull();
    expect(finding?.title).toBe("No attestation clause detected");
  });

  it("is silent when an attestation clause is present", () => {
    const ctx = willContext([
      "Last Will and Testament",
      "In witness whereof, the subscribing witnesses have hereunto set their hands.",
    ]);
    expect(findRule("EST-101").check(ctx)).toBeNull();
  });
});

describe("EST-201 — residuary share arithmetic", () => {
  it("fires when a residue split sums to 90%", () => {
    const ctx = willContext([
      "Last Will and Testament",
      "I devise the residue of my estate 40% to A, 50% to B.",
    ]);
    const finding = findRule("EST-201").check(ctx);
    expect(finding).not.toBeNull();
    expect(finding?.title).toContain("90%");
    expect(finding?.description).toContain("40%");
    expect(finding?.description).toContain("50%");
  });

  it("is silent when a residue split sums to 100%", () => {
    const ctx = willContext([
      "Last Will and Testament",
      "I devise the residue of my estate 50% to A, 50% to B.",
    ]);
    expect(findRule("EST-201").check(ctx)).toBeNull();
  });

  it("is silent when the residue is divided in equal, non-numeric shares", () => {
    const ctx = willContext([
      "Last Will and Testament",
      "I devise the residue of my estate in equal shares to my children.",
    ]);
    expect(findRule("EST-201").check(ctx)).toBeNull();
  });

  it("is silent when there is no residuary clause at all", () => {
    const ctx = willContext([
      "Last Will and Testament",
      "I nominate Jane Doe as executor. 40% and 50% appear here but the estate plan has no such clause.",
    ]);
    expect(findRule("EST-201").check(ctx)).toBeNull();
  });

  it("dedupes a fraction and its parenthetical percent, and sums correctly to 100%", () => {
    const ctx = willContext([
      "Last Will and Testament",
      "I devise the residue of my estate: one-half (1/2) to A and one-half (1/2) to B.",
    ]);
    expect(findRule("EST-201").check(ctx)).toBeNull();
  });

  it("treats thirds as summing to ~100% (rounds within 0.5) and stays silent", () => {
    const ctx = willContext([
      "Last Will and Testament",
      "I devise the residue of my estate: one-third to A, one-third to B, one-third to C.",
    ]);
    expect(findRule("EST-201").check(ctx)).toBeNull();
  });
});

describe("EST-303 — guardian nomination for minor children", () => {
  it("fires when minor children are referenced but no guardian is nominated", () => {
    const ctx = willContext([
      "Last Will and Testament",
      "I leave my estate to my minor children in equal shares.",
    ]);
    const finding = findRule("EST-303").check(ctx);
    expect(finding).not.toBeNull();
  });

  it("is silent when a guardian is nominated", () => {
    const ctx = willContext([
      "Last Will and Testament",
      "I have minor children. I nominate my sister as guardian of my minor children.",
    ]);
    expect(findRule("EST-303").check(ctx)).toBeNull();
  });

  it("is silent when there is no reference to minor children", () => {
    const ctx = willContext(["Last Will and Testament", "I leave my estate to my adult children."]);
    expect(findRule("EST-303").check(ctx)).toBeNull();
  });
});

describe("EST-301 — executor / personal representative named", () => {
  it("fires when no executor / personal representative is named", () => {
    const ctx = willContext(["Last Will and Testament", "I devise my estate to my children."]);
    const finding = findRule("EST-301").check(ctx);
    expect(finding).not.toBeNull();
  });

  it("is silent when an executor is appointed", () => {
    const ctx = willContext(["Last Will and Testament", "I appoint Jane Doe as Executor."]);
    expect(findRule("EST-301").check(ctx)).toBeNull();
  });
});
