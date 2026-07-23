import { describe, expect, it } from "vitest";

import { ESTATE_CHECK_RULES, estateCheckRulesForOverlay } from "./estate-checks.js";
import { estateFormalitiesForState } from "../../../../dkb/estate-formalities.js";
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

describe("EST-106 — witness blocks vs. recital count", () => {
  it("fires when the will recites two witnesses but shows one block", () => {
    const ctx = willContext([
      "Last Will and Testament",
      "Signed in the presence of two (2) competent witnesses.",
      "_______________________ Witness",
    ]);
    const finding = findRule("EST-106").check(ctx);
    expect(finding).not.toBeNull();
    expect(finding?.title).toContain("recites 2 witnesses");
    expect(finding?.title).toContain("1 witness signature block");
  });

  it("is silent when the blocks match the recital", () => {
    const ctx = willContext([
      "Last Will and Testament",
      "Signed in the presence of two witnesses.",
      "_______________________ Witness",
      "_______________________ Witness",
    ]);
    expect(findRule("EST-106").check(ctx)).toBeNull();
  });

  it("counts two blocks on one line and handles 'two or more credible witnesses'", () => {
    const ctx = willContext([
      "Last Will and Testament",
      "Signed in the presence of two or more credible witnesses.",
      "Witness: __________    Witness: __________",
    ]);
    expect(findRule("EST-106").check(ctx)).toBeNull();
  });

  it("stays silent with zero blocks — that absence is EST-105's finding", () => {
    const ctx = willContext([
      "Last Will and Testament",
      "Signed in the presence of two witnesses who attested this will.",
    ]);
    expect(findRule("EST-106").check(ctx)).toBeNull();
  });

  it("stays silent when the will recites no witness count at all", () => {
    const ctx = willContext([
      "Last Will and Testament",
      "I, John Doe, revoke all prior wills.",
      "_______________________ Witness",
    ]);
    expect(findRule("EST-106").check(ctx)).toBeNull();
  });

  it("does not count 'IN WITNESS WHEREOF, I sign: ___' (testator boilerplate) as a witness block", () => {
    // Audit finding: the testator's own execution line contains the token
    // "witness" and an underscore run, so it silenced EST-107 on a will
    // with only one real witness. Recites two, shows one real block.
    const ctx = willContext([
      "Execution",
      "Signed in the presence of two competent witnesses.",
      "IN WITNESS WHEREOF, I sign: ______________",
      "Witness signature: ______________",
    ]);
    const finding = findRule("EST-106").check(ctx);
    expect(finding).not.toBeNull();
    expect(finding?.title).toContain("shows 1 witness signature block");
  });

  it("does not count a 'WITNESSETH:' preamble with underscores as a witness block", () => {
    // Audit finding: "WITNESSETH: ... this day ____" tripped the counter
    // while EST-105's presence patterns said zero blocks — the same report
    // asserted both 0 and 1 blocks. With zero real blocks, EST-106/107
    // must stay silent (EST-105 owns the zero-block case).
    const ctx = willContext([
      "Recitals",
      "WITNESSETH: this instrument, made this day ______",
      "The testator recites two witnesses.",
    ]);
    expect(findRule("EST-106").check(ctx)).toBeNull();
    const overlay = estateFormalitiesForState("us-ca");
    const est107 = estateCheckRulesForOverlay(overlay).find((r) => r.id === "EST-107")!;
    expect(est107.check(ctx)).toBeNull();
    // And EST-105 still reports the absence — no self-contradiction.
    expect(findRule("EST-105").check(ctx)).not.toBeNull();
  });

  it("'in witness whereof, I sign' no longer satisfies EST-105's presence patterns", () => {
    const ctx = willContext([
      "Execution",
      "IN WITNESS WHEREOF, I sign this will on the date below: ______________",
    ]);
    expect(findRule("EST-105").check(ctx)).not.toBeNull();
  });

  it("ignores testator/notary signature lines when counting witness blocks", () => {
    const ctx = willContext([
      "Last Will and Testament",
      "Signed in the presence of two witnesses.",
      "By: _______________________ Testator",
      "_______________________ Notary Public, my commission expires",
      "_______________________ Witness",
    ]);
    const finding = findRule("EST-106").check(ctx);
    expect(finding).not.toBeNull();
    expect(finding?.title).toContain("1 witness signature block");
  });
});

describe("EST-107 — witness blocks vs. the asserted state's statute", () => {
  function est107For(state: string): Rule {
    const overlay = estateFormalitiesForState(state);
    const rule = estateCheckRulesForOverlay(overlay).find((r) => r.id === "EST-107");
    if (!rule) throw new Error(`EST-107 not built for ${state}`);
    return rule;
  }

  it("fires when the will shows one block and the state expects two, with no recital", () => {
    const ctx = willContext([
      "Execution",
      "Signed by the testator on the date below.",
      "Witness: ______________",
    ]);
    const finding = est107For("us-va")!.check(ctx);
    expect(finding).not.toBeNull();
    expect(finding?.title).toBe("Will shows 1 witness signature block; Virginia expects 2");
    expect(finding?.source_citations?.some((c) => c.id === "va-code-64-2-403")).toBe(true);
  });

  it("fires when the recital is internally consistent but short of the statute", () => {
    // Recites one witness and shows one block — EST-106 is silent
    // (blocks >= recited); only the statute comparison catches it.
    const ctx = willContext([
      "Execution",
      "Signed in the presence of one witness.",
      "Witness: ______________",
    ]);
    expect(est107For("us-ga")!.check(ctx)).not.toBeNull();
  });

  it("is silent when the blocks meet the statute's count", () => {
    const ctx = willContext(["Execution", "Witness: ______________", "Witness: ______________"]);
    expect(est107For("us-va")!.check(ctx)).toBeNull();
  });

  it("stays silent with zero blocks — that absence is EST-105's finding", () => {
    const ctx = willContext(["Execution", "Signed by the testator on the date below."]);
    expect(est107For("us-va")!.check(ctx)).toBeNull();
  });

  it("stays silent when the recital overstates the blocks — that mismatch is EST-106's", () => {
    const ctx = willContext([
      "Execution",
      "Signed in the presence of two competent witnesses.",
      "Witness: ______________",
    ]);
    expect(est107For("us-va")!.check(ctx)).toBeNull();
  });

  it("under a notarization-alternative state, a detected notary block silences the shortfall", () => {
    // CO accepts notarized acknowledgment in lieu of witnesses — with a
    // notary block present, the witness shortfall is not non-compliance.
    const ctx = willContext([
      "Execution",
      "Witness: ______________",
      "Acknowledged before me, a notary public. My commission expires 2027.",
    ]);
    expect(est107For("us-co")!.check(ctx)).toBeNull();
  });

  it("under a notarization-alternative state with NO notary language, warns naming both paths", () => {
    const ctx = willContext(["Execution", "Witness: ______________"]);
    const rule = est107For("us-co")!;
    expect(rule.default_severity).toBe("warning");
    const finding = rule.check(ctx);
    expect(finding).not.toBeNull();
    expect(finding?.explanation).toContain("neither path is evidenced");
    expect(finding?.explanation).toContain("notary public");
  });

  it("a notary block does NOT silence the shortfall in a non-alternative state", () => {
    // Virginia has no notarization alternative — a notary block (e.g. a
    // self-proving affidavit) never substitutes for the witnesses.
    const ctx = willContext([
      "Execution",
      "Witness: ______________",
      "Acknowledged before me, a notary public.",
    ]);
    expect(est107For("us-va")!.check(ctx)).not.toBeNull();
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
