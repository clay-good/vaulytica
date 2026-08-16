import { describe, expect, it } from "vitest";

import { TRUST_ESTATE_RULES } from "./rules.js";
import { EST_PLAYBOOK_IDS } from "./_helpers.js";
import { buildContext } from "../../../_test-fixtures.js";
import { runEngine } from "../../../runner.js";
import type { Playbook, RuleContext } from "../../../finding.js";

const WILL_PB: Playbook = { id: "last-will-and-testament", version: "1.0.0" };
const TRUST_PB: Playbook = { id: "revocable-living-trust", version: "1.0.0" };
const AD_PB: Playbook = { id: "advance-directive", version: "1.0.0" };
const HC_PB: Playbook = { id: "healthcare-poa", version: "1.0.0" };
const POA_PB: Playbook = { id: "durable-poa-financial", version: "1.0.0" };
const PRENUP_PB: Playbook = { id: "prenuptial-agreement", version: "1.0.0" };
const POSTNUP_PB: Playbook = { id: "postnuptial-agreement", version: "1.0.0" };
const MSA_PB: Playbook = { id: "family-msa", version: "1.0.0" };

const SRC = { name: "test.docx", sha256: "0".repeat(64), size_bytes: 100 };

function withPb(ctx: RuleContext, pb: Playbook): RuleContext {
  return { ...ctx, playbook: pb };
}

describe("v4 Trust/estate/family ruleset — registry contract", () => {
  it("exports exactly 60 rules with stable EST-NNN ids", () => {
    expect(TRUST_ESTATE_RULES.length).toBe(60);
    const ids = TRUST_ESTATE_RULES.map((r) => r.id);
    expect(new Set(ids).size).toBe(60);
    for (const r of TRUST_ESTATE_RULES) {
      expect(r.id, r.id).toMatch(/^EST-\d{3}$/);
      expect(r.version, r.id).toMatch(/^\d+\.\d+\.\d+$/);
      expect(r.category, r.id).toBe("trust-estate");
      expect(r.applies_to_playbooks, r.id).toBeDefined();
    }
  });

  it("scopes every rule to one or more trust-estate playbooks", () => {
    const allowed = new Set<string>(EST_PLAYBOOK_IDS);
    for (const r of TRUST_ESTATE_RULES) {
      for (const pb of r.applies_to_playbooks ?? []) {
        expect(allowed.has(pb), `${r.id} → ${pb}`).toBe(true);
      }
    }
  });

  it("does not fire under a non-trust-estate playbook", async () => {
    const ctx = buildContext(["Some other doc", "No estate content."]);
    const run = await runEngine({ rules: TRUST_ESTATE_RULES, ctx, source_file: SRC });
    expect(run.findings.length).toBe(0);
    expect(run.execution_log.every((e) => !e.fired)).toBe(true);
  });
});

describe("v4 Trust/estate/family — EST-060 disclaimer always fires", () => {
  it.each([
    ["will", WILL_PB],
    ["revocable trust", TRUST_PB],
    ["advance directive", AD_PB],
    ["healthcare POA", HC_PB],
    ["durable POA", POA_PB],
    ["prenup", PRENUP_PB],
    ["postnup", POSTNUP_PB],
    ["family MSA", MSA_PB],
  ] as const)("fires EST-060 disclaimer under %s playbook", async (_label, pb) => {
    const ctx = withPb(
      buildContext(["Document", "Any text — the disclaimer applies unconditionally."]),
      pb,
    );
    const run = await runEngine({ rules: TRUST_ESTATE_RULES, ctx, source_file: SRC });
    const disclaimer = run.findings.find((f) => f.rule_id === "EST-060");
    expect(disclaimer, "EST-060 must fire on every run").toBeDefined();
    expect(disclaimer?.severity).toBe("info");
  });
});

describe("v4 Trust/estate/family — failure cases", () => {
  it("EST-002 fires when will omits revocation of prior wills", async () => {
    const ctx = withPb(
      buildContext([
        "Last Will and Testament",
        "I, the testator, residing in California, nominate Jane Doe as executor. Bond waived. I devise the residue of my estate to my children. Guardian for minor children: Alice. Self-proving affidavit attached. Signed by testator, witnessed by 2 witnesses, notary.",
      ]),
      WILL_PB,
    );
    const run = await runEngine({ rules: TRUST_ESTATE_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "EST-002")).toBe(true);
  });

  it("EST-011 fires when revocable trust omits revocability language", async () => {
    const ctx = withPb(
      buildContext([
        "Living Trust",
        "Settlor John Doe creates this trust. Trustee: John Doe. Successor trustee: Mary Doe. Schedule A transfers initial trust property. During settlor's lifetime, income and principal as requested. Upon settlor's death, distribute to beneficiaries equally. Pour-over will references. Spendthrift provision restrains creditors.",
      ]),
      TRUST_PB,
    );
    const run = await runEngine({ rules: TRUST_ESTATE_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "EST-011")).toBe(true);
  });

  it("EST-022 fires when advance directive omits triggering condition", async () => {
    const ctx = withPb(
      buildContext([
        "Advance Directive",
        "Declarant, of sound mind. End-of-life: I do not want life-sustaining treatment or artificial hydration. Pain management: provide palliative care. Organ donation: donate all. Witnessed and notarized. Revocable orally or in writing.",
      ]),
      AD_PB,
    );
    const run = await runEngine({ rules: TRUST_ESTATE_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "EST-022")).toBe(true);
  });

  it("EST-032 fires when durable POA omits durability language", async () => {
    const ctx = withPb(
      buildContext([
        "Power of Attorney",
        "Principal John Smith appoints Jane Smith as agent. Authority: banking, real estate, taxes, business. Hot powers specifically authorized for gifts. Effective immediately. Agent duties: loyalty, good faith, no commingling. Third-party reliance protected. Notary acknowledgment + recording.",
      ]),
      POA_PB,
    );
    const run = await runEngine({ rules: TRUST_ESTATE_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "EST-032")).toBe(true);
  });

  it("EST-039 fires when prenup omits financial-disclosure schedules", async () => {
    const ctx = withPb(
      buildContext([
        "Prenuptial Agreement",
        "Prospective spouses in contemplation of marriage. Separate property remains separate; community property defined. Spousal-support waiver. Estate elective-share waived. Each party had independent counsel and sufficient review time. Governing law: California. Signed and notarized prior to marriage.",
      ]),
      PRENUP_PB,
    );
    const run = await runEngine({ rules: TRUST_ESTATE_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "EST-039")).toBe(true);
  });

  it("EST-056 fires when family MSA with children omits parenting plan", async () => {
    const ctx = withPb(
      buildContext([
        "Marital Settlement Agreement",
        // The fixture is named "with children" and, until EST-056 v1.1.0 gated
        // on the condition its own description states, contained no reference
        // to a child at all — it passed on the misfire it was meant to catch.
        "Petitioner and respondent, date of separation 2026-01-01. The parties have two minor children. Division of property: real estate to respondent, accounts split. Spousal support: $5,000/month for 36 months. Tax: TCJA-compliant alimony. QDRO for 401(k) division. Incorporated into judgment without merger.",
      ]),
      MSA_PB,
    );
    const run = await runEngine({ rules: TRUST_ESTATE_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "EST-056")).toBe(true);
  });
});

describe("EST-034 — 'is effective immediately upon execution' (v1.1.0)", () => {
  const POA_PB_LOCAL: Playbook = { id: "durable-poa-financial", version: "1.0.0" };

  it("reads the adjective-first effectiveness clause", async () => {
    const ctx = withPb(
      buildContext([
        "Effectiveness",
        "This power of attorney is effective immediately upon my execution of it, and is not conditioned upon any determination of my incapacity.",
      ]),
      POA_PB_LOCAL,
    );
    const run = await runEngine({ rules: TRUST_ESTATE_RULES, ctx, source_file: SRC });
    expect(run.findings.map((f) => f.rule_id)).not.toContain("EST-034");
  });

  it("still fires when effectiveness is never addressed", async () => {
    const ctx = withPb(
      buildContext(["Appointment", "I appoint my brother as my attorney-in-fact."]),
      POA_PB_LOCAL,
    );
    const run = await runEngine({ rules: TRUST_ESTATE_RULES, ctx, source_file: SRC });
    expect(run.findings.map((f) => f.rule_id)).toContain("EST-034");
  });
});

describe("EST-038 — contemplation-of-marriage recital in real wording (v1.1.0)", () => {
  const PRENUP_PB_LOCAL: Playbook = { id: "prenuptial-agreement", version: "1.0.0" };
  const run1 = async (body: string) => {
    const ctx = withPb(buildContext(["Prenuptial Agreement", body]), PRENUP_PB_LOCAL);
    const run = await runEngine({ rules: TRUST_ESTATE_RULES, ctx, source_file: SRC });
    return new Set(run.findings.map((f) => f.rule_id));
  };

  it("reads 'in contemplation of their forthcoming marriage' and 'intend to marry'", async () => {
    expect(
      (
        await run1(
          "Alexandra and Jonathan, who intend to marry each other, enter into this Agreement in contemplation of their forthcoming marriage.",
        )
      ).has("EST-038"),
    ).toBe(false);
  });

  it("still fires when no marriage recital is present", async () => {
    expect(
      (await run1("The parties agree to divide their property as set forth in Schedule A.")).has(
        "EST-038",
      ),
    ).toBe(true);
  });
});

describe("EST-032 — durability reads the statutory 'not be affected by … incapacity' (v1.1.0)", () => {
  const POA: Playbook = { id: "durable-poa-financial", version: "1.0.0" };
  const has = async (b: string) =>
    new Set(
      (
        await runEngine({
          rules: TRUST_ESTATE_RULES,
          ctx: withPb(buildContext(["POA", b]), POA),
          source_file: SRC,
        })
      ).findings.map((f) => f.rule_id),
    );
  it("does not fire on 'shall not be affected by my incapacity' / 'not terminated by'", async () => {
    expect(
      (await has("This power of attorney shall not be affected by my subsequent incapacity.")).has(
        "EST-032",
      ),
    ).toBe(false);
    expect((await has("This power is not terminated by my disability.")).has("EST-032")).toBe(
      false,
    );
  });
  it("still fires when no durability language is present", async () => {
    expect((await has("The agent may act on my behalf in financial matters.")).has("EST-032")).toBe(
      true,
    );
  });
});

describe("EST-006 / EST-056 — documents that state there are no children", () => {
  const fires = async (id: string, pbId: string, b: string) =>
    (
      await runEngine({
        rules: TRUST_ESTATE_RULES,
        ctx: {
          ...buildContext(["Agreement", b]),
          playbook: { id: pbId, version: "1.0.0" },
        },
        source_file: SRC,
      })
    ).findings.some((f) => f.rule_id === id);

  // Both rules describe themselves as conditional on minor children but never
  // enforced the condition. Note the naive gate does not work: these documents
  // do contain the word "children" — they negate it.
  it("EST-006 stays silent on a will that states the testator has no children", async () => {
    expect(
      await fires(
        "EST-006",
        "last-will-and-testament",
        "I, the Testator, hereby revoke all prior wills. I have no children. I appoint Jane Roe as Executor, to serve without bond. I give my residuary estate to my spouse.",
      ),
    ).toBe(false);
  });

  it("EST-006 still fires when the will does have minor children", async () => {
    expect(
      await fires(
        "EST-006",
        "last-will-and-testament",
        "I, the Testator, revoke all prior wills. I have three children under the age of eighteen. I appoint Jane Roe as Executor. I give my residuary estate to my spouse.",
      ),
    ).toBe(true);
  });

  it("EST-056 stays silent on an MSA for a couple with no children", async () => {
    expect(
      await fires(
        "EST-056",
        "family-msa",
        "The parties, who have no children together and none are expected, agree to divide marital property as set forth herein, and each waives spousal support.",
      ),
    ).toBe(false);
  });

  it("EST-056 still fires when the marriage does have children", async () => {
    expect(
      await fires(
        "EST-056",
        "family-msa",
        "The parties have two minor children of the marriage and agree to divide marital property as set forth herein.",
      ),
    ).toBe(true);
  });
});
