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
        "Petitioner and respondent, date of separation 2026-01-01. Division of property: real estate to respondent, accounts split. Spousal support: $5,000/month for 36 months. Tax: TCJA-compliant alimony. QDRO for 401(k) division. Incorporated into judgment without merger.",
      ]),
      MSA_PB,
    );
    const run = await runEngine({ rules: TRUST_ESTATE_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "EST-056")).toBe(true);
  });
});
