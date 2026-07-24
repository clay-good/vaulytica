import { describe, expect, it } from "vitest";

import { INSURANCE_RULES } from "./rules.js";
import { INS_PLAYBOOK_IDS } from "./_helpers.js";
import { buildContext } from "../../../_test-fixtures.js";
import { runEngine } from "../../../runner.js";
import type { Playbook, RuleContext } from "../../../finding.js";

const POLICY_PB: Playbook = { id: "insurance-policy-summary", version: "1.0.0" };
const ENDORSEMENT_PB: Playbook = { id: "insurance-endorsement", version: "1.0.0" };
const IND_PB: Playbook = { id: "indemnification-agreement", version: "1.0.0" };
const HH_PB: Playbook = { id: "hold-harmless-agreement", version: "1.0.0" };

const SRC = { name: "test.docx", sha256: "0".repeat(64), size_bytes: 100 };

function withPb(ctx: RuleContext, pb: Playbook): RuleContext {
  return { ...ctx, playbook: pb };
}

describe("v4 Insurance ruleset — registry contract", () => {
  it("exports exactly 25 rules with stable INS-NNN ids", () => {
    expect(INSURANCE_RULES.length).toBe(25);
    const ids = INSURANCE_RULES.map((r) => r.id);
    expect(new Set(ids).size).toBe(25);
    for (const r of INSURANCE_RULES) {
      expect(r.id, r.id).toMatch(/^INS-\d{3}$/);
      expect(r.version, r.id).toMatch(/^\d+\.\d+\.\d+$/);
      expect(r.category, r.id).toBe("insurance");
      expect(r.applies_to_playbooks, r.id).toBeDefined();
    }
  });

  it("scopes every rule to one or more insurance playbooks", () => {
    const allowed = new Set<string>(INS_PLAYBOOK_IDS);
    for (const r of INSURANCE_RULES) {
      for (const pb of r.applies_to_playbooks ?? []) {
        expect(allowed.has(pb), `${r.id} → ${pb}`).toBe(true);
      }
    }
  });

  it("does not fire under a non-insurance playbook", async () => {
    const ctx = buildContext(["Some other doc", "No insurance content."]);
    const run = await runEngine({ rules: INSURANCE_RULES, ctx, source_file: SRC });
    expect(run.findings.length).toBe(0);
    expect(run.execution_log.every((e) => !e.fired)).toBe(true);
  });
});

const COMPLIANT_POLICY: [string, ...string[]][] = [
  [
    "Declarations Page",
    "Named Insured: Acme Corp. Producer / Broker: Best Insurance Agency, license 12345. Policy Period: inception 2026-01-01 to expiration 2027-01-01, 12:01 a.m. Limits of liability: each occurrence $1,000,000; general aggregate $2,000,000. Premium: $25,000. Deductible: $5,000 per occurrence; SIR $10,000. Forms Schedule: CG 00 01 04 13 Commercial General Liability (edition 04/13). Coverage Trigger: occurrence; retroactive date n/a; ERP n/a.",
  ],
];

describe("v4 Insurance — compliant policy fixture", () => {
  it("emits no critical findings against the compliant policy fixture", async () => {
    const ctx = withPb(buildContext(...COMPLIANT_POLICY), POLICY_PB);
    const run = await runEngine({ rules: INSURANCE_RULES, ctx, source_file: SRC });
    const criticals = run.findings.filter((f) => f.severity === "critical");
    expect(criticals.map((f) => f.rule_id)).toEqual([]);
  });

  it("is deterministic across runs", async () => {
    const ctx = withPb(buildContext(...COMPLIANT_POLICY), POLICY_PB);
    const a = await runEngine({ rules: INSURANCE_RULES, ctx, source_file: SRC });
    const b = await runEngine({ rules: INSURANCE_RULES, ctx, source_file: SRC });
    expect(a.result_hash).toEqual(b.result_hash);
  });
});

describe("v4 Insurance — failure cases", () => {
  it("INS-003 fires when declarations omit limits", async () => {
    const ctx = withPb(
      buildContext([
        "Declarations",
        "Named Insured: Acme. Policy period: 2026-01-01 to 2027-01-01. Premium $25,000. Deductible $5,000.",
      ]),
      POLICY_PB,
    );
    const run = await runEngine({ rules: INSURANCE_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "INS-003")).toBe(true);
  });

  it("INS-010 fires on absolute coverage-restricting endorsement", async () => {
    const ctx = withPb(
      buildContext([
        "Endorsement",
        "Form CG 21 67 12 04 (edition 12/04). This endorsement modifies coverage. Effective date: at policy inception. Absolute exclusion of communicable disease coverage applies.",
      ]),
      ENDORSEMENT_PB,
    );
    const run = await runEngine({ rules: INSURANCE_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "INS-010")).toBe(true);
  });

  it("INS-015 fires on Type I broad-form indemnity", async () => {
    const ctx = withPb(
      buildContext([
        "Indemnification Agreement",
        "Indemnitor: Acme. Indemnitee: BigCo and its officers and agents. Indemnitor shall indemnify and hold harmless Indemnitee from any and all claims, including claims caused by indemnitee's sole negligence. Insurance: CGL with additional insured CG 20 10 and waiver of subrogation CG 24 04.",
      ]),
      IND_PB,
    );
    const run = await runEngine({ rules: INSURANCE_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "INS-015")).toBe(true);
  });

  it("INS-022 fires on pre-dispute release of gross negligence", async () => {
    const ctx = withPb(
      buildContext([
        "Hold Harmless Agreement",
        "Acme shall be held harmless and released from any and all future claims, including those arising from gross negligence or willful misconduct, during the activity at the gym premises.",
      ]),
      HH_PB,
    );
    const run = await runEngine({ rules: INSURANCE_RULES, ctx, source_file: SRC });
    expect(run.findings.some((f) => f.rule_id === "INS-022")).toBe(true);
  });
});

describe("INS-015 — the canonical 'in whole or in part' broad-form indemnity (v1.1.0)", () => {
  const run1 = async (body: string) => {
    const ctx = withPb(buildContext(["Indemnity", body]), IND_PB);
    const run = await runEngine({ rules: INSURANCE_RULES, ctx, source_file: SRC });
    return new Set(run.findings.map((f) => f.rule_id));
  };

  it("fires on 'caused in whole or in part by the negligence of the Owner' (Type I)", async () => {
    expect(
      (
        await run1(
          "Contractor shall indemnify Owner from all liability caused in whole or in part by the negligence of the Owner.",
        )
      ).has("INS-015"),
    ).toBe(true);
  });

  it("stays silent on a Type III limited indemnity", async () => {
    expect(
      (
        await run1(
          "Subcontractor shall indemnify Owner only to the extent of Subcontractor's own negligence.",
        )
      ).has("INS-015"),
    ).toBe(false);
  });
});
